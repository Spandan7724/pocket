//! OCI distribution client (pull only) and the digest-addressed erofs image cache.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::layers;

const MAX_MANIFEST: u64 = 4 << 20;
const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("invalid image reference {0:?}: {1}")]
    Reference(String, &'static str),
    #[error("registry request {url} failed: {msg}")]
    Http { url: String, msg: String },
    #[error("{what}: digest mismatch (expected {expected}, got {actual})")]
    Digest {
        what: String,
        expected: String,
        actual: String,
    },
    #[error("image {0} has no manifest for linux/{1}")]
    NoPlatform(String, String),
    #[error("unsupported layer media type {0}")]
    MediaType(String),
    #[error("mkfs.erofs failed: {0}")]
    Mkfs(String),
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: io::Error,
    },
    #[error("malformed manifest: {0}")]
    Manifest(String),
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> ImageError {
    let what = what.into();
    move |source| ImageError::Io { what, source }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// API host, e.g. `registry-1.docker.io`.
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference, ImageError> {
        let bad = |why| ImageError::Reference(s.into(), why);
        if s.is_empty() || s.len() > 512 || s.contains(char::is_whitespace) {
            return Err(bad("empty, too long or contains whitespace"));
        }
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                let hex = d
                    .strip_prefix("sha256:")
                    .ok_or_else(|| bad("only sha256 digests"))?;
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("digest must be sha256:<64 hex>"));
                }
                (r, Some(d.to_ascii_lowercase()))
            }
            None => (s, None),
        };
        let (domain, path) = match rest.split_once('/') {
            Some((d, p)) if d.contains(['.', ':']) || d == "localhost" => (d.to_string(), p),
            _ => ("docker.io".to_string(), rest),
        };
        let host = domain.split(':').next().unwrap_or_default();
        let host_ok = host.split('.').all(|l| {
            l.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        let port_ok = domain
            .split_once(':')
            .is_none_or(|(_, p)| p.parse::<u16>().is_ok());
        if !host_ok || !port_ok {
            return Err(bad("invalid registry host"));
        }
        let (path, tag) = match path.rsplit_once(':') {
            Some((p, t)) if !t.contains('/') => (p, Some(t.to_string())),
            _ => (path, None),
        };
        let valid = |c: &str| {
            c.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                && c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        };
        if !path.split('/').all(valid) {
            return Err(bad("repository must be lowercase [a-z0-9._-] components"));
        }
        let repository = if domain == "docker.io" && !path.contains('/') {
            format!("library/{path}")
        } else {
            path.to_string()
        };
        let registry = if domain == "docker.io" {
            "registry-1.docker.io".into()
        } else {
            domain
        };
        let tag = match (tag, &digest) {
            (None, None) => Some("latest".into()),
            (t, _) => t,
        };
        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    fn reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

pub fn oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

struct Registry {
    agent: ureq::Agent,
    token: Option<String>,
}

fn http(url: &str, e: impl std::fmt::Display) -> ImageError {
    ImageError::Http {
        url: url.into(),
        msg: e.to_string(),
    }
}

impl Registry {
    fn new() -> Registry {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .user_agent(concat!("pocket/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Registry { agent, token: None }
    }

    /// Anonymous bearer token per the `WWW-Authenticate` challenge (Docker Hub, GHCR).
    fn authenticate(&mut self, challenge: &str) -> Result<(), ImageError> {
        let params = challenge
            .strip_prefix("Bearer ")
            .ok_or_else(|| http("auth", format!("unsupported challenge {challenge:?}")))?;
        let mut realm = None;
        let mut query = vec![];
        for kv in params.split(',') {
            if let Some((k, v)) = kv.trim().split_once('=') {
                let v = v.trim_matches('"');
                if k == "realm" {
                    realm = Some(v.to_string());
                } else if k == "service" || k == "scope" {
                    query.push((k.to_string(), v.to_string()));
                }
            }
        }
        let realm = realm.ok_or_else(|| http("auth", "challenge without realm"))?;
        if !realm.starts_with("https://") {
            return Err(http(&realm, "token realm must be https"));
        }
        let mut req = self.agent.get(&realm);
        for (k, v) in &query {
            req = req.query(k, v);
        }
        let mut resp = req.call().map_err(|e| http(&realm, e))?;
        if resp.status() != 200 {
            return Err(http(&realm, format!("HTTP {}", resp.status())));
        }
        #[derive(Deserialize)]
        struct Tok {
            token: Option<String>,
            access_token: Option<String>,
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_MANIFEST)
            .read_to_string()
            .map_err(|e| http(&realm, e))?;
        let t: Tok = serde_json::from_str(&body).map_err(|e| http(&realm, e))?;
        self.token = t.token.or(t.access_token);
        Ok(())
    }

    fn get(
        &mut self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<ureq::http::Response<ureq::Body>, ImageError> {
        for attempt in 0..2 {
            let mut req = self.agent.get(url);
            if let Some(a) = accept {
                req = req.header("Accept", a);
            }
            if let Some(t) = &self.token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            let resp = req.call().map_err(|e| http(url, e))?;
            match resp.status().as_u16() {
                200 => return Ok(resp),
                401 if attempt == 0 => {
                    let ch = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    self.authenticate(&ch)?;
                }
                s => return Err(http(url, format!("HTTP {s}"))),
            }
        }
        Err(http(url, "unauthorized"))
    }

    fn manifest(
        &mut self,
        r: &Reference,
        reference: &str,
    ) -> Result<(Vec<u8>, String), ImageError> {
        let url = format!(
            "https://{}/v2/{}/manifests/{reference}",
            r.registry, r.repository
        );
        let mut resp = self.get(&url, Some(MANIFEST_TYPES))?;
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_MANIFEST)
            .read_to_vec()
            .map_err(|e| http(&url, e))?;
        let digest = format!("sha256:{}", hex(&Sha256::digest(&body)));
        if reference.starts_with("sha256:") && reference != digest {
            return Err(ImageError::Digest {
                what: url,
                expected: reference.into(),
                actual: digest,
            });
        }
        Ok((body, digest))
    }

    fn blob(&mut self, r: &Reference, d: &Descriptor, dest: &Path) -> Result<(), ImageError> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            r.registry, r.repository, d.digest
        );
        let mut resp = self.get(&url, None)?;
        let tmp = dest.with_extension("partial");
        let mut f = BufWriter::new(File::create(&tmp).map_err(io_err(tmp.display().to_string()))?);
        let mut hasher = Sha256::new();
        let mut reader = resp.body_mut().with_config().limit(u64::MAX).reader();
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(io_err(url.clone()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            f.write_all(&buf[..n])
                .map_err(io_err(tmp.display().to_string()))?;
            total += n as u64;
        }
        f.flush().map_err(io_err(tmp.display().to_string()))?;
        let actual = format!("sha256:{}", hex(&hasher.finalize()));
        if actual != d.digest || (d.size != 0 && total != d.size) {
            let _ = fs::remove_file(&tmp);
            return Err(ImageError::Digest {
                what: url,
                expected: d.digest.clone(),
                actual,
            });
        }
        fs::rename(&tmp, dest).map_err(io_err(dest.display().to_string()))
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn digest_hex(d: &str) -> Result<&str, ImageError> {
    d.strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| ImageError::Manifest(format!("bad digest {d:?}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledImage {
    /// Platform manifest digest; the cache key.
    pub digest: String,
    pub path: PathBuf,
    pub cache_hit: bool,
}

/// `images/<hex>.erofs` keyed by manifest digest; blobs under `blobs/sha256/`.
pub struct ImageStore {
    pub images_dir: PathBuf,
    pub blobs_dir: PathBuf,
    pub mkfs_erofs: PathBuf,
}

impl ImageStore {
    pub fn image_path(&self, digest: &str) -> Result<PathBuf, ImageError> {
        Ok(self
            .images_dir
            .join(format!("{}.erofs", digest_hex(digest)?)))
    }

    /// Pulls `reference` for linux/<host arch> and returns its erofs image. A digest
    /// already in the cache needs no network; a tag costs one manifest request.
    pub fn pull(
        &self,
        reference: &str,
        progress: &dyn Fn(&str),
    ) -> Result<PulledImage, ImageError> {
        let r = Reference::parse(reference)?;
        for d in [&self.images_dir, &self.blobs_dir] {
            fs::create_dir_all(d).map_err(io_err(d.display().to_string()))?;
        }
        if let Some(d) = &r.digest {
            let link = self.images_dir.join(format!("{}.link", digest_hex(d)?));
            let platform = fs::read_to_string(&link).unwrap_or_else(|_| d.clone());
            let p = self.image_path(platform.trim())?;
            if p.exists() {
                return Ok(PulledImage {
                    digest: platform.trim().into(),
                    path: p,
                    cache_hit: true,
                });
            }
        }
        let mut reg = Registry::new();
        progress(&format!("resolving {reference}"));
        let (body, top_digest) = reg.manifest(&r, r.reference())?;
        let mut m: Manifest =
            serde_json::from_slice(&body).map_err(|e| ImageError::Manifest(e.to_string()))?;
        let mut digest = top_digest.clone();
        if !m.manifests.is_empty() {
            let arch = oci_arch();
            let pick = m
                .manifests
                .iter()
                .find(|d| {
                    d.platform.as_ref().is_some_and(|p| {
                        p.os == "linux"
                            && p.architecture == arch
                            && (arch != "arm64" || p.variant.as_deref().is_none_or(|v| v == "v8"))
                    })
                })
                .ok_or_else(|| ImageError::NoPlatform(reference.into(), arch.into()))?;
            let (body, d) = reg.manifest(&r, &pick.digest.clone())?;
            m = serde_json::from_slice(&body).map_err(|e| ImageError::Manifest(e.to_string()))?;
            digest = d;
            let link = self
                .images_dir
                .join(format!("{}.link", digest_hex(&top_digest)?));
            let _ = fs::write(link, &digest);
        }
        let _ = &m.media_type;
        let out = self.image_path(&digest)?;
        if out.exists() {
            return Ok(PulledImage {
                digest,
                path: out,
                cache_hit: true,
            });
        }
        let work = self
            .images_dir
            .join(format!("{}.build", &digest_hex(&digest)?[..16]));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).map_err(io_err(work.display().to_string()))?;
        let result = (|| {
            let mut tars = vec![];
            for (i, l) in m.layers.iter().enumerate() {
                let gz = match l.media_type.as_str() {
                    t if t.ends_with("tar+gzip") || t.ends_with("tar.gzip") => true,
                    t if t.ends_with(".tar") || t.ends_with("tar") => false,
                    t => return Err(ImageError::MediaType(t.into())),
                };
                let blob = self.blobs_dir.join(digest_hex(&l.digest)?);
                if !blob.exists() {
                    progress(&format!(
                        "layer {}/{}: {} ({:.1} MiB)",
                        i + 1,
                        m.layers.len(),
                        &l.digest[..19],
                        l.size as f64 / 1048576.0
                    ));
                    reg.blob(&r, l, &blob)?;
                }
                let tar = work.join(format!("layer{i}.tar"));
                let src = File::open(&blob).map_err(io_err(blob.display().to_string()))?;
                let mut dst =
                    BufWriter::new(File::create(&tar).map_err(io_err(tar.display().to_string()))?);
                let mut input: Box<dyn Read> = if gz {
                    Box::new(flate2::read::GzDecoder::new(BufReader::new(src)))
                } else {
                    Box::new(BufReader::new(src))
                };
                io::copy(&mut input, &mut dst).map_err(io_err(format!("unpack {}", l.digest)))?;
                dst.flush().map_err(io_err(tar.display().to_string()))?;
                tars.push(tar);
            }
            progress("merging layers");
            let merged = work.join("merged.tar");
            layers::merge(&tars, &merged).map_err(io_err("merge layers"))?;
            for t in &tars {
                let _ = fs::remove_file(t);
            }
            progress("building erofs");
            build_erofs_from_tar(&self.mkfs_erofs, &merged, &out)
        })();
        let _ = fs::remove_dir_all(&work);
        result?;
        Ok(PulledImage {
            digest,
            path: out,
            cache_hit: false,
        })
    }
}

/// Uncompressed (DAX-capable) erofs from a tarball, padded to 2 MiB for virtio-pmem.
pub fn build_erofs_from_tar(mkfs: &Path, tar: &Path, out: &Path) -> Result<(), ImageError> {
    let tmp = out.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let o = Command::new(mkfs)
        .stdout(Stdio::null())
        .arg("--tar=f")
        .arg("-Uc1b9d5a2-0000-4000-8000-706f636b6574")
        .arg(&tmp)
        .arg(tar)
        .stdin(Stdio::null())
        .output()
        .map_err(io_err(format!("run {}", mkfs.display())))?;
    if !o.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(ImageError::Mkfs(
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ));
    }
    pad_2m(&tmp)?;
    fs::rename(&tmp, out).map_err(io_err(out.display().to_string()))
}

pub fn pad_2m(p: &Path) -> Result<(), ImageError> {
    let f = File::options()
        .write(true)
        .open(p)
        .map_err(io_err(p.display().to_string()))?;
    let len = f.metadata().map_err(io_err(p.display().to_string()))?.len();
    f.set_len(len.div_ceil(2 << 20) * (2 << 20))
        .map_err(io_err(p.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let r = Reference::parse("ubuntu:24.04").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()),
            ("registry-1.docker.io", "library/ubuntu", Some("24.04"))
        );
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(r.tag.as_deref(), Some("latest"));
        let d = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("ghcr.io/org/img@{d}")).unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str(), r.tag, r.digest),
            ("ghcr.io", "org/img", None, Some(d))
        );
        let r = Reference::parse("localhost:5000/x/y:t").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str()),
            ("localhost:5000", "x/y")
        );
        for bad in ["", "UPPER", "a b", "x@sha256:12", "x@md5:aa", "../x"] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }
}
