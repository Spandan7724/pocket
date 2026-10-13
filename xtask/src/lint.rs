//! Dependency-direction and VMM-isolation lint (ARCHITECTURE.md §2, CONTRACTS.md §6).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::bail;
use crate::util::{Result, output, root, step};

/// Workspace crates each crate may depend on. Anything not listed is a violation.
const ALLOWED: &[(&str, &[&str])] = &[
    ("pocket-cli", &["pocket-tui", "pocket-proto"]),
    ("pocket-tui", &["pocket-proto"]),
    (
        "pocketd",
        &[
            "pocket-vmm",
            "pocket-image",
            "pocket-net",
            "pocket-git",
            "pocket-store",
            "pocket-proto",
        ],
    ),
    ("pocket-proto", &[]),
    ("pocket-vmm", &["pocket-proto"]),
    ("pocket-image", &["pocket-proto"]),
    ("pocket-net", &["pocket-proto"]),
    ("pocket-git", &["pocket-proto"]),
    ("pocket-store", &["pocket-proto"]),
    ("pocket-init", &["pocket-proto"]),
    ("pocket-guest", &["pocket-proto"]),
    (
        "pocket-tests",
        &["pocket-proto", "pocket-vmm", "pocket-image"],
    ),
    ("xtask", &[]),
];

/// External crates allowed anywhere in the guest binaries' dependency closure.
const GUEST_EXTERNAL: &[&str] = &[
    "cobs",
    "libc",
    "postcard",
    "proc-macro2",
    "quote",
    "serde",
    "serde_core",
    "serde_derive",
    "syn",
    "thiserror",
    "thiserror-impl",
    "unicode-ident",
];
const GUEST_CRATES: &[&str] = &["pocket-init", "pocket-guest", "pocket-proto"];

/// Strings that only VMM-specific code would contain.
const VMM_MARKERS: &[&str] = &[
    "cloud-hypervisor",
    "cloud_hypervisor",
    "firecracker",
    "ch-remote",
];

pub struct Graph {
    pub members: BTreeSet<String>,
    /// name -> direct normal/build dependency names
    pub deps: BTreeMap<String, BTreeSet<String>>,
    /// (package, dependency path) for every path dependency
    pub path_deps: Vec<(String, String)>,
}

fn load() -> Result<Graph> {
    let json = output(Command::new(env!("CARGO")).current_dir(root()).args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
    ]))?;
    let v: Value = serde_json::from_str(&json)?;
    let id_name: BTreeMap<&str, &str> = v["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["id"].as_str().unwrap(), p["name"].as_str().unwrap()))
        .collect();
    let members = v["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id_name[id.as_str().unwrap()].to_string())
        .collect();
    let mut deps = BTreeMap::new();
    for node in v["resolve"]["nodes"].as_array().unwrap() {
        let name = id_name[node["id"].as_str().unwrap()].to_string();
        let set: BTreeSet<String> = node["deps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| {
                d["dep_kinds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|k| k["kind"].as_str() != Some("dev"))
            })
            .map(|d| id_name[d["pkg"].as_str().unwrap()].to_string())
            .collect();
        deps.entry(name).or_insert_with(BTreeSet::new).extend(set);
    }
    let mut path_deps = Vec::new();
    for p in v["packages"].as_array().unwrap() {
        for d in p["dependencies"].as_array().unwrap() {
            if let Some(path) = d["path"].as_str() {
                path_deps.push((p["name"].as_str().unwrap().to_string(), path.to_string()));
            }
        }
    }
    Ok(Graph {
        members,
        deps,
        path_deps,
    })
}

pub fn check_graph(g: &Graph, root: &Path) -> Vec<String> {
    let allowed: BTreeMap<&str, &[&str]> = ALLOWED.iter().copied().collect();
    let mut errs = Vec::new();
    for m in &g.members {
        let Some(ok) = allowed.get(m.as_str()) else {
            errs.push(format!(
                "{m}: not in the lint's allowlist; add it to xtask/src/lint.rs"
            ));
            continue;
        };
        for d in g.deps.get(m).into_iter().flatten() {
            if g.members.contains(d) && !ok.contains(&d.as_str()) {
                errs.push(format!("{m} -> {d}: dependency direction not allowed"));
            }
        }
    }
    for c in GUEST_CRATES {
        let mut seen = BTreeSet::new();
        let mut stack = vec![c.to_string()];
        while let Some(n) = stack.pop() {
            for d in g.deps.get(&n).into_iter().flatten() {
                if seen.insert(d.clone()) {
                    stack.push(d.clone());
                }
            }
        }
        for d in seen {
            if !g.members.contains(&d) && !GUEST_EXTERNAL.contains(&d.as_str()) {
                errs.push(format!(
                    "{c} pulls in `{d}`: guest crates stay small (GUEST_EXTERNAL)"
                ));
            }
        }
    }
    let crates = root.join("crates");
    for (pkg, path) in &g.path_deps {
        let p = Path::new(path);
        if !p.starts_with(&crates) {
            errs.push(format!("{pkg}: path dependency outside crates/: {path}"));
        }
    }
    errs
}

fn check_vmm_markers(dir: &Path, errs: &mut Vec<String>) -> Result {
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "pocket-vmm") {
                continue;
            }
            check_vmm_markers(&p, errs)?;
        } else if p.extension().is_some_and(|x| x == "rs" || x == "toml") {
            let text = fs::read_to_string(&p)?.to_lowercase();
            for m in VMM_MARKERS {
                if text.contains(m) {
                    errs.push(format!(
                        "{}: mentions `{m}`; VMM code lives in pocket-vmm",
                        p.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn lint_deps() -> Result {
    step("lint-deps");
    let g = load()?;
    let mut errs = check_graph(&g, &root());
    check_vmm_markers(&root().join("crates"), &mut errs)?;
    if !errs.is_empty() {
        bail!("dependency lint failed:\n  {}", errs.join("\n  "));
    }
    eprintln!(
        "ok: {} workspace crates, dependency directions and guest dependency closure checked",
        g.members.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &str)]) -> Graph {
        let members = ALLOWED.iter().map(|(n, _)| n.to_string()).collect();
        let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (a, b) in edges {
            deps.entry(a.to_string()).or_default().insert(b.to_string());
        }
        Graph {
            members,
            deps,
            path_deps: vec![],
        }
    }

    #[test]
    fn allowed_edges_pass() {
        let g = graph(&[("pocket-cli", "pocket-tui"), ("pocketd", "pocket-vmm")]);
        assert!(check_graph(&g, Path::new("/r")).is_empty());
    }

    #[test]
    fn cli_linking_daemon_subsystem_fails() {
        let g = graph(&[("pocket-cli", "pocket-vmm")]);
        let errs = check_graph(&g, Path::new("/r"));
        assert_eq!(
            errs,
            ["pocket-cli -> pocket-vmm: dependency direction not allowed"]
        );
    }

    #[test]
    fn heavy_guest_dependency_fails() {
        let g = graph(&[("pocket-init", "pocket-proto"), ("pocket-proto", "tokio")]);
        let errs = check_graph(&g, Path::new("/r"));
        assert!(
            errs.iter()
                .any(|e| e.contains("pocket-init pulls in `tokio`")),
            "{errs:?}"
        );
    }

    #[test]
    fn spike_path_dependency_fails() {
        let mut g = graph(&[]);
        g.path_deps
            .push(("pocketd".into(), "/r/spike/thing".into()));
        let errs = check_graph(&g, Path::new("/r"));
        assert_eq!(
            errs,
            ["pocketd: path dependency outside crates/: /r/spike/thing"]
        );
    }
}
