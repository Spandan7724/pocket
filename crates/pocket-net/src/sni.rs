//! Server name from a TLS ClientHello (RFC 8446 §4.1.2, RFC 6066 §3). Input is hostile:
//! every length is bounds-checked; anything unexpected yields `None`.

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (h, t) = b.split_at(n);
    *b = t;
    Some(h)
}

fn u8_(b: &mut &[u8]) -> Option<usize> {
    take(b, 1).map(|x| x[0] as usize)
}

fn u16_(b: &mut &[u8]) -> Option<usize> {
    take(b, 2).map(|x| u16::from_be_bytes([x[0], x[1]]) as usize)
}

/// `Some(name)` if `data` starts with a ClientHello record carrying an SNI host name.
pub fn client_hello_sni(data: &[u8]) -> Option<String> {
    let mut b = data;
    if u8_(&mut b)? != 0x16 {
        return None;
    }
    take(&mut b, 2)?;
    let rec_len = u16_(&mut b)?;
    let n = rec_len.min(b.len());
    let mut rec = take(&mut b, n)?;
    if u8_(&mut rec)? != 0x01 {
        return None;
    }
    let hs_len = (u8_(&mut rec)? << 16) | u16_(&mut rec)?;
    let n = hs_len.min(rec.len());
    let mut hs = take(&mut rec, n)?;
    take(&mut hs, 2 + 32)?;
    let sid = u8_(&mut hs)?;
    take(&mut hs, sid)?;
    let cs = u16_(&mut hs)?;
    take(&mut hs, cs)?;
    let comp = u8_(&mut hs)?;
    take(&mut hs, comp)?;
    let ext_len = u16_(&mut hs)?;
    let mut exts = take(&mut hs, ext_len)?;
    while !exts.is_empty() {
        let ty = u16_(&mut exts)?;
        let len = u16_(&mut exts)?;
        let mut e = take(&mut exts, len)?;
        if ty != 0 {
            continue;
        }
        let list_len = u16_(&mut e)?;
        let mut list = take(&mut e, list_len)?;
        while !list.is_empty() {
            let kind = u8_(&mut list)?;
            let n = u16_(&mut list)?;
            let name = take(&mut list, n)?;
            if kind == 0 {
                let s = std::str::from_utf8(name).ok()?;
                return (!s.is_empty()
                    && s.len() <= 253
                    && s.bytes().all(|c| c.is_ascii_graphic()))
                .then(|| s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn client_hello(name: &str) -> Vec<u8> {
    let mut sni = vec![0u8];
    sni.extend((name.len() as u16).to_be_bytes());
    sni.extend(name.as_bytes());
    let mut list = (sni.len() as u16).to_be_bytes().to_vec();
    list.extend(sni);
    let mut ext = 0u16.to_be_bytes().to_vec();
    ext.extend((list.len() as u16).to_be_bytes());
    ext.extend(list);
    let mut body = vec![3, 3];
    body.extend([7u8; 32]);
    body.push(0);
    body.extend(2u16.to_be_bytes());
    body.extend([0x13, 0x01]);
    body.extend([1, 0]);
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut hs = vec![1, 0];
    hs.extend((body.len() as u16).to_be_bytes());
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sni_and_survives_garbage() {
        assert_eq!(
            client_hello_sni(&client_hello("example.com")).as_deref(),
            Some("example.com")
        );
        let h = client_hello("example.com");
        for cut in 0..h.len() {
            let _ = client_hello_sni(&h[..cut]);
        }
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), None);
        let mut x: u32 = 1;
        for _ in 0..20000 {
            let buf: Vec<u8> = (0..64)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let mut b = vec![0x16, 3, 1, 0, 60, 1];
            b.extend(buf);
            let _ = client_hello_sni(&b);
        }
    }
}
