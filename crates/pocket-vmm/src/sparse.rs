//! Snapshot memory files hold all guest RAM; most of it is zero. Punching those pages
//! out keeps templates and hibernation images at the size of the memory actually used.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::Path;

const PAGE: usize = 4096;
const CHUNK: usize = 1 << 20;
static ZERO: [u8; PAGE] = [0; PAGE];

/// Replaces every all-zero 4 KiB page of `path` with a hole. Returns the bytes punched.
pub fn punch_zero_pages(path: &Path) -> io::Result<u64> {
    let mut f = File::options().read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    let mut buf = vec![0u8; CHUNK];
    let mut off = 0u64;
    let mut punched = 0u64;
    let mut run: Option<u64> = None;
    let punch = |f: &File, start: u64, end: u64| -> io::Result<()> {
        // SAFETY: plain syscall on an open descriptor.
        let r = unsafe {
            libc::fallocate(
                f.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                start as libc::off_t,
                (end - start) as libc::off_t,
            )
        };
        if r != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    f.seek(SeekFrom::Start(0))?;
    while off < len {
        let want = CHUNK.min((len - off) as usize);
        f.read_exact(&mut buf[..want])?;
        for (i, page) in buf[..want].chunks(PAGE).enumerate() {
            let at = off + (i * PAGE) as u64;
            // Slice equality is a memcmp, fast in debug builds too.
            let zero = page == &ZERO[..page.len()];
            match (zero, run) {
                (true, None) => run = Some(at),
                (false, Some(start)) => {
                    punch(&f, start, at)?;
                    punched += at - start;
                    run = None;
                }
                _ => {}
            }
        }
        off += want as u64;
    }
    if let Some(start) = run {
        punch(&f, start, len)?;
        punched += len - start;
    }
    Ok(punched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zero_pages_become_holes() {
        let p = std::env::temp_dir().join(format!("pocket-sparse-{}", std::process::id()));
        let mut f = File::create(&p).unwrap();
        let mut data = vec![0u8; 64 * PAGE];
        data[3 * PAGE] = 1;
        data[40 * PAGE + 7] = 9;
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        let punched = punch_zero_pages(&p).unwrap();
        assert_eq!(punched, 62 * PAGE as u64);
        assert_eq!(std::fs::read(&p).unwrap(), data);
        std::fs::remove_file(&p).unwrap();
    }
}
