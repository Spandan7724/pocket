//! Unified line diffs for review screens (`config pull`).

/// Lines of `a` and `b` as a unified diff with `ctx` lines of context.
pub fn unified(a: &str, b: &str, ctx: usize) -> String {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    if a.len() * b.len() > 25_000_000 {
        return format!(
            "  (file too large to diff: {} → {} lines)\n",
            a.len(),
            b.len()
        );
    }
    // LCS table, then walk it into edit ops.
    let (n, m) = (a.len(), b.len());
    let mut t = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[i][j] = if a[i] == b[j] {
                t[i + 1][j + 1] + 1
            } else {
                t[i + 1][j].max(t[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(char, &str)> = vec![];
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if j < m && (i == n || t[i][j + 1] >= t[i + 1][j]) {
            ops.push(('+', b[j]));
            j += 1;
        } else {
            ops.push(('-', a[i]));
            i += 1;
        }
    }
    let keep: Vec<bool> = (0..ops.len())
        .map(|k| {
            let lo = k.saturating_sub(ctx);
            let hi = (k + ctx + 1).min(ops.len());
            ops[lo..hi].iter().any(|(c, _)| *c != ' ')
        })
        .collect();
    let mut out = String::new();
    let mut gap = false;
    for (k, (c, l)) in ops.iter().enumerate() {
        if keep[k] {
            if gap {
                out.push_str("  …\n");
                gap = false;
            }
            out.push_str(&format!("{c} {l}\n"));
        } else {
            gap = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn small_diff() {
        let d = super::unified("a\nb\nc\n", "a\nB\nc\nd\n", 1);
        assert_eq!(d, "  a\n- b\n+ B\n  c\n+ d\n");
        assert_eq!(super::unified("x\n", "x\n", 3), "");
    }
}
