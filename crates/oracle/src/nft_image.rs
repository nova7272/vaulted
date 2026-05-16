//! Deterministic NFT contour image generator
//!
//! Generates unique contour-based SVG images from NFT Token IDs.
//! Uses marching squares on a distance field with noise warp.
//! Same token_id = same image everywhere (Oracle + client).
//!
//! Algorithm matches TypeScript version in ui/src/utils/nft_image.ts:
//! - FNV-1a hash → LCG PRNG (identical sequences)
//! - Value noise with quintic interpolation
//! - Scalar field = sqrt(distance) from warped focal point
//! - Marching squares → chain segments → Catmull-Rom Bézier

use std::fmt::Write;

// ── Constants (must match TypeScript exactly) ──

const NEON_COLORS: &[&str] = &[
    "#ff3b7a", "#00e5a0", "#ffc53d", "#3b82f6", "#a855f7", "#06b6d4", "#f97316", "#ec4899",
    "#22d3ee", "#84cc16",
];
const BG: &str = "#060608";
const LINES: usize = 25;
const STROKE: f64 = 1.8;
const WARP: f64 = 35.0;
const IMG_W: usize = 256;
const IMG_H: usize = 384;
const PAD: usize = 80;
const FW: usize = IMG_W + PAD * 2;
const FH: usize = IMG_H + PAD * 2;
const RES: usize = 3;

// ── PRNG (must match TypeScript FNV-1a + LCG exactly) ──

fn fnv_hash(s: &str) -> u32 {
    let mut h: u32 = 2166136261;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

struct Lcg(u32);

impl Lcg {
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
        self.0 as f64 / 4294967295.0
    }
}

// ── Value noise (must match TypeScript makeNoise) ──

struct Noise {
    grid: Vec<f64>,
}

impl Noise {
    const N: usize = 32;

    fn new(rng: &mut Lcg) -> Self {
        let mut grid = Vec::with_capacity(Self::N * Self::N);
        for _ in 0..Self::N * Self::N {
            grid.push(rng.next() * 2.0 - 1.0);
        }
        Self { grid }
    }

    fn get(&self, ix: i32, iy: i32) -> f64 {
        let n = Self::N as i32;
        let x = ((ix % n) + n) % n;
        let y = ((iy % n) + n) % n;
        self.grid[x as usize + y as usize * Self::N]
    }

    fn quintic(t: f64) -> f64 {
        t * t * t * (t * (t * 6.0 - 15.0) + 10.0)
    }

    fn sample(&self, x: f64, y: f64) -> f64 {
        let ix = x.floor() as i32;
        let iy = y.floor() as i32;
        let fx = Self::quintic(x - x.floor());
        let fy = Self::quintic(y - y.floor());
        let a = self.get(ix, iy) * (1.0 - fx) + self.get(ix + 1, iy) * fx;
        let b = self.get(ix, iy + 1) * (1.0 - fx) + self.get(ix + 1, iy + 1) * fx;
        a * (1.0 - fy) + b * fy
    }
}

// ── Marching squares ──

type Pt = [f64; 2];

fn march_squares(field: &[f64], cols: usize, rows: usize, thr: f64) -> Vec<[Pt; 2]> {
    let mut segs = Vec::new();

    for iy in 0..rows - 1 {
        for ix in 0..cols - 1 {
            let v0 = field[iy * cols + ix];
            let v1 = field[iy * cols + ix + 1];
            let v2 = field[(iy + 1) * cols + ix + 1];
            let v3 = field[(iy + 1) * cols + ix];

            let mut cfg = 0u8;
            if v0 > thr {
                cfg |= 1;
            }
            if v1 > thr {
                cfg |= 2;
            }
            if v2 > thr {
                cfg |= 4;
            }
            if v3 > thr {
                cfg |= 8;
            }

            if cfg == 0 || cfg == 15 {
                continue;
            }

            let lerp = |va: f64, vb: f64, pa: Pt, pb: Pt| -> Pt {
                if (va - vb).abs() < 1e-6 {
                    return [(pa[0] + pb[0]) / 2.0, (pa[1] + pb[1]) / 2.0];
                }
                let t = (thr - va) / (vb - va);
                [pa[0] + (pb[0] - pa[0]) * t, pa[1] + (pb[1] - pa[1]) * t]
            };

            let p: Pt = [ix as f64, iy as f64];
            let q: Pt = [ix as f64 + 1.0, iy as f64];
            let r: Pt = [ix as f64 + 1.0, iy as f64 + 1.0];
            let s: Pt = [ix as f64, iy as f64 + 1.0];

            let a = lerp(v0, v1, p, q);
            let b = lerp(v1, v2, q, r);
            let c = lerp(v3, v2, s, r);
            let d = lerp(v0, v3, p, s);

            match cfg {
                1 | 14 => segs.push([d, a]),
                2 | 13 => segs.push([a, b]),
                3 | 12 => segs.push([d, b]),
                4 | 11 => segs.push([b, c]),
                5 => {
                    segs.push([d, a]);
                    segs.push([b, c]);
                },
                6 | 9 => segs.push([a, c]),
                7 | 8 => segs.push([d, c]),
                10 => {
                    segs.push([d, c]);
                    segs.push([a, b]);
                },
                _ => {},
            }
        }
    }
    segs
}

// ── Chain segments into polylines ──

fn chain_segments(segs: &[[Pt; 2]]) -> Vec<Vec<Pt>> {
    let eps = 0.01;
    let res_f = RES as f64;

    let pts: Vec<[Pt; 2]> = segs
        .iter()
        .map(|s| {
            [
                [s[0][0] * res_f, s[0][1] * res_f],
                [s[1][0] * res_f, s[1][1] * res_f],
            ]
        })
        .collect();

    let mut used = vec![false; pts.len()];
    let mut chains: Vec<Vec<Pt>> = Vec::new();

    let near = |a: &Pt, b: &Pt| -> bool { (a[0] - b[0]).abs() < eps && (a[1] - b[1]).abs() < eps };

    for i in 0..pts.len() {
        if used[i] {
            continue;
        }
        used[i] = true;
        let mut ch = vec![pts[i][0], pts[i][1]];

        let mut changed = true;
        while changed {
            changed = false;
            for j in 0..pts.len() {
                if used[j] {
                    continue;
                }
                let head = ch[0];
                let tail = *ch.last().unwrap();

                if near(&tail, &pts[j][0]) {
                    ch.push(pts[j][1]);
                    used[j] = true;
                    changed = true;
                } else if near(&tail, &pts[j][1]) {
                    ch.push(pts[j][0]);
                    used[j] = true;
                    changed = true;
                } else if near(&head, &pts[j][1]) {
                    ch.insert(0, pts[j][0]);
                    used[j] = true;
                    changed = true;
                } else if near(&head, &pts[j][0]) {
                    ch.insert(0, pts[j][1]);
                    used[j] = true;
                    changed = true;
                }
            }
        }

        if ch.len() > 4 {
            chains.push(ch);
        }
    }
    chains
}

// ── Downsample + Catmull-Rom → cubic Bézier SVG path ──

fn to_bezier_path(pts: &[Pt]) -> String {
    let step = 3;
    let mut ds: Vec<Pt> = vec![pts[0]];
    let mut i = step;
    while i < pts.len() - 1 {
        ds.push(pts[i]);
        i += step;
    }
    ds.push(*pts.last().unwrap());

    if ds.len() < 3 {
        return String::new();
    }

    let mut d = format!("M{:.1},{:.1}", ds[0][0], ds[0][1]);
    let n = ds.len();

    for i in 0..n - 1 {
        let p0 = ds[if i > 0 { i - 1 } else { 0 }];
        let p1 = ds[i];
        let p2 = ds[(i + 1).min(n - 1)];
        let p3 = ds[(i + 2).min(n - 1)];
        let k = 5.0;

        write!(
            d,
            "C{:.1},{:.1} {:.1},{:.1} {:.1},{:.1}",
            p1[0] + (p2[0] - p0[0]) / k,
            p1[1] + (p2[1] - p0[1]) / k,
            p2[0] - (p3[0] - p1[0]) / k,
            p2[1] - (p3[1] - p1[1]) / k,
            p2[0],
            p2[1],
        )
        .ok();
    }
    d
}

// ── Public API ──

/// Generate a deterministic contour-based SVG from an NFT token ID.
/// Output is identical to the TypeScript version (same PRNG + algorithm).
pub fn generate_nft_svg(token_id: &str) -> String {
    let mut rng = Lcg::new(fnv_hash(token_id));

    // Color picked FIRST — must match TypeScript order
    let ci = (rng.next() * NEON_COLORS.len() as f64) as usize;
    let stroke = NEON_COLORS[ci.min(NEON_COLORS.len() - 1)];

    let n1 = Noise::new(&mut rng);
    let n2 = Noise::new(&mut rng);

    // Random focal point position
    let fx = PAD as f64 + rng.next() * IMG_W as f64;
    let fy = PAD as f64 + rng.next() * IMG_H as f64;

    // Build scalar field
    let cols = FW / RES + 1;
    let rows = FH / RES + 1;
    let mut field = vec![0.0f64; cols * rows];

    for iy in 0..rows {
        for ix in 0..cols {
            let x = (ix * RES) as f64;
            let y = (iy * RES) as f64;
            let wx = n1.sample(x * 0.006, y * 0.006) * WARP
                + n1.sample(x * 0.013, y * 0.013) * WARP * 0.4;
            let wy = n2.sample(x * 0.006, y * 0.006) * WARP
                + n2.sample(x * 0.013, y * 0.013) * WARP * 0.4;
            let dx = x + wx - fx;
            let dy = y + wy - fy;
            field[iy * cols + ix] = (dx * dx + dy * dy).sqrt();
        }
    }

    // Find field range
    let mn = field.iter().cloned().fold(f64::INFINITY, f64::min);
    let mx = field.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // Extract iso-lines and build SVG paths
    let mut paths = String::with_capacity(16384);
    for l in 0..LINES {
        let thr = mn + (mx - mn) * (l as f64 + 1.0) / (LINES as f64 + 1.0);
        let segs = march_squares(&field, cols, rows, thr);
        let chains = chain_segments(&segs);
        for ch in &chains {
            let d = to_bezier_path(ch);
            if !d.is_empty() {
                write!(
                    paths,
                    r#"<path d="{}" fill="none" stroke="{}" stroke-width="{}" stroke-linecap="round" opacity="0.6"/>"#,
                    d, stroke, STROKE
                )
                    .ok();
            }
        }
    }

    // Show wider view including padding area (2:3 ratio preserved)
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="10 10 396 594" width="{w}" height="{h}"><rect x="10" y="10" width="396" height="594" fill="{bg}"/>{paths}</svg>"#,
        w = IMG_W,
        h = IMG_H,
        bg = BG,
        paths = paths,
    )
}

/// Get the neon color assigned to a token ID
pub fn get_nft_color(token_id: &str) -> (&'static str, &'static str) {
    let mut rng = Lcg::new(fnv_hash(token_id));
    // Color is the FIRST rng call — matches generate_nft_svg
    let ci = (rng.next() * NEON_COLORS.len() as f64) as usize;
    (BG, NEON_COLORS[ci.min(NEON_COLORS.len() - 1)])
}

/// Generate XLS-24 compatible metadata JSON for an NFT
pub fn generate_nft_metadata(token_id: &str, image_url: &str) -> String {
    let short_id = if token_id.len() >= 12 {
        format!("{}...{}", &token_id[..6], &token_id[token_id.len() - 6..])
    } else {
        token_id.to_string()
    };

    serde_json::json!({
        "name": format!("XRPL Vault #{}", &short_id),
        "description": "End-to-end encrypted file stored on XRPL Vault with Proxy Re-Encryption access control",
        "image": image_url,
        "attributes": [
            {"trait_type": "Encryption", "value": "AES-256-GCM"},
            {"trait_type": "Access Control", "value": "Proxy Re-Encryption"},
            {"trait_type": "Network", "value": "XRPL"},
            {"trait_type": "Token ID", "value": &short_id}
        ]
    })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let id = "0008000049A8ECBB223D180261DC8A3A8995E141FAB37FDCC533AA9E00F42E03";
        assert_eq!(generate_nft_svg(id), generate_nft_svg(id));
    }

    #[test]
    fn test_unique() {
        let s1 =
            generate_nft_svg("0008000049A8ECBB223D180261DC8A3A8995E141FAB37FDCC533AA9E00F42E03");
        let s2 =
            generate_nft_svg("0008000049A8ECBB223D180261DC8A3A8995E141FAB37FDCDC197B9F00F42E04");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_valid_svg() {
        let svg =
            generate_nft_svg("0008000049A8ECBB223D180261DC8A3A8995E141FAB37FDCC533AA9E00F42E03");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("path"));
    }

    #[test]
    fn test_all_colors_reachable() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let id = format!("{:064x}", i * 7919u64);
            let (_, color) = get_nft_color(&id);
            seen.insert(color);
        }
        assert!(seen.len() >= 8, "Should reach most neon colors");
    }

    #[test]
    fn test_fnv_hash() {
        // Verify FNV produces expected values
        let h = fnv_hash("test");
        assert_ne!(h, 0);
        assert_eq!(fnv_hash("test"), fnv_hash("test"));
        assert_ne!(fnv_hash("test"), fnv_hash("test2"));
    }
}
