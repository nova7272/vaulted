import { useMemo } from 'react'

// ── Seeded PRNG ──
function fnvHash(str: string): number {
    let h = 2166136261 >>> 0
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0 }
    return h
}
function lcg(seed: number) {
    let s = seed >>> 0
    return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 0xffffffff }
}

// ── Smooth value noise (quintic interpolation) ──
function makeNoise(rng: () => number) {
    const N = 48, g: number[] = []
    for (let i = 0; i < N * N; i++) g.push(rng() * 2 - 1)
    const gt = (x: number, y: number) => g[((x % N) + N) % N + ((y % N) + N) % N * N]
    const q = (t: number) => t * t * t * (t * (t * 6 - 15) + 10)
    return (x: number, y: number) => {
        const ix = Math.floor(x), iy = Math.floor(y), fx = q(x - ix), fy = q(y - iy)
        return (gt(ix, iy) * (1 - fx) + gt(ix + 1, iy) * fx) * (1 - fy) +
            (gt(ix, iy + 1) * (1 - fx) + gt(ix + 1, iy + 1) * fx) * fy
    }
}

// ── Marching squares ──
function marchSquares(field: Float32Array, cols: number, rows: number, thr: number) {
    const segs: [number, number][][] = []
    for (let iy = 0; iy < rows - 1; iy++) for (let ix = 0; ix < cols - 1; ix++) {
        const v0 = field[iy * cols + ix], v1 = field[iy * cols + ix + 1]
        const v2 = field[(iy + 1) * cols + ix + 1], v3 = field[(iy + 1) * cols + ix]
        let c = 0; if (v0 > thr) c |= 1; if (v1 > thr) c |= 2; if (v2 > thr) c |= 4; if (v3 > thr) c |= 8
        if (c === 0 || c === 15) continue
        const lp = (a: number, b: number, pa: [number, number], pb: [number, number]): [number, number] => {
            if (Math.abs(a - b) < 1e-6) return [(pa[0] + pb[0]) / 2, (pa[1] + pb[1]) / 2]
            const t = (thr - a) / (b - a); return [pa[0] + (pb[0] - pa[0]) * t, pa[1] + (pb[1] - pa[1]) * t]
        }
        const p: [number, number] = [ix, iy], q: [number, number] = [ix + 1, iy]
        const r: [number, number] = [ix + 1, iy + 1], s: [number, number] = [ix, iy + 1]
        const a = lp(v0, v1, p, q), b = lp(v1, v2, q, r), cc = lp(v3, v2, s, r), d = lp(v0, v3, p, s)
        switch (c) {
            case 1: case 14: segs.push([d, a]); break; case 2: case 13: segs.push([a, b]); break
            case 3: case 12: segs.push([d, b]); break; case 4: case 11: segs.push([b, cc]); break
            case 5: segs.push([d, a], [b, cc]); break; case 6: case 9: segs.push([a, cc]); break
            case 7: case 8: segs.push([d, cc]); break; case 10: segs.push([d, cc], [a, b]); break
        }
    }
    return segs
}

// ── Chain segments into polylines ──
function chainSegments(segs: [number, number][][], res: number) {
    const eps = 0.01
    const pts = segs.map(s => [
        [s[0][0] * res, s[0][1] * res] as [number, number],
        [s[1][0] * res, s[1][1] * res] as [number, number]
    ])
    const used = new Uint8Array(pts.length), chains: [number, number][][] = []
    const near = (a: [number, number], b: [number, number]) => Math.abs(a[0] - b[0]) < eps && Math.abs(a[1] - b[1]) < eps
    for (let i = 0; i < pts.length; i++) {
        if (used[i]) continue; used[i] = 1
        const ch: [number, number][] = [pts[i][0], pts[i][1]]
        let changed = true
        while (changed) { changed = false; for (let j = 0; j < pts.length; j++) {
            if (used[j]) continue; const hd = ch[0], tl = ch[ch.length - 1]
            if (near(tl, pts[j][0])) { ch.push(pts[j][1]); used[j] = 1; changed = true }
            else if (near(tl, pts[j][1])) { ch.push(pts[j][0]); used[j] = 1; changed = true }
            else if (near(hd, pts[j][1])) { ch.unshift(pts[j][0]); used[j] = 1; changed = true }
            else if (near(hd, pts[j][0])) { ch.unshift(pts[j][1]); used[j] = 1; changed = true }
        }}
        if (ch.length > 4) chains.push(ch)
    }
    return chains
}

// ── Downsample + Catmull-Rom → cubic Bézier path ──
function toBezierPath(pts: [number, number][]): string {
    const step = 4, ds: [number, number][] = [pts[0]]
    for (let i = step; i < pts.length - 1; i += step) ds.push(pts[i])
    ds.push(pts[pts.length - 1])
    if (ds.length < 3) return ''
    let d = `M${ds[0][0].toFixed(1)},${ds[0][1].toFixed(1)}`
    for (let i = 0; i < ds.length - 1; i++) {
        const p0 = ds[Math.max(0, i - 1)], p1 = ds[i]
        const p2 = ds[Math.min(ds.length - 1, i + 1)], p3 = ds[Math.min(ds.length - 1, i + 2)]
        const k = 5
        d += `C${(p1[0] + (p2[0] - p0[0]) / k).toFixed(1)},${(p1[1] + (p2[1] - p0[1]) / k).toFixed(1)} ` +
            `${(p2[0] - (p3[0] - p1[0]) / k).toFixed(1)},${(p2[1] - (p3[1] - p1[1]) / k).toFixed(1)} ` +
            `${p2[0].toFixed(1)},${p2[1].toFixed(1)}`
    }
    return d
}

// ── Component ──
interface Props {
    opacity?: number
    seed?: string
    color?: string
    strokeWidth?: number
    numLines?: number
}

export default function FingerprintBg({
                                          opacity = 0.5,
                                          seed = 'vaulted',
                                          color = 'rgba(106,160,255,0.06)',
                                          strokeWidth = 1.2,
                                          numLines = 60,
                                      }: Props) {
    const svgData = useMemo(() => {
        const rng = lcg(fnvHash(seed))
        const noise1 = makeNoise(rng)
        const noise2 = makeNoise(rng)

        // Viewport 1200×800, padded 300px each side so contours never cut at edges
        const PAD = 300
        const VW = 1200, VH = 800
        const TW = VW + PAD * 2, TH = VH + PAD * 2

        // Focal point at center
        const fcx = TW / 2
        const fcy = TH / 2

        // Build scalar field: distance from focus + noise warp
        const res = 4
        const cols = Math.ceil(TW / res) + 1
        const rows = Math.ceil(TH / res) + 1
        const field = new Float32Array(cols * rows)
        const warp = 35

        for (let iy = 0; iy < rows; iy++) {
            for (let ix = 0; ix < cols; ix++) {
                const x = ix * res, y = iy * res
                const wx = noise1(x * 0.006, y * 0.006) * warp + noise1(x * 0.013, y * 0.013) * warp * 0.4
                const wy = noise2(x * 0.006, y * 0.006) * warp + noise2(x * 0.013, y * 0.013) * warp * 0.4
                field[iy * cols + ix] = Math.sqrt((x + wx - fcx) ** 2 + (y + wy - fcy) ** 2)
            }
        }

        // Find range
        let mn = Infinity, mx = -Infinity
        for (let i = 0; i < field.length; i++) { mn = Math.min(mn, field[i]); mx = Math.max(mx, field[i]) }

        // Extract iso-lines
        const paths: string[] = []
        for (let l = 0; l < numLines; l++) {
            const threshold = mn + (mx - mn) * (l + 1) / (numLines + 1)
            const segs = marchSquares(field, cols, rows, threshold)
            const chains = chainSegments(segs, res)
            for (const ch of chains) {
                const d = toBezierPath(ch)
                if (d) paths.push(d)
            }
        }

        return { paths, PAD, VW, VH }
    }, [seed, numLines])

    return (
        <div className="fingerprint-bg" style={{ opacity }}>
            <svg
                width="100%"
                height="100%"
                viewBox={`${svgData.PAD} ${svgData.PAD} ${svgData.VW} ${svgData.VH}`}
                preserveAspectRatio="xMidYMid slice"
                style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}
            >
                {svgData.paths.map((d, i) => (
                    <path key={i} d={d} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
                ))}
            </svg>
        </div>
    )
}