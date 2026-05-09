// NFT Contour Image Generator
// Generates unique contour-based NFT thumbnails from tokenId seed
// Fixed: line count, stroke, warp | Varies: position, color

const NEON_COLORS = [
    '#ff3b7a','#00e5a0','#ffc53d','#3b82f6','#a855f7',
    '#06b6d4','#f97316','#ec4899','#22d3ee','#84cc16',
]
const BG = '#060608'
const LINES = 25
const STROKE = 1.8
const WARP = 35
const W = 256
const H = 384
const PAD = 80
const FW = W + PAD * 2
const FH = H + PAD * 2
const RES = 3

function fnvHash(s: string): number {
    let h = 2166136261 >>> 0
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0 }
    return h
}
function lcg(seed: number) {
    let s = seed >>> 0
    return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 0xffffffff }
}
function makeNoise(rng: () => number) {
    const N = 32, g: number[] = []
    for (let i = 0; i < N * N; i++) g.push(rng() * 2 - 1)
    const gt = (x: number, y: number) => g[((x % N) + N) % N + ((y % N) + N) % N * N]
    const q = (t: number) => t * t * t * (t * (t * 6 - 15) + 10)
    return (x: number, y: number) => {
        const ix = Math.floor(x), iy = Math.floor(y), fx = q(x - ix), fy = q(y - iy)
        return (gt(ix, iy) * (1 - fx) + gt(ix + 1, iy) * fx) * (1 - fy) +
            (gt(ix, iy + 1) * (1 - fx) + gt(ix + 1, iy + 1) * fx) * fy
    }
}

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

function chainSegments(segs: [number, number][][]) {
    const eps = 0.01
    const pts = segs.map(s => [
        [s[0][0] * RES, s[0][1] * RES] as [number, number],
        [s[1][0] * RES, s[1][1] * RES] as [number, number]
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

function toBezierPath(pts: [number, number][]): string {
    const step = 3, ds: [number, number][] = [pts[0]]
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

/** Generate SVG string for an NFT contour image */
export function generateNftSvg(tokenId: string, colorOverride?: string): string {
    const rng = lcg(fnvHash(tokenId))
    // Color picked FIRST — must match getNftColors order
    const ci = Math.floor(rng() * NEON_COLORS.length)
    const stroke = colorOverride || NEON_COLORS[ci]
    const n1 = makeNoise(rng), n2 = makeNoise(rng)
    const fx = PAD + rng() * W, fy = PAD + rng() * H

    const cols = Math.ceil(FW / RES) + 1, rows = Math.ceil(FH / RES) + 1
    const field = new Float32Array(cols * rows)
    for (let iy = 0; iy < rows; iy++) for (let ix = 0; ix < cols; ix++) {
        const x = ix * RES, y = iy * RES
        const wx = n1(x * 0.006, y * 0.006) * WARP + n1(x * 0.013, y * 0.013) * WARP * 0.4
        const wy = n2(x * 0.006, y * 0.006) * WARP + n2(x * 0.013, y * 0.013) * WARP * 0.4
        field[iy * cols + ix] = Math.sqrt((x + wx - fx) ** 2 + (y + wy - fy) ** 2)
    }

    let mn = Infinity, mx = -Infinity
    for (let i = 0; i < field.length; i++) { mn = Math.min(mn, field[i]); mx = Math.max(mx, field[i]) }

    let paths = ''
    for (let l = 0; l < LINES; l++) {
        const t = mn + (mx - mn) * (l + 1) / (LINES + 1)
        const chains = chainSegments(marchSquares(field, cols, rows, t))
        for (const ch of chains) {
            const d = toBezierPath(ch)
            if (d) paths += `<path d="${d}" fill="none" stroke="${stroke}" stroke-width="${STROKE}" stroke-linecap="round" opacity="0.6"/>`
        }
    }

    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${FW} ${FH}" width="${FW}" height="${FH}"><rect x="-200" y="-200" width="2000" height="2000" fill="${BG}"/>${paths}</svg>`
}

/** Get neon color for a tokenId */
export function getNftColors(tokenId: string, colorOverride?: string): { bg: string; stroke: string } {
    const rng = lcg(fnvHash(tokenId))
    // Color is the FIRST rng call — matches generateNftSvg
    const stroke = NEON_COLORS[Math.floor(rng() * NEON_COLORS.length)]
    const finalStroke = colorOverride || stroke; return { bg: BG, stroke: finalStroke }
}

/** Get data URL for NFT image — use as CSS background-image (cached) */
const _nftImageCache = new Map<string, string>()
export function getNftImageUrl(tokenId: string, colorOverride?: string): string {
    const cacheKey = colorOverride ? tokenId + ':' + colorOverride : tokenId; let cached = _nftImageCache.get(cacheKey)
    if (!cached) {
        const svg = generateNftSvg(tokenId, colorOverride)
        cached = `url("data:image/svg+xml,${encodeURIComponent(svg)}")`
        _nftImageCache.set(cacheKey, cached)
    }
    return cached
}