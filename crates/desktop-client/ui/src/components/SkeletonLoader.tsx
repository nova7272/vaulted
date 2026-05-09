/**
 * Skeleton loading placeholders
 *
 * Replaces bare spinners with shimmer-animated placeholders
 * that match the shape of real content (file cards, lists, etc.)
 */
import { CSSProperties } from 'react'

/* ── Base shimmer block ── */
function Bone({ w, h, r = 6, style }: { w?: string | number; h?: string | number; r?: number; style?: CSSProperties }) {
    return (
        <div
            className="v-skeleton"
            style={{
                width: w ?? '100%',
                height: h ?? 16,
                borderRadius: r,
                ...style,
            }}
        />
    )
}

/* ── File card skeleton (matches grid card layout) ── */
export function FileCardSkeleton() {
    return (
        <div style={{
            display: 'flex',
            background: 'var(--bg-2)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
        }}>
            {/* NFT image strip */}
            <Bone w={140} h="100%" r={0} style={{ minHeight: 180, flexShrink: 0 }} />

            {/* ID strip */}
            <Bone w={34} h="auto" r={0} style={{ minHeight: 180 }} />

            {/* Body */}
            <div style={{ flex: 1, padding: '22px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 12, minHeight: 180 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <Bone w="65%" h={22} />
                    <Bone w="35%" h={14} />
                    <Bone w="45%" h={14} />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <Bone h={50} r={10} />
                    <Bone h={50} r={10} />
                    <Bone h={50} r={10} />
                </div>
            </div>
        </div>
    )
}

/* ── Grid of file card skeletons ── */
export function FilesGridSkeleton({ count = 10 }: { count?: number }) {
    return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, overflow: 'hidden', maxHeight: 'calc(100vh - 200px)' }}>
            {Array.from({ length: count }).map((_, i) => (
                <FileCardSkeleton key={i} />
            ))}
        </div>
    )
}

/* ── Section header skeleton ── */
export function SectionHeaderSkeleton() {
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <Bone w={120} h={28} />
                <Bone w={180} h={14} />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
                <Bone w={80} h={38} r={10} />
                <Bone w={100} h={38} r={10} />
            </div>
        </div>
    )
}

/* ── Full files screen skeleton (cards only, header is real) ── */
export function FilesScreenSkeleton() {
    return (
        <FilesGridSkeleton count={10} />
    )
}

/* ── Secure notes screen skeleton (cards only, header is real) ── */
export function SecureNotesScreenSkeleton() {
    return (
        <FilesGridSkeleton count={10} />
    )
}

/* ── Activity row skeleton ── */
function ActivityRowSkeleton() {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', gap: 16,
            padding: '16px 18px',
            borderRadius: 'var(--radius-sm)',
        }}>
            <Bone w={40} h={40} r={20} />
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                <Bone w="55%" h={16} />
                <Bone w="35%" h={13} />
            </div>
            <Bone w={70} h={14} />
        </div>
    )
}

/* ── Activity screen skeleton ── */
export function ActivityScreenSkeleton() {
    return (
        <div>
            <SectionHeaderSkeleton />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {Array.from({ length: 6 }).map((_, i) => (
                    <ActivityRowSkeleton key={i} />
                ))}
            </div>
        </div>
    )
}

export default Bone