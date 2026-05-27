import { useState, useEffect, useMemo, useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { toast } from '../components/Toast'
import { ActivityScreenSkeleton } from '../components/SkeletonLoader'
import { useActivityLog, type ActivityType } from '../contexts/ActivityLogContext'
import { formatError } from '../utils/formatError'

/* ── Types ── */
interface IncomingOffer {
    offerIndex: string
    nftTokenId: string
    fromAddress: string
    amount: string
}

interface OutgoingOffer {
    offerIndex: string
    nftTokenId: string
    toAddress: string
    filename: string
    status: string
    createdAt: string
}

interface TransferHistoryItem {
    transferId: string
    nftTokenId: string
    otherParty: string
    direction: 'sent' | 'received'
    status: string
    createdAt: string
    filename: string | null
}

interface TransferHistory {
    sent: TransferHistoryItem[]
    received: TransferHistoryItem[]
}

interface ClaimResult {
    success: boolean
    txHash: string
    nftTokenId?: string | null
    transferId?: string | null
    engineResult: string
    engineResultMessage: string
}

/* ── Filter types ── */
type FilterType = 'all' | 'transfers' | 'creates' | 'removes'

/* ── Unified timeline entry ── */
interface TimelineEntry {
    id: string
    type: ActivityType
    label: string
    message: string
    detail?: string
    timestamp: Date
    status: string
    source: 'local' | 'transfer'
    transferId?: string
    direction?: 'sent' | 'received'
}

/* ── Icons ── */
const IcoRefresh = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
        <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
    </svg>
)
const IcoCheck = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="20 6 9 17 4 12"/>
    </svg>
)
/* ── Meta maps ── */
const TYPE_META: Record<string, { label: string; icon: string; color: string }> = {
    encrypt:           { label: 'Encrypted',         icon: '🔐', color: '#818cf8' },
    upload:            { label: 'Uploaded',           icon: '⬆',  color: '#6aa0ff' },
    download:          { label: 'Downloaded',         icon: '⬇',  color: '#6ac79a' },
    decrypt:           { label: 'Decrypted',          icon: '🔓', color: '#22d3ee' },
    transfer_sent:     { label: 'Sent',               icon: '↗',  color: '#e6b35a' },
    transfer_received: { label: 'Received',           icon: '↙',  color: '#6ac79a' },
    transfer_failed:   { label: 'Transfer Failed',    icon: '✕',  color: '#e07a6a' },
    nft_claimed:       { label: 'Claimed',            icon: '✓',  color: '#6ac79a' },
    nft_burned:        { label: 'Burned',             icon: '🔥', color: '#e07a6a' },
    file_deleted:      { label: 'Deleted',            icon: '🗑',  color: '#e07a6a' },
    auth_login:        { label: 'Signed In',          icon: '→',  color: '#6aa0ff' },
    auth_logout:       { label: 'Signed Out',         icon: '←',  color: '#868b98' },
    info:              { label: 'Info',                icon: 'ℹ',  color: '#868b98' },
}

const STATUS_COLORS: Record<string, { bg: string; color: string; label: string }> = {
    pending:    { bg: 'rgba(245,158,11,0.12)', color: '#e6b35a', label: 'Pending' },
    completed:  { bg: 'rgba(59,130,246,0.12)', color: '#6aa0ff', label: 'Completed' },
    finalized:  { bg: 'rgba(34,197,94,0.12)',  color: '#6ac79a', label: 'Finalized' },
    failed:     { bg: 'rgba(239,68,68,0.12)',  color: '#e07a6a', label: 'Failed' },
    cancelled:  { bg: 'rgba(113,113,122,0.12)',color: '#5a5f6c', label: 'Cancelled' },
    success:    { bg: 'rgba(34,197,94,0.12)',  color: '#6ac79a', label: 'Done' },
    error:      { bg: 'rgba(239,68,68,0.12)',  color: '#e07a6a', label: 'Error' },
}

/* ── Helpers ── */
const short = (s: string, pre = 6, suf = 4) => `${s.slice(0, pre)}...${s.slice(-suf)}`

function fmtDate(d: Date): string {
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/* ── Component ── */
interface ActivityScreenProps {
    oracleConnected?: boolean
}

export default function ActivityScreen({ oracleConnected }: ActivityScreenProps) {
    void oracleConnected
    const { entries: localEntries, addEntry } = useActivityLog()
    const [incomingOffers, setIncomingOffers] = useState<IncomingOffer[]>([])
    const [outgoingOffers, setOutgoingOffers] = useState<OutgoingOffer[]>([])
    const [transferHistory, setTransferHistory] = useState<TransferHistory | null>(null)
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState<FilterType>('all')
    const [claimingOffer, setClaimingOffer] = useState<string | null>(null)
    const [cancelling, setCancelling] = useState<string | null>(null)

    const loadAll = useCallback(async () => {
        setLoading(true)
        try {
            const [incoming, outgoing, history] = await Promise.all([
                invoke<IncomingOffer[]>('get_incoming_offers').catch(() => []),
                invoke<OutgoingOffer[]>('get_outgoing_offers').catch(() => []),
                invoke<TransferHistory>('get_transfer_history').catch(() => ({ sent: [], received: [] })),
            ])
            setIncomingOffers(incoming)
            setOutgoingOffers(outgoing)
            setTransferHistory(history)
        } catch (e) {
            console.error('Failed to load activity data:', e)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { loadAll() }, [loadAll])

    // Auto-refresh every 30 seconds
    useEffect(() => {
        const iv = setInterval(loadAll, 30000)
        return () => clearInterval(iv)
    }, [loadAll])

    /* ── Claim ── */
    const acceptOffer = async (offer: IncomingOffer) => {
        try {
            setClaimingOffer(offer.offerIndex)
            const result = await invoke<ClaimResult>('claim_nft', { offerIndex: offer.offerIndex })
            setIncomingOffers(prev => prev.filter(item => item.offerIndex !== offer.offerIndex))
            toast({ type: 'success', title: 'NFT claimed', sub: `Transaction ${result.txHash.slice(0, 8)}... accepted` })
            addEntry('transfer_received', 'Accepted NFT transfer', { detail: `Offer: ${short(offer.offerIndex, 8, 4)}`, nftTokenId: offer.nftTokenId })
            loadAll()
        } catch (e) {
            toast({ type: 'error', title: 'Claim failed', sub: formatError(e) })
        } finally {
            setClaimingOffer(null)
        }
    }

    /* ── Cancel transfer ── */
    const cancelTransfer = async (transferId: string) => {
        try {
            setCancelling(transferId)
            await invoke<{ success: boolean; message: string }>('cancel_transfer', { transferId })
            toast({ type: 'success', title: 'Transfer cancelled' })
            addEntry('info', 'Transfer cancelled', { detail: transferId.slice(0, 12) + '...' })
            loadAll()
        } catch (e) {
            toast({ type: 'error', title: 'Cancel failed', sub: formatError(e) })
        } finally {
            setCancelling(null)
        }
    }

    /* ── Build timeline ── */
    const pendingOut = outgoingOffers.filter(o => o.status === 'pending' || o.status === 'completed')

    const timeline = useMemo<TimelineEntry[]>(() => {
        const items: TimelineEntry[] = []

        // Local activity entries
        localEntries.forEach(entry => {
            items.push({
                id: `local-${entry.id}`,
                type: entry.type,
                label: TYPE_META[entry.type]?.label || entry.type,
                message: entry.message,
                detail: entry.detail,
                timestamp: entry.timestamp,
                status: entry.status,
                source: 'local',
            })
        })

        // Transfer history from backend
        if (transferHistory) {
            const all = [...transferHistory.sent, ...transferHistory.received]
            all.forEach(t => {
                const type: ActivityType = t.direction === 'sent' ? 'transfer_sent' : 'transfer_received'
                items.push({
                    id: `transfer-${t.transferId}`,
                    type,
                    label: TYPE_META[type]?.label || type,
                    message: t.filename || `NFT ${short(t.nftTokenId, 8, 4)}`,
                    detail: t.direction === 'sent' ? `To: ${short(t.otherParty)}` : `From: ${short(t.otherParty)}`,
                    timestamp: new Date(t.createdAt),
                    status: t.status,
                    source: 'transfer',
                    transferId: t.transferId,
                    direction: t.direction,
                })
            })
        }

        // Active outgoing offers (not yet in history)
        pendingOut.forEach(o => {
            const existsInHistory = items.some(i => i.source === 'transfer' && i.message === (o.filename || `NFT ${short(o.nftTokenId, 8, 4)}`))
            if (!existsInHistory) {
                items.push({
                    id: `outgoing-${o.offerIndex}`,
                    type: 'transfer_sent',
                    label: 'Sent',
                    message: o.filename || `NFT ${short(o.nftTokenId, 8, 4)}`,
                    detail: `To: ${short(o.toAddress)}`,
                    timestamp: new Date(o.createdAt),
                    status: o.status,
                    source: 'transfer',
                    direction: 'sent',
                })
            }
        })

        items.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())

        // Apply filter
        if (filter === 'transfers') return items.filter(i => i.type.startsWith('transfer') || i.type === 'nft_claimed')
        if (filter === 'creates') return items.filter(i => ['encrypt', 'upload'].includes(i.type))
        if (filter === 'removes') return items.filter(i => ['file_deleted', 'nft_burned'].includes(i.type))
        return items
    }, [localEntries, transferHistory, pendingOut, filter])

    return (
        <div style={{ maxWidth: 880, margin: '0 auto' }}>
            {/* Header */}
            <div className="v-section-head" style={{ marginBottom: 20 }}>
                <div>
                    <div className="v-section-title">Activity</div>
                    <div className="v-section-sub">Transfers, uploads, and all vault events</div>
                </div>
                <button onClick={loadAll} className="v-btn">
                    <IcoRefresh /> Refresh
                </button>
            </div>

            {/* ── INCOMING OFFERS (actionable) ── */}
            {incomingOffers.length > 0 && (
                <section style={{ marginBottom: 24 }}>
                    <div className="v-section-title" style={{fontSize:18, marginBottom: 12}}>Incoming offers</div>
                    <div className="v-col" style={{gap: 8}}>
                        {incomingOffers.map(offer => (
                            <div key={offer.offerIndex} className="v-offer-card">
                                <div style={{width:44,height:44,borderRadius:10,background:'var(--ok-soft)',color:'var(--ok)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:20,flexShrink:0}}>↙</div>
                                <div className="v-col" style={{flex:1,gap:2}}>
                                    <div className="title">NFT {short(offer.nftTokenId, 8, 4)}</div>
                                    <div className="sub">from {short(offer.fromAddress)}</div>
                                </div>

                                <button
                                    onClick={() => acceptOffer(offer)}
                                    disabled={claimingOffer !== null}
                                    className="v-btn v-btn-primary"
                                    style={{opacity: claimingOffer ? 0.4 : 1}}
                                ><IcoCheck /> Accept</button>
                            </div>
                        ))}
                    </div>
                </section>
            )}

            {/* ── FILTERS ── */}
            <div className="v-row" style={{ gap: 6, marginBottom: 16 }}>
                {([
                    { key: 'all' as FilterType, label: 'All' },
                    { key: 'transfers' as FilterType, label: 'Transfers' },
                    { key: 'creates' as FilterType, label: 'Creates' },
                    { key: 'removes' as FilterType, label: 'Removes' },
                ]).map(f => (
                    <span
                        key={f.key}
                        className={`v-chip${filter === f.key ? ' active' : ''}`}
                        onClick={() => setFilter(f.key)}
                    >
                        {f.label}
                    </span>
                ))}
            </div>

            {/* ── TIMELINE ── */}
            {loading && timeline.length === 0 ? (
                <ActivityScreenSkeleton />
            ) : timeline.length === 0 ? (
                <div style={{
                    textAlign: 'center', padding: '60px 24px',
                    borderRadius: 'var(--radius-md)', border: '1px dashed var(--bg-4)', background: 'var(--bg-1)',
                }}>
                    <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5" style={{ marginBottom: 16, opacity: 0.4 }}>
                        <path d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    <p style={{ fontSize: 16, color: 'var(--text-muted)', margin: '0 0 6px', fontWeight: 500 }}>No activity yet</p>
                    <p style={{ fontSize: 14, color: 'var(--text-muted)', margin: 0, opacity: 0.6 }}>
                        Your actions will appear here as you use the app
                    </p>
                </div>
            ) : (
                <div className="v-col" style={{ gap: 0 }}>
                    {timeline.map(entry => {
                        const meta = TYPE_META[entry.type] || TYPE_META.info
                        const st = STATUS_COLORS[entry.status] || STATUS_COLORS.success
                        const canCancel = entry.source === 'transfer'
                            && entry.direction === 'sent'
                            && (entry.status === 'pending' || entry.status === 'completed')

                        return (
                            <div key={entry.id} className="v-event">
                                {/* Icon */}
                                <div className="v-event-ico" style={{
                                    background: `${meta.color}15`, color: meta.color,
                                    borderRadius: 10, fontSize: 18,
                                }}>
                                    {meta.icon}
                                </div>

                                {/* Content */}
                                <div>
                                    <div className="v-event-label">
                                        {meta.label}
                                        <span className={`v-badge ${entry.status === 'pending' ? 'pending' : entry.status === 'failed' || entry.status === 'error' ? 'err' : 'ok'}`}>
                                            {st.label}
                                        </span>
                                    </div>
                                    <div className="v-event-desc">
                                        {entry.message}
                                        {entry.detail && (
                                            <span style={{ color: 'var(--fg-2)', marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                                                {entry.detail}
                                            </span>
                                        )}
                                    </div>
                                </div>

                                {/* Cancel button for pending transfers */}
                                {canCancel ? (
                                    <button
                                        onClick={() => entry.transferId && cancelTransfer(entry.transferId)}
                                        disabled={cancelling === entry.transferId}
                                        className="v-btn v-btn-danger"
                                        style={{height:34,padding:'0 14px',fontSize:13}}
                                    >
                                        {cancelling === entry.transferId ? '...' : 'Cancel'}
                                    </button>
                                ) : <span />}

                                {/* Date/time */}
                                <div className="v-event-time">
                                    {fmtDate(entry.timestamp)}
                                </div>
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}
