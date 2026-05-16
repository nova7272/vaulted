/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from 'react'

export interface ToastData {
    id: number
    type: 'success' | 'info' | 'error'
    title: string
    sub?: string
}

/** Maximum visible toasts at once */
const MAX_VISIBLE = 3
/** Auto-dismiss duration in ms */
const DISMISS_MS = 4000

interface ToastProps {
    toast: ToastData
    onRemove: (id: number) => void
}

function Toast({ toast, onRemove }: ToastProps) {
    const [visible, setVisible] = useState(false)

    useEffect(() => {
        requestAnimationFrame(() => setVisible(true))
        const t = setTimeout(() => {
            setVisible(false)
            setTimeout(() => onRemove(toast.id), 300)
        }, DISMISS_MS)
        return () => clearTimeout(t)
    }, [toast.id, onRemove])

    const colors = {
        success: { bg: '#0d1a14', border: 'rgba(106,199,154,0.3)', ico: '#6ac79a', ibg: 'rgba(106,199,154,0.15)' },
        info:    { bg: '#0d1220', border: 'rgba(106,160,255,0.3)', ico: '#6aa0ff', ibg: 'rgba(106,160,255,0.15)' },
        error:   { bg: '#1a0d0d', border: 'rgba(224,122,106,0.3)', ico: '#e07a6a', ibg: 'rgba(224,122,106,0.15)' },
    }
    const c = colors[toast.type]

    const icon = toast.type === 'success' ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>
    ) : toast.type === 'error' ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" /></svg>
    ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></svg>
    )

    return (
        <div
            role="alert"
            aria-live="assertive"
            style={{
                display: 'flex', alignItems: 'center', gap: 10,
                background: c.bg, border: `1px solid ${c.border}`,
                borderRadius: 12, padding: '10px 14px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
                minWidth: 280, maxWidth: 380,
                transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                opacity: visible ? 1 : 0,
                transform: visible ? 'translateY(0) scale(1)' : 'translateY(12px) scale(0.95)',
            }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: c.ibg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: c.ico, flexShrink: 0 }}>
                {icon}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 13, fontWeight: 600, color: '#f2f3f7', margin: 0, lineHeight: 1.3 }}>{toast.title}</p>
                {toast.sub && <p style={{ fontSize: 11, color: '#868b98', margin: '2px 0 0', overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' as const }}>{toast.sub}</p>}
            </div>
            <button
                aria-label="Close notification"
                onClick={() => { setVisible(false); setTimeout(() => onRemove(toast.id), 300) }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#5a5f6c', padding: '2px', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>
            </button>
        </div>
    )
}

interface ToastContainerProps {
    toasts: ToastData[]
    onRemove: (id: number) => void
}

export function ToastContainer({ toasts, onRemove }: ToastContainerProps) {
    // Only show the last MAX_VISIBLE toasts
    const visibleToasts = toasts.slice(-MAX_VISIBLE)
    // Count overflow
    const overflow = toasts.length - MAX_VISIBLE

    return (
        <div style={{
            position: 'fixed', bottom: 20, right: 20,
            display: 'flex', flexDirection: 'column', gap: 8,
            zIndex: 1000, pointerEvents: 'none',
        }}>
            {overflow > 0 && (
                <div style={{
                    pointerEvents: 'all',
                    textAlign: 'center',
                    fontSize: 11,
                    color: '#5a5f6c',
                    padding: '4px 0',
                }}>
                    +{overflow} more
                </div>
            )}
            {visibleToasts.map(t => (
                <div key={t.id} style={{ pointerEvents: 'all' }}>
                    <Toast toast={t} onRemove={onRemove} />
                </div>
            ))}
        </div>
    )
}

// ── Global toast function ──

let _addToast: ((t: Omit<ToastData, 'id'>) => void) | null = null

export function registerToastFn(fn: (t: Omit<ToastData, 'id'>) => void) { _addToast = fn }

/**
 * Show a toast notification.
 * Deduplicates: won't show the same title+type within 2 seconds.
 */
const _recentToasts = new Map<string, number>()

export function toast(t: Omit<ToastData, 'id'>) {
    const key = `${t.type}:${t.title}`
    const now = Date.now()
    const lastShown = _recentToasts.get(key)

    // Deduplicate — skip if same toast shown within 2 seconds
    if (lastShown && now - lastShown < 2000) return

    _recentToasts.set(key, now)
    // Cleanup old entries every 50 toasts
    if (_recentToasts.size > 50) {
        for (const [k, ts] of _recentToasts) {
            if (now - ts > 5000) _recentToasts.delete(k)
        }
    }

    _addToast?.(t)
}