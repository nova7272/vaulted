import { useEffect, useRef, useCallback, useId, type ReactNode } from 'react'

interface ModalProps {
    /** Controls visibility */
    open: boolean
    /** Called when user requests close (Escape, backdrop click) */
    onClose?: () => void
    /** Prevent close (e.g. during async operation) */
    preventClose?: boolean
    /** Modal title — used for aria-labelledby */
    title?: string
    /** Custom width */
    width?: number
    children: ReactNode
}

/**
 * Accessible modal dialog.
 *
 * Features:
 * - role="dialog" + aria-modal
 * - aria-labelledby (auto-generated from title)
 * - Focus trap (Tab/Shift+Tab cycle within modal)
 * - Escape to close
 * - Backdrop click to close
 * - Auto-focus first focusable element
 * - Restores focus on unmount
 */
export default function Modal({ open, onClose, preventClose, title, width, children }: ModalProps) {
    const modalRef = useRef<HTMLDivElement>(null)
    const previousFocus = useRef<HTMLElement | null>(null)
    const reactId = useId()
    const titleId = `modal-title-${reactId.replace(/:/g, '')}`

    // Save + restore focus
    useEffect(() => {
        if (open) {
            previousFocus.current = document.activeElement as HTMLElement
            // Auto-focus first focusable element after render
            requestAnimationFrame(() => {
                const modal = modalRef.current
                if (!modal) return
                const focusable = modal.querySelectorAll<HTMLElement>(
                    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
                )
                if (focusable.length) focusable[0].focus()
                else modal.focus()
            })
        }
        return () => {
            if (previousFocus.current && typeof previousFocus.current.focus === 'function') {
                previousFocus.current.focus()
            }
        }
    }, [open])

    // Escape key
    useEffect(() => {
        if (!open) return
        const handleKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && !preventClose && onClose) {
                e.stopPropagation()
                onClose()
            }
        }
        document.addEventListener('keydown', handleKey)
        return () => document.removeEventListener('keydown', handleKey)
    }, [open, preventClose, onClose])

    // Focus trap
    const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        if (e.key !== 'Tab') return
        const modal = modalRef.current
        if (!modal) return
        const focusable = modal.querySelectorAll<HTMLElement>(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        )
        if (!focusable.length) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus() }
        } else {
            if (document.activeElement === last) { e.preventDefault(); first.focus() }
        }
    }, [])

    if (!open) return null

    return (
        <div
            className="v-modal-backdrop"
            onClick={() => { if (!preventClose && onClose) onClose() }}
            role="presentation"
        >
            <div
                ref={modalRef}
                className="v-modal"
                style={width ? { width } : undefined}
                onClick={e => e.stopPropagation()}
                onKeyDown={handleKeyDown}
                role="dialog"
                aria-modal="true"
                aria-labelledby={title ? titleId : undefined}
                tabIndex={-1}
            >
                {title && <h3 id={titleId}>{title}</h3>}
                {children}
            </div>
        </div>
    )
}