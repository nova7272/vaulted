import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { QrCode } from './QrCode'
import { formatError } from '../utils/formatError'

interface QrLoginStartResponse {
    loginRequestId: string
    challenge: string
    oracleUrl: string
    expiresAt: string
    qrPayload: unknown
}

export interface QrLoginPollResponse {
    status: string
    approved: boolean
    oracleSession?: boolean
    identityId?: string | null
    localVaultedWallet?: boolean
    localDecryptAvailable?: boolean
}

interface OracleLoginModalProps {
    isOpen: boolean
    onClose: () => void
    onSuccess: (result: QrLoginPollResponse) => void
    startOnOpen?: boolean
}

type LoginState = 'idle' | 'loading' | 'waiting' | 'success' | 'error'

const secondsRemaining = (iso: string) =>
    Math.max(0, Math.ceil((new Date(iso).getTime() - Date.now()) / 1000))

const qrLoginCommand = 'start_vaulted_qr_login'
const qrPollCommand = 'poll_vaulted_qr_login'

const classifyQrError = (error: unknown) => {
    const message = String(error)
    const lower = message.toLowerCase()
    if (lower.includes('command') || lower.includes('invoke') || lower.includes('not found')) {
        return {
            errorClass: 'tauri_invoke_error',
            display: 'QR login command did not reach the desktop backend. Restart the desktop app and try again.',
        }
    }
    if (lower.includes('timeout') || lower.includes('timed out')) {
        return {
            errorClass: 'timeout',
            display: 'QR login request timed out. Confirm Oracle is running and try again.',
        }
    }
    if (lower.includes('oracle api error') || lower.includes('http') || lower.includes('error sending request') || lower.includes('localhost:3000')) {
        return {
            errorClass: 'oracle_request_error',
            display: 'Desktop reached the QR login command, but Oracle could not be reached. Confirm the Oracle service URL and try again.',
        }
    }
    if (lower.includes('expired')) {
        return {
            errorClass: 'expired',
            display: 'QR login expired. Create a new QR request and try again.',
        }
    }
    if (lower.includes('consumed') || lower.includes('replay')) {
        return {
            errorClass: 'replay_or_consumed',
            display: 'QR login request was already used. Create a new QR request and try again.',
        }
    }
    return {
        errorClass: 'unknown',
        display: `${formatError(error)} Check desktop logs for the safe QR command boundary status.`,
    }
}

const qrDebug = (details: Record<string, string | boolean | number | null | undefined>) => {
    console.debug('[qr-login]', details)
}

const qrWarn = (details: Record<string, string | boolean | number | null | undefined>) => {
    console.warn('[qr-login]', details)
}

export function OracleLoginModal({ isOpen, onClose, onSuccess, startOnOpen = false }: OracleLoginModalProps) {
    const [state, setState] = useState<LoginState>('idle')
    const [error, setError] = useState<string | null>(null)
    const [payload, setPayload] = useState<QrLoginStartResponse | null>(null)
    const [copied, setCopied] = useState(false)
    const [remaining, setRemaining] = useState(0)
    const [approvedResult, setApprovedResult] = useState<QrLoginPollResponse | null>(null)
    const pollToken = useRef(0)
    const onCloseRef = useRef(onClose)
    const onSuccessRef = useRef(onSuccess)

    const qrValue = useMemo(
        () => (payload ? JSON.stringify(payload.qrPayload) : ''),
        [payload],
    )

    useEffect(() => {
        onCloseRef.current = onClose
        onSuccessRef.current = onSuccess
    }, [onClose, onSuccess])

    const pollQrLogin = useCallback(async (loginRequestId: string, token: number) => {
        try {
            for (let i = 0; i < 120; i++) {
                if (pollToken.current !== token) return
                qrDebug({
                    ui_step: 'poll_begin',
                    command: qrPollCommand,
                    qr_request_id: loginRequestId,
                })
                const result = await invoke<QrLoginPollResponse>('poll_vaulted_qr_login', { loginRequestId })
                if (pollToken.current !== token) return
                qrDebug({
                    ui_step: 'poll_result',
                    command: qrPollCommand,
                    qr_request_id: loginRequestId,
                    status: result.status,
                    approved: result.approved,
                })
                if (result.approved || result.status === 'approved' || result.status === 'consumed') {
                    setApprovedResult(result)
                    setState('success')
                    onSuccessRef.current(result)
                    if (result.localDecryptAvailable || result.localVaultedWallet) {
                        window.setTimeout(() => onCloseRef.current(), 800)
                    }
                    return
                }
                if (result.status === 'rejected' || result.status === 'expired') {
                    setError(`Login ${result.status}. Create a new QR request and try again.`)
                    setState('error')
                    return
                }
                await new Promise(resolve => window.setTimeout(resolve, 1500))
            }
            setError('QR login timed out. Create a new QR request and try again.')
            setState('error')
        } catch (e) {
            const classified = classifyQrError(e)
            qrWarn({
                ui_step: 'poll_error',
                command: qrPollCommand,
                qr_request_id: loginRequestId,
                error_class: classified.errorClass,
            })
            setError(classified.display)
            setState('error')
        }
    }, [])

    const startLogin = useCallback(async () => {
        qrDebug({ ui_step: 'start_clicked', command: qrLoginCommand })
        const token = pollToken.current + 1
        pollToken.current = token
        setState('loading')
        setError(null)
        setPayload(null)
        setCopied(false)
        setApprovedResult(null)

        try {
            qrDebug({ ui_step: 'invoke_start_begin', command: qrLoginCommand })
            const result = await invoke<QrLoginStartResponse>('start_vaulted_qr_login')
            qrDebug({
                ui_step: 'invoke_start_ok',
                command: qrLoginCommand,
                qr_request_id: result.loginRequestId,
            })
            setPayload(result)
            setRemaining(secondsRemaining(result.expiresAt))
            setState('waiting')
            void pollQrLogin(result.loginRequestId, token)
        } catch (e) {
            const classified = classifyQrError(e)
            qrWarn({
                ui_step: 'invoke_start_error',
                command: qrLoginCommand,
                error_class: classified.errorClass,
            })
            setError(classified.display)
            setState('error')
        }
    }, [pollQrLogin])

    useEffect(() => {
        if (!isOpen) return
        pollToken.current += 1
        const frame = requestAnimationFrame(() => {
            setState('idle')
            setError(null)
            setPayload(null)
            setCopied(false)
            setRemaining(0)
            setApprovedResult(null)
            if (startOnOpen) {
                qrDebug({ ui_step: 'modal_open_autostart', command: qrLoginCommand })
                void startLogin()
            }
        })
        return () => {
            pollToken.current += 1
            cancelAnimationFrame(frame)
        }
    }, [isOpen, startOnOpen, startLogin])

    useEffect(() => {
        if (!payload) return
        const update = () => setRemaining(secondsRemaining(payload.expiresAt))
        update()
        const id = window.setInterval(update, 1000)
        return () => window.clearInterval(id)
    }, [payload])

    const copyPayload = async () => {
        if (!qrValue) return
        await navigator.clipboard.writeText(qrValue)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 2000)
    }

    const cancel = () => {
        pollToken.current += 1
        onClose()
    }

    if (!isOpen) return null

    const timerText = payload
        ? remaining > 0
            ? `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}`
            : 'Expired'
        : ''

    return (
        <div className="modal-overlay" onClick={cancel}>
            <div className="modal-content oracle-login-modal" onClick={e => e.stopPropagation()}>
                <button className="modal-close" onClick={cancel} aria-label="Close QR login">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                </button>

                <div className="modal-header">
                    <div className="modal-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#6aa0ff" strokeWidth="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                            <path d="M7 11V7a5 5 0 0110 0v4" />
                        </svg>
                    </div>
                    <h2>Vaulted QR Login</h2>
                    <p className="modal-subtitle">Approve with an unlocked trusted Vaulted session</p>
                </div>

                <div className="modal-body">
                    {state === 'idle' && (
                        <div className="login-idle">
                            <p>Start a one-time Oracle login request, then approve it from an already-unlocked Vaulted session.</p>
                            <button className="btn-primary" onClick={startLogin}>Sign in with QR code</button>
                        </div>
                    )}

                    {state === 'loading' && (
                        <div className="login-loading">
                            <div className="spinner" />
                            <p>Preparing Vaulted QR login...</p>
                        </div>
                    )}

                    {state === 'waiting' && payload && (
                        <div className="login-waiting">
                            <QrCode value={qrValue} label="Vaulted QR login" size={220} />
                            <div className="qr-login-meta">
                                <span>{timerText}</span>
                                <code>{payload.loginRequestId.slice(0, 8)}...</code>
                            </div>
                            <div className="waiting-indicator">
                                <div className="pulse-dot" />
                                <span>Waiting for trusted-device approval...</span>
                            </div>
                            <div className="qr-login-actions">
                                <button className="btn-secondary" onClick={copyPayload}>
                                    {copied ? 'Copied' : 'Copy payload'}
                                </button>
                                <button className="btn-secondary" onClick={startLogin}>Retry</button>
                                <button className="btn-secondary" onClick={cancel}>Cancel</button>
                            </div>
                            <details className="qr-login-fallback">
                                <summary>Payload fallback</summary>
                                <textarea readOnly value={JSON.stringify(payload.qrPayload, null, 2)} />
                            </details>
                        </div>
                    )}

                    {state === 'success' && (
                        <div className="login-success">
                            <div className="success-icon">
                                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#6ac79a" strokeWidth="2">
                                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                                    <polyline points="22 4 12 14.01 9 11.01" />
                                </svg>
                            </div>
                            <p>{approvedResult?.localDecryptAvailable ? 'Vaulted session unlocked.' : 'Oracle session approved.'}</p>
                            {!approvedResult?.localDecryptAvailable && (
                                <p className="safe-note">Local file decrypt still requires restoring the 12-word phrase on this device.</p>
                            )}
                            <button className="btn-secondary" onClick={cancel}>Close</button>
                        </div>
                    )}

                    {state === 'error' && (
                        <div className="login-error">
                            <div className="error-icon">
                                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#e07a6a" strokeWidth="2">
                                    <circle cx="12" cy="12" r="10" />
                                    <path d="M15 9l-6 6M9 9l6 6" />
                                </svg>
                            </div>
                            <p>Authentication failed</p>
                            <p className="error-text">{error}</p>
                            <div className="qr-login-actions">
                                <button className="btn-primary" onClick={startLogin}>Try again</button>
                                <button className="btn-secondary" onClick={cancel}>Cancel</button>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            <style>{`
        .oracle-login-modal {
          max-width: 460px;
          background: #181c25;
          border: 1px solid #262c3a;
          border-radius: 16px;
          padding: 24px;
        }
        .modal-header { text-align: center; margin-bottom: 24px; }
        .modal-icon {
          width: 64px;
          height: 64px;
          background: rgba(59, 130, 246, 0.1);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 16px;
        }
        .modal-header h2 { margin: 0 0 8px; font-size: 20px; color: #f2f3f7; }
        .modal-subtitle { margin: 0; color: #868b98; font-size: 14px; }
        .modal-body {
          min-height: 220px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
        }
        .login-idle,
        .login-loading,
        .login-success,
        .login-error,
        .login-waiting { width: 100%; text-align: center; }
        .login-idle p,
        .login-loading p,
        .login-success p,
        .login-error p {
          color: #868b98;
          margin: 0 0 16px;
          line-height: 1.6;
        }
        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #262c3a;
          border-top-color: #6aa0ff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 0 auto;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .qr-login-meta {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 10px;
          margin: 12px 0;
          color: #868b98;
          font-size: 12px;
        }
        .qr-login-meta span {
          color: #e6b35a;
          font-weight: 700;
          font-variant-numeric: tabular-nums;
        }
        .qr-login-meta code {
          color: #f2f3f7;
          font-family: var(--font-mono);
          font-size: 12px;
        }
        .waiting-indicator {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          color: #868b98;
          font-size: 13px;
          margin: 12px 0;
        }
        .pulse-dot {
          width: 8px;
          height: 8px;
          background: #6aa0ff;
          border-radius: 50%;
          animation: pulse 1.5s ease-in-out infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.25); }
        }
        .qr-login-actions {
          display: flex;
          justify-content: center;
          gap: 8px;
          flex-wrap: wrap;
          margin-top: 14px;
        }
        .qr-login-fallback {
          margin-top: 14px;
          text-align: left;
          color: #868b98;
          font-size: 12px;
        }
        .qr-login-fallback textarea {
          width: 100%;
          min-height: 120px;
          border-radius: 10px;
          padding: 12px;
          margin-top: 8px;
          font-family: var(--font-mono);
          font-size: 12px;
          background: #0f1219;
          color: #f2f3f7;
          border: 1px solid #262c3a;
          resize: vertical;
        }
        .safe-note,
        .error-text {
          color: #e6b35a !important;
          font-size: 13px;
          line-height: 1.5;
        }
        .error-text { color: #e07a6a !important; }
      `}</style>
        </div>
    )
}
