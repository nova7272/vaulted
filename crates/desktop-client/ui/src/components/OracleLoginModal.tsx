import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'

interface QrLoginStartResponse {
    loginRequestId: string
    challenge: string
    oracleUrl: string
    expiresAt: string
    qrPayload: unknown
}

interface OracleLoginModalProps {
    isOpen: boolean
    onClose: () => void
    onSuccess: () => void
}

type LoginState = 'idle' | 'loading' | 'waiting' | 'success' | 'error'

export function OracleLoginModal({ isOpen, onClose, onSuccess }: OracleLoginModalProps) {
    const [state, setState] = useState<LoginState>('idle')
    const [error, setError] = useState<string | null>(null)
    const [payload, setPayload] = useState<QrLoginStartResponse | null>(null)
    const [challenge, setChallenge] = useState<string>('')

    // Reset when modal opens. Defer state writes to avoid synchronous effect updates.
    useEffect(() => {
        if (!isOpen) return
        const frame = requestAnimationFrame(() => {
            setState('idle')
            setError(null)
            setPayload(null)
            setChallenge('')
        })
        return () => cancelAnimationFrame(frame)
    }, [isOpen])

    const startLogin = async () => {
        setState('loading')
        setError(null)

        try {
            const result = await invoke<QrLoginStartResponse>('start_vaulted_qr_login')

            setChallenge(result.challenge)
            setPayload(result)
            setState('waiting')

            pollQrLogin(result.loginRequestId)
        } catch (e) {
            console.error('Failed to start Oracle login:', e)
            setError(String(e))
            setState('error')
        }
    }

    const pollQrLogin = async (loginRequestId: string) => {
        try {
            for (let i = 0; i < 120; i++) {
                const result = await invoke<{ status: string; approved: boolean }>('poll_vaulted_qr_login', { loginRequestId })
                if (result.approved || result.status === 'approved' || result.status === 'consumed') {
                    setState('success')
                    setTimeout(() => {
                        onSuccess()
                        onClose()
                    }, 1000)
                    return
                }
                if (result.status === 'rejected' || result.status === 'expired') {
                    setError(`Login ${result.status}`)
                    setState('error')
                    return
                }
                await new Promise(resolve => setTimeout(resolve, 1500))
            }
            setError('QR login timed out')
            setState('error')
        } catch (e) {
            console.error('Vaulted QR login polling failed:', e)
            setError(String(e))
            setState('error')
        }
    }


    if (!isOpen) return null

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content oracle-login-modal" onClick={e => e.stopPropagation()}>
                <button className="modal-close" onClick={onClose}>
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
                    <h2>Oracle Authentication</h2>
                    <p className="modal-subtitle">Approve with a trusted Vaulted device</p>
                </div>

                <div className="modal-body">
                    {state === 'idle' && (
                        <div className="login-idle">
                            <p>Authentication is required to perform secure operations like uploading files and managing transfers.</p>
                            <button className="btn-primary" onClick={startLogin}>
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M15 12H3" />
                                </svg>
                                Start Authentication
                            </button>
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
                            <p>Scan or copy this Vaulted QR login payload with a trusted device.</p>
                            <textarea
                                readOnly
                                value={JSON.stringify(payload.qrPayload, null, 2)}
                                style={{ width: '100%', minHeight: 140, borderRadius: 10, padding: 12, fontFamily: 'ui-monospace, monospace', fontSize: 12, background: '#0f1219', color: '#f2f3f7', border: '1px solid #262c3a' }}
                            />
                            <p className="challenge-text">
                                Challenge: <code>{challenge.slice(0, 30)}...</code>
                            </p>
                            <div className="waiting-indicator">
                                <div className="pulse-dot" />
                                <span>Waiting for Vaulted device approval...</span>
                            </div>
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
                            <p>Authentication successful!</p>
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
                            <button className="btn-primary" onClick={startLogin}>
                                Try Again
                            </button>
                        </div>
                    )}
                </div>
            </div>

            <style>{`
        .oracle-login-modal {
          max-width: 420px;
          background: #181c25;
          border: 1px solid #262c3a;
          border-radius: 16px;
          padding: 24px;
        }

        .modal-header {
          text-align: center;
          margin-bottom: 24px;
        }

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

        .modal-header h2 {
          margin: 0 0 8px;
          font-size: 20px;
          color: #f2f3f7;
        }

        .modal-subtitle {
          margin: 0;
          color: #868b98;
          font-size: 14px;
        }

        .modal-body {
          min-height: 200px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
        }

        .login-idle p {
          text-align: center;
          color: #868b98;
          margin-bottom: 20px;
          line-height: 1.6;
        }

        .login-loading,
        .login-success,
        .login-error {
          text-align: center;
        }

        .login-loading p,
        .login-success p,
        .login-error p {
          color: #868b98;
          margin-top: 16px;
        }

        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #262c3a;
          border-top-color: #6aa0ff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .qr-container {
          background: #181c25;
          padding: 16px;
          border-radius: 12px;
          margin-bottom: 16px;
        }

        .qr-container img {
          width: 200px;
          height: 200px;
          display: block;
        }

        .login-waiting p {
          color: #868b98;
          margin: 8px 0;
        }

        .challenge-text {
          font-size: 12px;
        }

        .challenge-text code {
          background: #0b0d12;
          padding: 2px 6px;
          border-radius: 4px;
          font-family: monospace;
        }

        .waiting-indicator {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 16px;
          color: #868b98;
          font-size: 14px;
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
          50% { opacity: 0.5; transform: scale(1.2); }
        }

        .success-icon,
        .error-icon {
          margin-bottom: 8px;
        }

        .error-text {
          font-size: 13px;
          color: #e07a6a !important;
          margin-bottom: 16px !important;
        }

        .btn-primary,
        .btn-secondary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .btn-primary {
          background: #6aa0ff;
          color: #f2f3f7;
          border: none;
        }

        .btn-primary:hover {
          background: #3b6fe0;
        }

        .btn-secondary {
          background: transparent;
          color: #868b98;
          border: 1px solid #262c3a;
          margin-top: 12px;
        }

        .btn-secondary:hover {
          background: #323232;
          border-color: #5a5f6c;
        }

        .modal-close {
          position: absolute;
          top: 16px;
          right: 16px;
          background: none;
          border: none;
          color: #5a5f6c;
          cursor: pointer;
          padding: 4px;
          border-radius: 4px;
        }

        .modal-close:hover {
          color: #868b98;
          background: #323232;
        }
      `}</style>
        </div>
    )
}