import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import FingerprintBg from '../components/FingerprintBg'

interface UserInfo { walletAddress: string; publicKey: string; hasPreKeys: boolean; expiresAt: string }
interface AuthScreenProps { onLogin: (u: UserInfo) => void }
interface XamanPayload { uuid: string; qrPng: string; qrUri: string; websocketUrl: string; expiresAt: string | null }

const IcoShield = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
)
const IcoCube = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
    </svg>
)
const IcoTransfer = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/>
        <polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
    </svg>
)

export default function AuthScreen({ onLogin }: AuthScreenProps) {
    const [step, setStep] = useState<'initial'|'scanning'|'deriving'>('initial')
    const [qrCode, setQrCode] = useState<string|null>(null)
    const [error, setError] = useState<string|null>(null)
    const [status, setStatus] = useState('')

    const startAuth = async () => {
        try {
            setError(null); setStatus('Creating sign request...')
            const p = await invoke<XamanPayload>('start_xaman_auth')
            setQrCode(p.qrPng); setStep('scanning'); setStatus('Scan QR code with Xaman')
            await invoke('wait_for_auth', { payloadUuid: p.uuid, websocketUrl: p.websocketUrl })
            setStatus('Checking encryption keys...')
            const hasKeys = await invoke<boolean>('has_pre_keys')
            if (!hasKeys) await deriveKeys()
            onLogin(await invoke<UserInfo>('get_current_user'))
        } catch(e) { setError(String(e)); setStep('initial') }
    }

    const deriveKeys = async () => {
        setStep('deriving'); setStatus('Creating key derivation request...')
        const p = await invoke<XamanPayload>('start_key_derivation')
        setQrCode(p.qrPng); setStatus('Sign again to derive encryption keys')
        await invoke('wait_for_key_derivation', { payloadUuid: p.uuid, websocketUrl: p.websocketUrl })
    }

    return (
        <div className="v-login">
            <FingerprintBg opacity={0.8} seed="vaulted" />

            <div className="v-login-logo">[<span className="br">v</span>]aulted</div>

            <div className="v-login-features">
                <div><IcoShield /> Encrypt</div>
                <div><IcoCube /> NFT</div>
                <div><IcoTransfer /> Transfer</div>
            </div>

            {step === 'initial' ? (
                <div className="v-login-card">
                    <h3>Sign in to your vault</h3>
                    <button className="v-btn-xaman" onClick={startAuth}>
                        <span style={{ fontFamily: 'ui-monospace, monospace', fontWeight: 700, fontSize: 18, letterSpacing: '-0.02em' }}>X</span>
                        Connect with Xaman
                    </button>
                    <div style={{ fontSize: 14, color: '#6a6f7d', marginTop: 14 }}>No account, no password. Your wallet is your key.</div>
                    {error && <div style={{ fontSize: 12, color: '#e07a6a', marginTop: 12, padding: '8px 12px', background: 'rgba(224,122,106,0.1)', borderRadius: 8 }}>{error}</div>}
                </div>
            ) : (
                <div className="v-login-card" style={{ width: 440 }}>
                    {qrCode && (
                        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 18 }}>
                            <div className="v-qr-wrap">
                                <img src={qrCode} alt="QR" style={{ width: 240, height: 240, display: 'block', imageRendering: 'pixelated' as const }} />
                            </div>
                        </div>
                    )}
                    <div style={{ color: '#1a1d26', fontSize: 17, fontWeight: 600, marginBottom: 6 }}>
                        {step === 'scanning' ? 'Scan with Xaman wallet' : 'Derive encryption keys'}
                    </div>
                    <div style={{ color: '#6a6f7d', fontSize: 14, marginBottom: 14 }}>
                        {step === 'scanning'
                            ? 'Confirm the sign-in request on your device.'
                            : 'Sign again to create your encryption keys.'}
                    </div>
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#3b6fe0', fontSize: 14, fontWeight: 500 }}>
                        <div className="v-spin" style={{ borderColor: 'rgba(59,111,224,0.2)', borderTopColor: '#3b6fe0' }} />
                        {status || 'Waiting for signature…'}
                    </div>
                    {error && <div style={{ fontSize: 13, color: '#e07a6a', marginTop: 14, padding: '10px 14px', background: 'rgba(224,122,106,0.1)', borderRadius: 10 }}>{error}</div>}
                    <div style={{ marginTop: 16 }}>
                        <button onClick={() => { setStep('initial'); setQrCode(null); setError(null); setStatus('') }}
                                style={{ padding: '10px 22px', borderRadius: 10, border: '1px solid #ddd', background: '#fff', color: '#6a6f7d', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>
                            Cancel
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}