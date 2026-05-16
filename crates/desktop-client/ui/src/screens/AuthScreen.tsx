import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import FingerprintBg from '../components/FingerprintBg'

interface UserInfo {
    walletAddress: string
    publicKey: string
    hasPreKeys: boolean
    hasVaultedWallet?: boolean
    vaultedIdentityId?: string | null
    encryptionPublicKey?: string | null
    signingPublicKey?: string | null
    expiresAt: string
}
interface AuthScreenProps { onLogin: (u: UserInfo) => void }
interface VaultedIdentityResponse {
    vaultedIdentityId: string
    mnemonic?: string | null
    signingPublicKey: string
    encryptionPublicKey: string
    devicePublicKey: string
    protocolVersion: string
}

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
    const [step, setStep] = useState<'initial'|'backup'|'restore'>('initial')
    const [error, setError] = useState<string|null>(null)
    const [status, setStatus] = useState('')
    const [createdIdentity, setCreatedIdentity] = useState<VaultedIdentityResponse|null>(null)
    const [restorePhrase, setRestorePhrase] = useState('')
    const [advancedSeed, setAdvancedSeed] = useState(false)

    const createVaultedWallet = async () => {
        try {
            setError(null)
            setStatus('Generating Vaulted seed phrase…')
            const wordCount = advancedSeed ? 24 : 12
            const identity = await invoke<VaultedIdentityResponse>('create_vaulted_wallet', { wordCount, passphrase: null })
            setCreatedIdentity(identity)
            setStep('backup')
            setStatus(`Write down your ${wordCount}-word Vaulted seed phrase. It is the only recovery key.`)
        } catch(e) { setError(String(e)); setStep('initial') }
    }

    const restoreVaultedWallet = async () => {
        try {
            setError(null)
            setStatus('Restoring Vaulted identity from seed…')
            await invoke<VaultedIdentityResponse>('restore_vaulted_wallet', { mnemonic: restorePhrase.trim(), passphrase: null })
            setStatus('Vaulted wallet restored.')
            onLogin(await invoke<UserInfo>('get_current_user'))
        } catch(e) { setError(String(e)) }
    }

    return (
        <div className="v-login">
            <FingerprintBg opacity={0.8} seed="vaulted" />

            <div className="v-login-logo">[<span className="br">v</span>]aulted</div>

            <div className="v-login-features">
                <div><IcoShield /> Seed identity</div>
                <div><IcoCube /> NFT anchor</div>
                <div><IcoTransfer /> Grants</div>
            </div>

            {step === 'initial' && (
                <div className="v-login-card">
                    <h3>Create or restore your Vaulted wallet</h3>
                    <button className="v-btn-vaulted" onClick={createVaultedWallet}>Create new Vaulted wallet</button>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#6a6f7d', marginTop: 12, cursor: 'pointer' }}>
                        <input type="checkbox" checked={advancedSeed} onChange={e => setAdvancedSeed(e.target.checked)} />
                        Advanced security: generate a 24-word seed instead of the standard 12-word seed
                    </label>
                    <button className="v-btn-vaulted" onClick={() => setStep('restore')} style={{ marginTop: 10, background: '#fff', color: '#1a1d26', border: '1px solid #d7dbe7' }}>
                        Restore from seed phrase
                    </button>
                    <div style={{ fontSize: 13, color: '#6a6f7d', marginTop: 14 }}>
                        Standard Vaulted setup uses a 12-word seed phrase. Vaulted cannot recover encrypted files without this seed.
                    </div>
                    {error && <div style={{ fontSize: 12, color: '#e07a6a', marginTop: 12, padding: '8px 12px', background: 'rgba(224,122,106,0.1)', borderRadius: 8 }}>{error}</div>}
                </div>
            )}

            {step === 'backup' && createdIdentity && (
                <div className="v-login-card" style={{ width: 560 }}>
                    <h3>Back up your Vaulted seed phrase</h3>
                    <div style={{ fontSize: 13, color: '#6a6f7d', marginBottom: 12 }}>
                        Vaulted cannot recover encrypted files without this seed. Do not paste it into chat, logs, analytics, or screenshots.
                    </div>
                    <div
                        style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(3, 1fr)',
                            gap: 8,
                            textAlign: 'left',
                            fontFamily: 'ui-monospace, monospace',
                            fontSize: 13,
                            padding: 14,
                            background: '#f6f7fb',
                            color: '#111827',
                            border: '1px solid #d7dbe7',
                            borderRadius: 12
                        }}
                    >
                        {(createdIdentity.mnemonic || '').split(' ').filter(Boolean).map((w, i) => (
                            <div
                                key={i}
                                style={{
                                    color: '#111827',
                                    background: '#ffffff',
                                    border: '1px solid #e5e7eb',
                                    borderRadius: 8,
                                    padding: '8px 10px'
                                }}
                            >
                                {i + 1}. {w}
                            </div>
                        ))}
                    </div>
                    <div style={{ fontSize: 12, color: '#6a6f7d', marginTop: 12 }}>Identity: {createdIdentity.vaultedIdentityId.slice(0, 16)}…</div>
                    <button className="v-btn-vaulted" onClick={async () => onLogin(await invoke<UserInfo>('get_current_user'))} style={{ marginTop: 16 }}>I saved my seed phrase</button>
                </div>
            )}

            {step === 'restore' && (
                <div className="v-login-card" style={{ width: 520 }}>
                    <h3>Restore Vaulted wallet</h3>
                    <textarea
                        value={restorePhrase}
                        onChange={e => setRestorePhrase(e.target.value)}
                        placeholder="Enter your 12 or 24 word Vaulted seed phrase"
                        style={{ width: '100%', minHeight: 110, borderRadius: 12, border: '1px solid #d7dbe7', padding: 12, resize: 'vertical' }}
                    />
                    <button className="v-btn-vaulted" onClick={restoreVaultedWallet} style={{ marginTop: 12 }}>Restore</button>
                    <button onClick={() => setStep('initial')} style={{ marginTop: 10, padding: '10px 22px', borderRadius: 10, border: '1px solid #ddd', background: '#fff', color: '#6a6f7d', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>Cancel</button>
                    {status && <div style={{ color: '#3b6fe0', fontSize: 13, marginTop: 10 }}>{status}</div>}
                    {error && <div style={{ fontSize: 13, color: '#e07a6a', marginTop: 14, padding: '10px 14px', background: 'rgba(224,122,106,0.1)', borderRadius: 10 }}>{error}</div>}
                </div>
            )}

        </div>
    )
}
