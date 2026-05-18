import { useMemo, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import FingerprintBg from '../components/FingerprintBg'
import { formatError } from '../utils/formatError'

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

type AuthStep = 'initial'|'backup'|'restore'

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
    const [step, setStep] = useState<AuthStep>('initial')
    const [error, setError] = useState<string|null>(null)
    const [status, setStatus] = useState('')
    const [createdIdentity, setCreatedIdentity] = useState<VaultedIdentityResponse|null>(null)
    const [restorePhrase, setRestorePhrase] = useState('')
    const [advancedSeed, setAdvancedSeed] = useState(false)
    const [seedSaved, setSeedSaved] = useState(false)
    const [copyArmed, setCopyArmed] = useState(false)
    const [copied, setCopied] = useState(false)

    const seedWords = useMemo(() => (createdIdentity?.mnemonic || '').split(' ').filter(Boolean), [createdIdentity])

    const finishLogin = async () => onLogin(await invoke<UserInfo>('get_current_user'))

    const createVaultedWallet = async () => {
        try {
            setError(null)
            setStatus('Generating your Vaulted seed phrase…')
            setSeedSaved(false)
            setCopied(false)
            setCopyArmed(false)
            const wordCount = advancedSeed ? 24 : 12
            const identity = await invoke<VaultedIdentityResponse>('create_vaulted_wallet', { wordCount, passphrase: null })
            setCreatedIdentity(identity)
            setStep('backup')
            setStatus(`Write down your ${wordCount}-word recovery phrase. You will only see it once.`)
        } catch(e) {
            setError(formatError(e))
            setStep('initial')
        }
    }

    const restoreVaultedWallet = async () => {
        try {
            setError(null)
            setStatus('Restoring your Vaulted wallet…')
            await invoke<VaultedIdentityResponse>('restore_vaulted_wallet', { mnemonic: restorePhrase.trim(), passphrase: null })
            setStatus('Vaulted wallet restored.')
            await finishLogin()
        } catch(e) { setError(formatError(e)) }
    }

    const copySeedPhrase = async () => {
        if (!createdIdentity?.mnemonic) return
        if (!copyArmed) {
            setCopyArmed(true)
            setStatus('Only copy this phrase in a private place. Clipboard history may be stored by your system.')
            return
        }
        await navigator.clipboard.writeText(createdIdentity.mnemonic)
        setCopied(true)
        setStatus('Seed phrase copied. Paste it only into your offline backup, then clear the clipboard.')
        setTimeout(() => setCopied(false), 2000)
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
                <div className="v-login-card v-auth-card-wide">
                    <h3>Start with your Vaulted wallet</h3>
                    <p className="v-auth-sub">One wallet unlocks encryption, Oracle access, and XRPL vault ownership.</p>

                    <div className="v-auth-choice-grid">
                        <button className="v-auth-choice primary" onClick={createVaultedWallet}>
                            <span className="v-auth-choice-title">Create wallet</span>
                            <span className="v-auth-choice-sub">Generate a new seed phrase and back it up offline.</span>
                        </button>
                        <button className="v-auth-choice" onClick={() => setStep('restore')}>
                            <span className="v-auth-choice-title">Restore wallet</span>
                            <span className="v-auth-choice-sub">Unlock Vaulted with your existing 12 or 24 word phrase.</span>
                        </button>
                    </div>

                    <details className="v-advanced-toggle">
                        <summary>Advanced</summary>
                        <label>
                            <input type="checkbox" checked={advancedSeed} onChange={e => setAdvancedSeed(e.target.checked)} />
                            Generate a 24-word seed phrase instead of the standard 12-word phrase
                        </label>
                    </details>
                    {status && <div className="v-auth-status">{status}</div>}
                    {error && <div className="v-auth-error">{error}</div>}
                </div>
            )}

            {step === 'backup' && createdIdentity && (
                <div className="v-login-card v-auth-backup-card">
                    <h3>Back up your seed phrase</h3>
                    <p className="v-auth-sub">Write these words on paper and store them offline. Vaulted cannot recover encrypted files without them.</p>

                    <div className="v-seed-grid" aria-label="Vaulted seed phrase">
                        {seedWords.map((w, i) => (
                            <div className="v-seed-word" key={i}><span>{i + 1}</span>{w}</div>
                        ))}
                    </div>

                    <div className="v-seed-actions">
                        <button className="v-btn" onClick={copySeedPhrase}>{copied ? 'Copied' : copyArmed ? 'Copy anyway' : 'Copy seed phrase'}</button>
                        <div className="v-seed-warning">Never share this phrase. It will not be shown again after onboarding.</div>
                    </div>

                    <label className="v-backup-confirm">
                        <input type="checkbox" checked={seedSaved} onChange={e => setSeedSaved(e.target.checked)} />
                        I saved this seed phrase offline
                    </label>

                    <button className="v-btn-vaulted" disabled={!seedSaved} onClick={finishLogin}>Continue to Vaulted</button>
                    <div className="v-auth-identity">Identity {createdIdentity.vaultedIdentityId.slice(0, 16)}…</div>
                    {status && <div className="v-auth-status">{status}</div>}
                </div>
            )}

            {step === 'restore' && (
                <div className="v-login-card v-auth-card-wide">
                    <h3>Restore Vaulted wallet</h3>
                    <p className="v-auth-sub">Enter your recovery phrase locally. It is used to unlock your Vaulted identity and XRPL wallet.</p>
                    <textarea
                        className="v-restore-textarea"
                        value={restorePhrase}
                        onChange={e => setRestorePhrase(e.target.value)}
                        placeholder="Enter your 12 or 24 word Vaulted seed phrase"
                    />
                    <button className="v-btn-vaulted" onClick={restoreVaultedWallet} disabled={restorePhrase.trim().split(/\s+/).filter(Boolean).length < 12}>Restore wallet</button>
                    <button className="v-auth-link-button" onClick={() => { setStep('initial'); setError(null); setStatus('') }}>Back</button>
                    {status && <div className="v-auth-status">{status}</div>}
                    {error && <div className="v-auth-error">{error}</div>}
                </div>
            )}
        </div>
    )
}
