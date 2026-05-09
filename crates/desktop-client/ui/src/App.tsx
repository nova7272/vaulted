import { useState, useEffect, useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import Sidebar from './components/Sidebar'
import ProgressBar from './components/ProgressBar'
import FingerprintBg from './components/FingerprintBg'
import AuthScreen from './screens/AuthScreen'
import FilesScreen from './screens/FilesScreen'
import UploadScreen from './screens/UploadScreen'
import SettingsScreen from './screens/SettingsScreen'
import ActivityScreen from './screens/ActivityScreen'
import { SecureNotesScreen } from './screens/SecureNotesScreen'
import { OracleLoginModal } from './components/OracleLoginModal'
import { ActivityLogProvider } from './contexts/ActivityLogContext'
import type { ToastData } from './components/Toast'
import { ToastContainer, registerToastFn } from './components/Toast'

type Screen = 'auth'|'files'|'upload'|'settings'|'activity'|'secure-notes'
interface UserInfo { walletAddress:string; publicKey:string; hasPreKeys:boolean; expiresAt:string }

const IcoLogout = () => (
    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>
    </svg>
)
const IcoCopy = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
    </svg>
)

// Pixel avatar generated from wallet address (web3 style)
function PixelAvatar({ seed, size = 28 }: { seed: string; size?: number }) {
    const hash = (s: string) => { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h * 33) + s.charCodeAt(i)) >>> 0; return h }
    const h = hash(seed)
    const hue = h % 360
    const pixels: Array<{ x: number; y: number; c: string }> = []
    for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 3; x++) {
            const bit = (h >> (y * 3 + x)) & 1
            if (bit) {
                const c = `hsl(${hue}, 65%, ${40 + ((h >> (y + x + 8)) % 25)}%)`
                pixels.push({ x, y, c })
                if (x < 2) pixels.push({ x: 4 - x, y, c })
            }
        }
    }
    const ps = size / 5
    return (
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ borderRadius: size / 3.5, flexShrink: 0 }}>
            <rect width={size} height={size} fill={`hsl(${hue}, 25%, 14%)`} rx={size / 3.5} />
            {pixels.map((p, i) => (
                <rect key={i} x={p.x * ps} y={p.y * ps} width={ps - 0.3} height={ps - 0.3} fill={p.c} />
            ))}
        </svg>
    )
}

function App() {
    const [screen, setScreen] = useState<Screen>('auth')
    const [authed, setAuthed] = useState(false)
    const [user, setUser] = useState<UserInfo|null>(null)
    const [loading, setLoading] = useState(true)
    const [toasts, setToasts] = useState<ToastData[]>([])
    const [searchQuery, setSearchQuery] = useState('')
    const [walletCopied, setWalletCopied] = useState(false)

    // Oracle auth state
    const [oracleAuthed, setOracleAuthed] = useState(false)
    const [showOracleLogin, setShowOracleLogin] = useState(false)
    const [checkingOracleAuth, setCheckingOracleAuth] = useState(false)

    const addToast = useCallback((t: Omit<ToastData,'id'>) => {
        const id = Date.now()
        setToasts(prev => [...prev, { ...t, id }])
    }, [])

    useEffect(() => { registerToastFn(addToast) }, [addToast])
    const removeToast = useCallback((id: number) => setToasts(prev => prev.filter(t => t.id !== id)), [])

    // Check Oracle auth status
    const checkOracleAuth = useCallback(async () => {
        setCheckingOracleAuth(true)
        try {
            const status = await invoke<{
                authenticated: boolean
                walletAddress: string | null
            }>('get_oracle_auth_status')
            setOracleAuthed(status.authenticated)
        } catch (e) {
            console.error('Failed to check Oracle auth:', e)
            setOracleAuthed(false)
        } finally {
            setCheckingOracleAuth(false)
        }
    }, [])

    useEffect(()=>{ (async()=>{
        try {
            const ok = await invoke<boolean>('is_authenticated')
            if(ok){
                setUser(await invoke<UserInfo>('get_current_user'))
                setAuthed(true)
                setScreen('files')
                // Check Oracle auth after Xaman auth
                checkOracleAuth()
            }
        } catch(e){ console.error(e) } finally{ setLoading(false) }
    })() },[checkOracleAuth])

    const handleLogout = useCallback(async () => {
        try {
            await invoke('oracle_logout').catch(() => {})
            await invoke('logout')
        } catch {}
        setUser(null)
        setAuthed(false)
        setOracleAuthed(false)
        setScreen('auth')
    }, [])

    // Listen for session-expired event from Rust backend
    useEffect(() => {
        const unlisten = listen('session-expired', () => {
            addToast({ type: 'error', title: 'Session expired. Please sign in again.' })
            setTimeout(() => handleLogout(), 1500)
        })
        return () => { unlisten.then(fn => fn()) }
    }, [addToast, handleLogout])

    // Periodic Oracle status check (every 10 seconds) — just updates UI state
    useEffect(() => {
        if (!authed) return
        const interval = setInterval(async () => {
            try {
                const status = await invoke<{
                    authenticated: boolean
                    walletAddress: string | null
                }>('get_oracle_auth_status')
                setOracleAuthed(status.authenticated)
            } catch (e) {
                console.error('Failed to check Oracle auth:', e)
                setOracleAuthed(false)
            }
        }, 10000)
        return () => clearInterval(interval)
    }, [authed])

    const handleLogin = useCallback(async (u: UserInfo) => {
        setUser(u)
        setAuthed(true)
        setScreen('files')
        // Check Oracle auth status (should be authenticated from SignIn)
        setTimeout(() => {
            checkOracleAuth()
        }, 500)
    }, [checkOracleAuth])

    const handleOracleLoginSuccess = () => {
        setOracleAuthed(true)
        setShowOracleLogin(false)
        addToast({ type: 'success', title: 'Oracle authentication successful' })
    }

    if(loading) return (
        <div className="loading-screen">
            <div className="loading-logo">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="white">
                    <path fillRule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.705-3.078z" clipRule="evenodd"/>
                </svg>
            </div>
            <p className="loading-text"><span className="br">[</span>v<span className="br">]</span>aulted</p>
        </div>
    )

    if(!authed) return <AuthScreen onLogin={handleLogin}/>

    const showSearch = screen === 'files'
    const shortWallet = user?.walletAddress
        ? `${user.walletAddress.slice(0,4)}...${user.walletAddress.slice(-4)}`
        : '—'

    return (
        <ActivityLogProvider>
            <div className="app-container">
                <FingerprintBg opacity={0.5} />
                <Sidebar
                    currentScreen={screen}
                    onNavigate={s => { setScreen(s); setSearchQuery('') }}
                    user={user}
                    onLogout={handleLogout}
                />
                <div className="main-wrapper">
                    {/* TopBar — Claude Design */}
                    <header className="v-topbar">
                        <div>
                            <span className="v-topbar-title">
                                {screen === 'files' ? 'Files' : screen === 'upload' ? 'Upload' : screen === 'secure-notes' ? 'Secure Notes' : screen === 'activity' ? 'Activity' : 'Settings'}
                            </span>
                            <span className="v-topbar-crumb">
                                {screen === 'files' && `· ${searchQuery ? 'searching…' : 'encrypted items'}`}
                                {screen === 'upload' && '· encrypt & mint'}
                                {screen === 'secure-notes' && '· encrypted'}
                                {screen === 'activity' && '· last 30 days'}
                                {screen === 'settings' && '· wallet & security'}
                            </span>
                        </div>
                        <div className="v-topbar-spacer" />

                        {showSearch && (
                            <div className="v-search">
                                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                <input
                                    placeholder="Search by name or NFT ID…"
                                    value={searchQuery}
                                    onChange={e => setSearchQuery(e.target.value)}
                                />
                            </div>
                        )}

                        {!oracleAuthed && (
                            <div className="v-oracle-warn" title="Oracle server is unavailable. Some features may not work.">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                <span>Oracle unavailable</span>
                            </div>
                        )}

                        <div className="v-avatar">
                            <PixelAvatar seed={user?.walletAddress || 'default'} size={50} />
                        </div>

                        <div className="v-wallet" onClick={async () => {
                            if (user?.walletAddress) {
                                await navigator.clipboard.writeText(user.walletAddress)
                                setWalletCopied(true)
                                setTimeout(() => setWalletCopied(false), 2000)
                            }
                        }} title="Click to copy wallet address">
                            <span className="v-wallet-addr">{shortWallet}</span>
                            <div className="v-wallet-copy" style={{ color: walletCopied ? '#6ac79a' : undefined }}>
                                {walletCopied
                                    ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                    : <IcoCopy />
                                }
                            </div>
                        </div>

                        <button className="v-iconbtn" onClick={handleLogout} title="Sign out">
                            <IcoLogout />
                        </button>
                    </header>

                    <main className="main-content">
                        {screen==='files' && <FilesScreen onNavigate={setScreen} searchQuery={searchQuery} oracleConnected={oracleAuthed} />}
                        {/* UploadScreen stays mounted to preserve upload progress */}
                        <div style={{display: screen==='upload' ? 'contents' : 'none'}}>
                            <UploadScreen oracleConnected={oracleAuthed} onNavigate={setScreen} />
                        </div>
                        {screen==='secure-notes' && <SecureNotesScreen oracleConnected={oracleAuthed} />}
                        {screen==='activity' && <ActivityScreen oracleConnected={oracleAuthed} />}
                        {screen==='settings' && <SettingsScreen user={user} />}
                    </main>
                </div>

                {/* Oracle Login Modal */}
                <OracleLoginModal
                    isOpen={showOracleLogin}
                    onClose={() => setShowOracleLogin(false)}
                    onSuccess={handleOracleLoginSuccess}
                />

                <ToastContainer toasts={toasts} onRemove={removeToast} />
                <ProgressBar hideOnScreens={['upload', 'secure-notes']} currentScreen={screen} />

            </div>
        </ActivityLogProvider>
    )
}
export default App