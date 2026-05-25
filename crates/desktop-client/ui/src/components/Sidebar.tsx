interface UserInfo { walletAddress:string; publicKey:string; hasPreKeys:boolean; expiresAt:string }
interface SidebarProps {
    currentScreen: string
    onNavigate: (s:'files'|'upload'|'wallet'|'secure-notes'|'settings'|'activity') => void
    user: UserInfo|null
    onLogout: () => void
}

// NFT Folder icon with lock badge
const IcoVault = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>
        <text x="12" y="15.5" textAnchor="middle" fontFamily="ui-monospace, monospace" fontSize="5.2" fontWeight="700" fill="currentColor" stroke="none">NFT</text>
        <circle cx="19.5" cy="5.5" r="2.6" fill="#0a0c11" stroke="currentColor" strokeWidth="1"/>
        <rect x="18.3" y="5.2" width="2.4" height="1.8" rx="0.3" fill="currentColor" stroke="none"/>
        <path d="M18.7 5.2v-0.6a0.8 0.8 0 0 1 1.6 0v0.6" stroke="currentColor" strokeWidth="0.7" fill="none"/>
    </svg>
)

// NFT Document icon with lock badge
const IcoSecureNotes = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/>
        <path d="M14 3v5h5"/>
        <text x="10.5" y="14.5" textAnchor="middle" fontFamily="ui-monospace, monospace" fontSize="5" fontWeight="700" fill="currentColor" stroke="none">NFT</text>
        <circle cx="18.5" cy="18.5" r="2.6" fill="#0a0c11" stroke="currentColor" strokeWidth="1"/>
        <rect x="17.3" y="18.2" width="2.4" height="1.8" rx="0.3" fill="currentColor" stroke="none"/>
        <path d="M17.7 18.2v-0.6a0.8 0.8 0 0 1 1.6 0v0.6" stroke="currentColor" strokeWidth="0.7" fill="none"/>
    </svg>
)

const IcoUpload = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
)

const IcoActivity = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="3 12 7 12 10 4 14 20 17 12 21 12"/>
    </svg>
)

const IcoWallet = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H19a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5.5A2.5 2.5 0 0 1 3 16.5v-9z"/>
        <path d="M17 12h4"/>
        <circle cx="16.5" cy="12" r="1"/>
    </svg>
)

const IcoSettings = () => (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
)

export default function Sidebar({ currentScreen, onNavigate }: SidebarProps) {
    const nav = [
        { id:'files'        as const, label:'Vault',          Icon:IcoVault },
        { id:'upload'       as const, label:'Upload',         Icon:IcoUpload },
        { id:'secure-notes' as const, label:'Secure Notes',   Icon:IcoSecureNotes },
        { id:'wallet'       as const, label:'Wallet',         Icon:IcoWallet },
        { id:'activity'     as const, label:'Activity',       Icon:IcoActivity },
        { id:'settings'     as const, label:'Settings',       Icon:IcoSettings },
    ]

    return (
        <aside className="sidebar">
            <div className="sidebar-logo">
                <span className="logo-bracket">[</span>
                <span className="logo-v">v</span>
                <span className="logo-bracket">]</span>
            </div>
            <nav className="sidebar-nav">
                {nav.map(({ id, label, Icon }) => (
                    <button key={id} onClick={() => onNavigate(id)}
                            className={`nav-btn${currentScreen === id ? ' active' : ''}`}>
                        <Icon />
                        <span className="tooltip">{label}</span>
                    </button>
                ))}
            </nav>
        </aside>
    )
}
