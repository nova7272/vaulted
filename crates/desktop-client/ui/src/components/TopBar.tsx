interface UserInfo { walletAddress:string; publicKey:string; hasPreKeys:boolean; expiresAt:string }
interface TopBarProps {
  currentScreen: string
  onNavigate: (s:'files'|'upload'|'settings'|'history'|'secure-notes') => void
  user: UserInfo|null
  onLogout: () => void
  searchQuery?: string
  onSearchChange?: (q: string) => void
}

const IcoFiles = () => (<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M12 8v8m-4-4h8"/></svg>)
const IcoUpload = () => (<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 16V4m0 0l-4 4m4-4l4 4M3 20h18"/></svg>)
const IcoSecure = () => (<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/></svg>)
const IcoHistory = () => (<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></svg>)
const IcoSettings = () => (<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4m0 14v4m-9-9h4m14 0h-4m-2.5-6.5l2.8-2.8m-12.6 12.6l2.8-2.8m0-9.6l-2.8-2.8m12.6 12.6l-2.8-2.8"/></svg>)
const IcoLogout = () => (<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>)
const IcoSearch = () => (<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>)

export default function TopBar({ currentScreen, onNavigate, user, onLogout, searchQuery, onSearchChange }: TopBarProps) {
  const nav = [
    { id:'files' as const, label:'Files', Icon:IcoFiles },
    { id:'upload' as const, label:'Upload', Icon:IcoUpload },
    { id:'secure-notes' as const, label:'Secure Notes', Icon:IcoSecure },
    { id:'history' as const, label:'History', Icon:IcoHistory },
    { id:'settings' as const, label:'Settings', Icon:IcoSettings },
  ]
  const shortAddr = user?.walletAddress ? `${user.walletAddress.slice(0,4)}...${user.walletAddress.slice(-4)}` : '----'

  return (
      <div className="topbar-container">
        <header className="topbar">
          <div className="topbar-logo">
            <span className="logo-bracket">[</span>
            <span className="logo-v">v</span>
            <span className="logo-bracket">]</span>
            <span className="logo-text">aulted</span>
          </div>
          <nav className="topbar-nav">
            {nav.map(({ id, label, Icon }) => (
                <button key={id} onClick={() => onNavigate(id)} className={`topbar-btn${currentScreen === id ? ' active' : ''}`}>
                  <Icon /><span>{label}</span>
                </button>
            ))}
          </nav>
          <div className="topbar-user">
            <div className="wallet-badge"><div className="wallet-dot" /><span className="wallet-addr">{shortAddr}</span></div>
            <button className="logout-btn" onClick={onLogout} title="Sign out"><IcoLogout /></button>
          </div>
        </header>
        {onSearchChange && (
            <div className="search-bar">
              <div className="search-wrapper">
                <IcoSearch />
                <input
                    type="text"
                    placeholder="Search files..."
                    value={searchQuery || ''}
                    onChange={e => onSearchChange(e.target.value)}
                    className="search-input"
                />
              </div>
            </div>
        )}
      </div>
  )
}