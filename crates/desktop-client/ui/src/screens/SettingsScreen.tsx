import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'

interface UserInfo { walletAddress:string; publicKey:string; hasPreKeys:boolean; expiresAt:string }
interface Props { user:UserInfo|null }
interface OracleStatus {
  authenticated:boolean; walletAddress:string|null; expiresAt:string|null
  hasRefreshToken:boolean; role:string|null; deviceFingerprint:string; needsRefresh:boolean
}

export default function SettingsScreen({ user }: Props) {
  const [balance, setBalance] = useState<string|null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState<string|null>(null)
  const [oracleStatus, setOracleStatus] = useState<OracleStatus|null>(null)

  useEffect(() => { fetchOracle() }, [])

  const fetchBalance = async () => {
    try { setLoading(true); setBalance(await invoke<string>('get_xrp_balance')) }
    catch(e){ console.error(e) } finally{ setLoading(false) }
  }

  const fetchOracle = async () => {
    try { setOracleStatus(await invoke<OracleStatus>('get_oracle_auth_status_extended')) }
    catch(e) { console.error(e) }
  }

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text); setCopied(label); setTimeout(()=>setCopied(null), 2000)
  }

  const fmtExpiry = (iso: string|null) => {
    if (!iso) return 'N/A'
    const d = new Date(iso)
    const now = new Date()
    const diff = d.getTime() - now.getTime()
    if (diff < 0) return 'Expired'
    const mins = Math.floor(diff / 60000)
    if (mins < 60) return `${mins}m remaining`
    return `${Math.floor(mins/60)}h ${mins%60}m remaining`
  }

  const Section = ({title,children}:{title:string,children:React.ReactNode}) => (
      <div style={{ background:'var(--bg-2)', borderRadius:'var(--radius-md)', padding:'20px 22px', marginBottom:14, border:'1px solid var(--line)' }}>
        <p style={{ fontWeight:600, color:'var(--fg-0)', fontSize:14, margin:'0 0 16px', paddingBottom:12, borderBottom:'1px solid var(--line)' }}>{title}</p>
        {children}
      </div>
  )

  const Row = ({label,value,mono,onCopy}:{label:string;value:string;mono?:boolean;onCopy?:()=>void}) => (
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0' }}>
        <span style={{ color:'var(--fg-2)', fontSize:13 }}>{label}</span>
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <span style={{ color:'var(--fg-0)', fontSize:13, fontWeight:500, fontFamily: mono ? 'var(--font-mono)' : 'inherit', maxWidth:260, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{value}</span>
          {onCopy && (
              <button onClick={onCopy} style={{ background:'none', border:'none', cursor:'pointer', color: copied===label ? '#6ac79a' : '#868b98', padding:2, fontSize:12 }}>
                {copied===label ? '✓' : '⧉'}
              </button>
          )}
        </div>
      </div>
  )

  const Dot = ({ok}:{ok:boolean}) => (
      <span style={{ width:6, height:6, borderRadius:'50%', background: ok ? 'var(--ok)' : 'var(--danger)', display:'inline-block', marginRight:8, boxShadow: `0 0 0 3px ${ok ? 'rgba(106,199,154,0.15)' : 'rgba(224,122,106,0.15)'}` }}/>
  )

  return (
      <div className="fade-in" style={{ maxWidth:620, margin:'0 auto' }}>
        <div className="v-section-head" style={{marginBottom:18}}>
          <div>
            <div className="v-section-title">Settings</div>
            <div className="v-section-sub">Wallet, Oracle, and security details</div>
          </div>
        </div>

        <Section title="Wallet">
          <Row label="Address" value={user?.walletAddress || 'Not connected'} mono onCopy={user?.walletAddress ? ()=>copy(user.walletAddress,'Address') : undefined} />
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', background:'#1f2430', borderRadius:10, padding:'14px 18px', marginTop:12 }}>
            <div>
              <p style={{ fontSize:11, color:'#868b98', textTransform:'uppercase', letterSpacing:'.05em', marginBottom:4, fontWeight:600 }}>XRP Balance</p>
              <p style={{ fontSize:24, fontWeight:700, color:'#f2f3f7', margin:0, fontFamily:'monospace' }}>
                {balance !== null ? <>{balance} <span style={{ fontSize:14, color:'#868b98', fontWeight:500 }}>XRP</span></> : <span style={{ color:'#5a5f6c', fontSize:18 }}>—</span>}
              </p>
            </div>
            <button className="btn-secondary" style={{ padding:'8px 14px', fontSize:13 }} onClick={fetchBalance} disabled={loading}>
              {loading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
        </Section>

        <Section title="Oracle Connection">
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
            <Dot ok={oracleStatus?.authenticated ?? false}/>
            <span style={{ fontSize:14, fontWeight:500, color: oracleStatus?.authenticated ? '#6ac79a' : '#e07a6a' }}>
            {oracleStatus?.authenticated ? 'Connected' : 'Not connected'}
          </span>
            <button onClick={fetchOracle} style={{ marginLeft:'auto', background:'none', border:'none', cursor:'pointer', color:'#868b98', fontSize:12 }}>Refresh</button>
          </div>
          <Row label="Token expiry" value={fmtExpiry(oracleStatus?.expiresAt ?? null)} />
          <Row label="Refresh token" value={oracleStatus?.hasRefreshToken ? 'Available' : 'None'} />
          <Row label="Role" value={oracleStatus?.role || 'user'} />
          {oracleStatus?.needsRefresh && (
              <div style={{ background:'rgba(251,191,36,0.1)', border:'1px solid rgba(251,191,36,0.3)', borderRadius:8, padding:'8px 12px', marginTop:10, display:'flex', alignItems:'center', gap:8 }}>
                <span style={{ color:'#e6b35a', fontSize:12 }}>Token expires soon — will auto-refresh</span>
              </div>
          )}
        </Section>

        <Section title="Security">
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
            <Dot ok={user?.hasPreKeys ?? false}/>
            <span style={{ fontSize:14, fontWeight:500, color: user?.hasPreKeys ? '#6ac79a' : '#e6b35a' }}>
            {user?.hasPreKeys ? 'PRE keys configured' : 'PRE keys not configured'}
          </span>
          </div>
          {user?.publicKey && <Row label="Public key" value={user.publicKey.slice(0,32)+'...'} mono onCopy={()=>copy(user.publicKey,'Public key')} />}
          <Row label="Device fingerprint" value={oracleStatus?.deviceFingerprint ? oracleStatus.deviceFingerprint.slice(0,16)+'...' : 'Loading...'} mono
               onCopy={oracleStatus?.deviceFingerprint ? ()=>copy(oracleStatus.deviceFingerprint,'Device fingerprint') : undefined} />
        </Section>

        <Section title="About">
          <Row label="Version" value="XRPL Vault v0.1.0" />
          <Row label="Protocol" value="XRP Ledger (XRPL)" />
          <Row label="Encryption" value="Proxy Re-Encryption (PRE)" />
          <Row label="Access control" value="NFT-based ownership" />
          <Row label="Cipher" value="AES-256-GCM" />
        </Section>
      </div>
  )
}