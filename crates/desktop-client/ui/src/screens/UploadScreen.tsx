import { useState, useEffect, useRef, useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-dialog'
import { stat } from '@tauri-apps/plugin-fs'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import { getNftColors } from '../utils/nft_image'
import { formatError } from '../utils/formatError'

interface FileEntry { path: string; name: string; size: number; oversized: boolean }

const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100MB — matches backend AppConfig

interface UploadResult {
  vault_id: string; nft_token_id: string; offer_index: string
  signing_request_uri: string | null; nft_uri: string; manifest_hash: string; filename: string
  file_size: number; fragments_count: number
}
interface VaultedSubmitResponse {
  engineResult: string; engineResultMessage: string; txHash: string
  accepted: boolean; nftTokenId: string | null
}
interface VaultedSignedMintResponse {
  signed: { txBlob: string | null; txHash: string | null }
  submitted: VaultedSubmitResponse | null
}
interface VaultObjectResponse {
  nft_token_id: string | null
}
interface XrplAccountStatus {
  status: string; address: string; exists: boolean; balanceXrp: string | null
  reserveRequirementXrp: string; network: string; canMint: boolean
  actionHint: string; actionLabel: string | null; actionUrl: string | null
}
interface VaultedNftMetadataPreview {
  visualSeed: string; svg: string; imageDataUri: string; metadataJson: string
  metadataHash: string; metadataUri: string
}
interface ClaimPayload {
  uuid: string; qrPng: string; qrUri: string
  websocketUrl: string; expiresAt: string | null
}
interface ProgressEvent {
  operationId: string; operationType: string; stage: string
  progress: number; totalProgress: number; message: string
  bytesProcessed: number; bytesTotal: number
}

const CLAIM_TIMEOUT_SEC = 300 // 5 minutes

const fmt = (b: number) =>
    b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`

const fmtTime = (sec: number) => {
  const m = Math.floor(sec / 60)
  const s = sec % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

const STAGES: Record<string,{label:string;sub:string;order:number}> = {
  starting:    { label: 'Preparing',               sub: 'Initializing encryption',  order: 0 },
  encrypting:  { label: 'Encrypting file',         sub: 'AES-256-GCM',              order: 1 },
  minting:     { label: 'Minting NFT on XRPL',     sub: 'Recording ownership',      order: 2 },
  uploading:   { label: 'Uploading encrypted data', sub: 'Sending to storage nodes', order: 3 },
  fetching:    { label: 'Uploading encrypted data', sub: 'Sending to storage nodes', order: 3 },
  complete:    { label: 'Complete',                 sub: 'File secured',             order: 4 },
}

type ClaimState = 'loading' | 'waiting' | 'registered' | 'minting' | 'claimed' | 'expired' | 'cancelled' | 'error'

export default function UploadScreen({ onNavigate }: { oracleConnected?: boolean; onNavigate?: (s: string) => void }) {
  const [files, setFiles] = useState<string[]>([])
  const [fileEntries, setFileEntries] = useState<FileEntry[]>([])
  const [customName, setCustomName] = useState('')
  const [tag, setTag] = useState('')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<UploadResult|null>(null)
  const [claimPayload, setClaimPayload] = useState<ClaimPayload|null>(null)
  const [claimState, setClaimState] = useState<ClaimState>('loading')
  const [timeLeft, setTimeLeft] = useState(CLAIM_TIMEOUT_SEC)
  const [cancelling, setCancelling] = useState(false)
  const [mintResult, setMintResult] = useState<VaultedSubmitResponse | null>(null)
  const [nftPreview, setNftPreview] = useState<VaultedNftMetadataPreview | null>(null)
  const [error, setError] = useState<string|null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [progress, setProgress] = useState<ProgressEvent|null>(null)
  const [xrplStatus, setXrplStatus] = useState<XrplAccountStatus|null>(null)
  const [checkingXrpl, setCheckingXrpl] = useState(false)
  const [finalizingMint, setFinalizingMint] = useState(false)
  const [addressCopied, setAddressCopied] = useState(false)

  const timerRef = useRef<ReturnType<typeof setInterval>|null>(null)
  const abortedRef = useRef(false)

  // --- Cleanup timer ---
  const clearTimer = useCallback(() => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null }
  }, [])

  useEffect(() => () => clearTimer(), [clearTimer])

  // --- Load file info (sizes) after selection ---
  const loadFileInfo = useCallback(async (paths: string[]) => {
    const entries: FileEntry[] = await Promise.all(
        paths.map(async (p) => {
          const name = p.split(/[\\/]/).pop() || 'file'
          try {
            const info = await stat(p)
            const size = info.size ?? 0
            return { path: p, name, size, oversized: size > MAX_FILE_SIZE }
          } catch {
            return { path: p, name, size: 0, oversized: false }
          }
        })
    )
    setFileEntries(entries)
  }, [])

  // --- Cancel / Burn on oracle side ---
  const cancelAndBurn = useCallback(async (r: UploadResult) => {
    try {
      await invoke('cancel_secure_note_offer', {
        nftTokenId: r.nft_token_id,
        offerIndex: r.offer_index,
      })
    } catch (e) { console.error('Failed to cancel/burn on oracle:', e) }
  }, [])

  // --- File progress listener ---
  useEffect(() => {
    const unlisten = listen<ProgressEvent>('file-progress', (e) => setProgress(e.payload))
    return () => { unlisten.then(f => f()) }
  }, [])

  // --- Drag-drop ---
  useEffect(() => {
    let cleanup: (() => void) | null = null
    const setup = async () => {
      try {
        cleanup = await getCurrentWebviewWindow().onDragDropEvent((event) => {
          if (event.payload.type === 'over') setDragOver(true)
          else if (event.payload.type === 'drop') {
            setDragOver(false)
            const paths = event.payload.paths
            if (paths?.length) {
              setFiles(paths); setResult(null); setClaimPayload(null); setNftPreview(null); setError(null)
              loadFileInfo(paths)
              if (paths.length > 1) {
                const firstName = paths[0].split(/[\\/]/).pop()?.replace(/\.[^.]+$/, '') || 'files'
                setCustomName(`${firstName}_and_${paths.length - 1}_more`)
              } else setCustomName('')
            }
          } else if (event.payload.type === 'cancelled') setDragOver(false)
        })
      } catch(e) { console.warn('Drag-drop not available:', e) }
    }
    setup()
    return () => { if (cleanup) cleanup() }
  }, [loadFileInfo])

  const pickFiles = async () => {
    try {
      const f = await open({ multiple: true, title: 'Select files to upload' })
      if (f) {
        const sel = Array.isArray(f) ? f : [f]
        setFiles(sel); setResult(null); setClaimPayload(null); setNftPreview(null); setError(null)
        loadFileInfo(sel)
        if (sel.length > 1) {
          const firstName = sel[0].split(/[\\/]/).pop()?.replace(/\.[^.]+$/, '') || 'files'
          setCustomName(`${firstName}_and_${sel.length - 1}_more`)
        } else setCustomName('')
      }
    } catch(e) { setError(String(e)) }
  }


  const generateNftPreview = useCallback(async (r: UploadResult) => {
    return await invoke<VaultedNftMetadataPreview>('generate_vaulted_nft_metadata_preview', {
      manifestHash: r.manifest_hash,
      vaultObjectId: r.vault_id,
      metadataUri: r.nft_uri,
    })
  }, [])

  const upload = async () => {
    if (!files.length) return
    try {
      setUploading(true); setError(null); setProgress(null); setClaimState('loading')
      let finalName = customName || null
      if (tag && files.length === 1 && !customName) {
        const orig = files[0].split(/[\\/]/).pop() || 'file'
        const d = orig.lastIndexOf('.')
        finalName = d > 0 ? `${orig.slice(0,d)}[${tag}]${orig.slice(d)}` : `${orig}[${tag}]`
      } else if (tag && customName) {
        const d = customName.lastIndexOf('.')
        finalName = d > 0 ? `${customName.slice(0,d)}[${tag}]${customName.slice(d)}` : `${customName}[${tag}]`
      }
      let r: UploadResult
      if (files.length === 1 && !finalName) r = await invoke<UploadResult>('upload_file', { filePath: files[0] })
      else r = await invoke<UploadResult>('upload_files', { filePaths: files, customName: finalName || null })
      setResult(r)
      setNftPreview(await generateNftPreview(r))
      setClaimPayload(null)
      setTimeLeft(CLAIM_TIMEOUT_SEC)
      setClaimState('registered')
    } catch(e) { setError(String(e)) }
    finally { setUploading(false); setProgress(null) }
  }

  const handleCancel = async () => {
    if (!result) return
    setCancelling(true)
    abortedRef.current = true
    clearTimer()
    try {
      await cancelAndBurn(result)
      setClaimState('cancelled')
    } catch (e) {
      setError('Failed to cancel: ' + e)
    } finally { setCancelling(false) }
  }

  const checkXrplBeforeMint = async () => {
    setCheckingXrpl(true)
    setError(null)
    try {
      const status = await invoke<XrplAccountStatus>('check_xrpl_account_status', { address: null })
      setXrplStatus(status)
      return status
    } catch (e) {
      setError(formatError(e))
      return null
    } finally {
      setCheckingXrpl(false)
    }
  }

  const copyXrplAddress = async () => {
    if (!xrplStatus?.address) return
    await navigator.clipboard.writeText(xrplStatus.address)
    setAddressCopied(true)
    setTimeout(() => setAddressCopied(false), 1800)
  }

  const handleLocalMint = async () => {
    if (!result) return
    setError(null)
    setMintResult(null)
    const account = xrplStatus?.canMint ? xrplStatus : await checkXrplBeforeMint()
    if (!account) return
    if (!account.canMint) {
      setError(null)
      return
    }
    setClaimState('minting')
    try {
      const preview = nftPreview || await generateNftPreview(result)
      if (!nftPreview) setNftPreview(preview)

      await invoke('publish_vaulted_nft_metadata', {
        vaultObjectId: result.vault_id,
        manifestHash: result.manifest_hash,
        metadataUri: preview.metadataUri,
        metadataJson: preview.metadataJson,
        metadataHash: preview.metadataHash,
      })

      const minted = await invoke<VaultedSignedMintResponse>('mint_vaulted_nft_locally', {
        request: {
          metadataUri: preview.metadataUri,
          nftokenTaxon: 0,
        },
        submit: true,
      })

      const submitted = minted.submitted
      if (!submitted) throw new Error('XRPL transaction was signed but not submitted')
      if (!submitted.accepted) {
        throw new Error(`${submitted.engineResult}: ${submitted.engineResultMessage}`)
      }
      if (!submitted.nftTokenId) {
        setMintResult(submitted)
        throw new Error(`XRPL mint succeeded (${submitted.txHash}), but Vaulted could not extract the minted NFTokenID for Oracle finalization. Retry finalization after refreshing.`)
      }

      setMintResult(submitted)
      setResult({ ...result, nft_token_id: submitted.nftTokenId })

      await invoke('register_minted_vault_object', {
        vaultObjectId: result.vault_id,
        manifestUri: preview.metadataUri,
        manifestHash: result.manifest_hash,
        nftTokenId: submitted.nftTokenId,
        txHash: submitted.txHash,
      })

      setClaimState('claimed')
    } catch (e) {
      setClaimState('registered')
      setError(formatError(e))
    }
  }

  const handlePendingMintFinalize = async () => {
    if (!result || !mintResult?.accepted || !mintResult.txHash) return
    setError(null)
    setFinalizingMint(true)
    setClaimState('minting')
    try {
      const preview = nftPreview || await generateNftPreview(result)
      if (!nftPreview) setNftPreview(preview)

      const linked = await invoke<VaultObjectResponse>('finalize_pending_vault_mint', {
        vaultObjectId: result.vault_id,
        manifestUri: preview.metadataUri,
        manifestHash: result.manifest_hash,
        txHash: mintResult.txHash,
      })
      const nftTokenId = linked.nft_token_id
      if (!nftTokenId) {
        throw new Error(`Missing NFTokenID after finalize retry. tx_hash=${mintResult.txHash}`)
      }
      setResult({ ...result, nft_token_id: nftTokenId })
      setMintResult({ ...mintResult, nftTokenId })
      setClaimState('claimed')
    } catch (e) {
      setClaimState('registered')
      setError(formatError(e))
    } finally {
      setFinalizingMint(false)
    }
  }

  const resetAll = () => {
    abortedRef.current = true
    clearTimer()
    setFiles([]); setFileEntries([]); setCustomName(''); setTag('')
    setResult(null); setClaimPayload(null); setMintResult(null); setNftPreview(null); setXrplStatus(null)
    setClaimState('loading'); setTimeLeft(CLAIM_TIMEOUT_SEC)
    setProgress(null); setError(null); setFinalizingMint(false)
  }

  const isFolder = files.length === 1 && !files[0].includes('.')
  const willArchive = files.length > 1 || isFolder
  const hasOversized = fileEntries.some(f => f.oversized)
  const totalSize = fileEntries.reduce((s, f) => s + f.size, 0)
  const curStage = progress ? (STAGES[progress.stage] || STAGES.starting) : null
  const visStages = Object.entries(STAGES).filter(([k]) => !['starting','fetching'].includes(k))

  return (
      <div className="fade-in" style={{ maxWidth:960, margin:'0 auto' }}>
        {!uploading && !result && (
            <>
              <div className={`v-dropzone${dragOver ? ' drag-over' : ''}`}
                   style={{padding: files.length ? 28 : 56, marginBottom: files.length ? 20 : 0}}
                   onClick={pickFiles}>
                <div className="title">{dragOver ? 'Drop files here' : 'Drop files here or click to browse'}</div>
                <div className="sub">Max 100 MB per file · AES-256 encryption before upload</div>
              </div>

              {files.length > 0 && (
                  <div className="v-col" style={{ gap: 14 }}>
                    {willArchive && (
                        <div style={{ background:'var(--accent-soft)', border:'1px solid var(--accent-line)', borderRadius:'var(--radius-md)', padding:'12px 16px', marginBottom:16, display:'flex', alignItems:'center', gap:10 }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5" aria-hidden="true"><path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/></svg>
                          <span style={{ fontSize:12, color:'var(--accent)' }}>{isFolder ? 'Folder' : `${files.length} files`} will be archived before encryption</span>
                        </div>
                    )}

                    {/* File list with sizes */}
                    <div style={{ maxHeight: fileEntries.length > 4 ? 200 : 'none', overflowY: fileEntries.length > 4 ? 'auto' : 'visible', display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {fileEntries.map((entry, i) => (
                          <div key={i} className="v-filecard" style={{ height: 48 }}>
                            <div style={{ width: 42, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: '1px solid var(--line)', color: entry.oversized ? 'var(--danger)' : 'var(--fg-2)' }}>
                              {entry.oversized ? (
                                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                              ) : (
                                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
                              )}
                            </div>
                            <div className="v-file-body" style={{ gap: 1, padding: '0 10px' }}>
                              <div className="v-file-name" style={{ fontSize: 12 }}>{entry.name}</div>
                              <div className="v-file-meta" style={{ fontSize: 11 }}>
                              <span style={entry.oversized ? { color: 'var(--danger)', fontWeight: 600 } : undefined}>
                                {fmt(entry.size)}{entry.oversized ? ' — exceeds 100 MB limit' : ''}
                              </span>
                              </div>
                            </div>
                          </div>
                      ))}
                    </div>

                    {/* Total size */}
                    {fileEntries.length > 1 && (
                        <div style={{ fontSize: 12, color: 'var(--fg-2)', textAlign: 'right' }}>
                          Total: {fmt(totalSize)}
                        </div>
                    )}

                    {/* Oversized warning */}
                    {hasOversized && (
                        <div role="alert" style={{ background: 'var(--danger-soft)', border: '1px solid rgba(224,122,106,0.3)', borderRadius: 'var(--radius-md)', padding: '10px 14px', fontSize: 12, color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 8 }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                          One or more files exceed the 100 MB size limit. Remove them before uploading.
                        </div>
                    )}

                    <div className="v-field">
                      <div className="v-label">Display name</div>
                      <input className="v-input" type="text" value={customName} onChange={e=>setCustomName(e.target.value)}
                             placeholder={files.length===1 ? files[0].split(/[\\/]/).pop() : 'archive'} />
                    </div>
                    <div className="v-field">
                      <div className="v-label">Tag</div>
                      <input className="v-input" type="text" value={tag} onChange={e=>setTag(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g,''))}
                             placeholder="e.g. password, seed, key, backup, secret, wallet, none" />
                    </div>
                    <div className="v-row" style={{ justifyContent:'flex-end', marginTop: 4 }}>
                      <button className="v-btn" aria-label="Clear selected files" onClick={()=>{setFiles([]);setFileEntries([]);setCustomName('');setTag('')}}>Clear</button>
                      <button className="v-btn v-btn-primary" onClick={upload} disabled={hasOversized}>
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        Encrypt &amp; Upload {willArchive ? 'ZIP' : ''}
                      </button>
                    </div>
                  </div>
              )}
            </>
        )}

        {/* ── Stepper: shown during upload AND after result (all done) ── */}
        {(uploading || result) && (claimState !== 'registered' && claimState !== 'claimed' && claimState !== 'expired' && claimState !== 'cancelled' && claimState !== 'error') && (
            <div style={{ marginBottom:24 }}>
              <div style={{textAlign:'center',marginBottom:24}}>
                <div className="v-section-title" style={{fontSize:20}}>Minting NFT for <span className="v-mono" style={{color:'var(--accent)'}}>{customName || files[0]?.split(/[\\/]/).pop() || 'file'}</span></div>
                <div className="v-section-sub" style={{fontSize:15,marginTop:4}}>Keep this window open. Vaulted wallet mode keeps signing local.</div>
              </div>

              {/* Progress bar — larger */}
              <div style={{marginBottom:24}}>
                <div className="v-row" style={{justifyContent:'space-between',marginBottom:8}}>
                  <span style={{fontSize:15,fontWeight:500,color:'var(--fg-1)'}}>{result ? 'Complete' : (progress?.message || 'Starting...')}</span>
                  <span className="v-mono" style={{fontSize:15,fontWeight:600,color:'var(--fg-0)'}}>{result ? '100' : (progress?.totalProgress || 0)}%</span>
                </div>
                <div style={{ height:8, background:'var(--bg-1)', borderRadius:4, overflow:'hidden' }}>
                  <div style={{ height:'100%', borderRadius:4, background:'linear-gradient(90deg, var(--accent), var(--accent-deep))', width:`${result ? 100 : (progress?.totalProgress||0)}%`, transition:'width 0.3s ease' }}/>
                </div>
                {!result && progress && progress.bytesTotal > 0 && <p style={{ fontSize:13, color:'var(--fg-2)', marginTop:8 }}>{fmt(progress.bytesProcessed)} / {fmt(progress.bytesTotal)}</p>}
              </div>

              {/* Stepper — larger */}
              <div className="v-stepper v-stepper-lg" style={{maxWidth:480,margin:'0 auto'}}>
                {visStages.map(([key, stage]) => {
                  const allDone = !!result
                  const done = allDone || (curStage?.order ?? 0) > stage.order
                  const active = !allDone && (progress?.stage === key || (key==='uploading' && progress?.stage==='fetching'))
                  return (
                      <div key={key} className={`v-step${done?' done':''}${active?' active':''}`}>
                        <div className="v-step-icon">
                          {done
                              ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                              : active
                                  ? <div className="v-spin" style={{width:18,height:18}}/>
                                  : <span style={{width:8,height:8,borderRadius:'50%',background:'var(--fg-3)'}}/>
                          }
                        </div>
                        <div>
                          <div className="v-step-label">{stage.label}</div>
                          <div className="v-step-sub">{active && progress ? progress.message : stage.sub}</div>
                        </div>
                      </div>
                  )
                })}
              </div>
            </div>
        )}

        {/* ── Claim section (below stepper) ── */}
        {result && (
            <div className="fade-in" style={{ textAlign:'center' }}>

              {/* ── LOADING: creating claim payload ── */}
              {claimState === 'loading' && (
                  <div style={{padding:40}}>
                    <div className="v-spin" style={{width:32,height:32,margin:'0 auto 16px',borderWidth:2}}/>
                    <div style={{fontSize:15,fontWeight:500,color:'var(--fg-1)'}}>Preparing claim...</div>
                    <div className="v-section-sub" style={{marginTop:4}}>Preparing Vaulted signing request</div>
                  </div>
              )}

              {/* ── WAITING: QR code + countdown ── */}
              {claimState === 'waiting' && claimPayload && (
                  <div className="fade-in">
                    <div style={{marginBottom:20}}>
                      <div style={{fontSize:18,fontWeight:600,color:'var(--fg-0)',marginBottom:4}}>Scan to claim your NFT</div>
                      <div className="v-section-sub v-mono">NFT {result.nft_token_id.slice(0,8)}…{result.nft_token_id.slice(-4)} · {result.filename} · {fmt(result.file_size)}</div>
                    </div>

                    {/* QR image */}
                    <div style={{width:200,height:200,margin:'0 auto 20px',borderRadius:14,overflow:'hidden',background:'#fff',display:'flex',alignItems:'center',justifyContent:'center'}}>
                      <img src={claimPayload.qrPng} alt="Claim QR" style={{ width:'100%',height:'100%',objectFit:'contain' }}/>
                    </div>

                    {/* Timer text */}
                    <div style={{fontSize:28,fontWeight:700,fontFamily:'var(--font-mono)',color: timeLeft <= 60 ? 'var(--danger)' : 'var(--fg-0)',marginBottom:6}}>
                      {fmtTime(timeLeft)}
                    </div>
                    <div style={{fontSize:13,color:'var(--fg-2)',marginBottom:20}}>Time remaining to accept NFT</div>

                    {/* Signing request link */}
                    <div style={{marginBottom:20}}>
                      <a href={`${claimPayload.qrUri}`} target="_blank" rel="noopener noreferrer"
                         style={{ color:'var(--accent)',fontSize:13,textDecoration:'none',display:'inline-flex',alignItems:'center',gap:6 }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                        Open signing request
                      </a>
                    </div>

                    {/* Cancel button */}
                    <button className="v-btn v-btn-danger" disabled={cancelling}
                            style={{width:'100%',maxWidth:360,justifyContent:'center',height:44,fontSize:14,margin:'0 auto'}}
                            onClick={handleCancel}>
                      {cancelling ? (
                          <><div className="v-spin" style={{width:14,height:14,borderColor:'rgba(224,122,106,0.2)',borderTopColor:'var(--danger)'}}/> Cancelling...</>
                      ) : (
                          <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Cancel</>
                      )}
                    </button>
                  </div>
              )}


              {/* ── REGISTERED: Vaulted mode pending local XRPL signing ── */}
              {claimState === 'registered' && result && (
                  <div className="fade-in">
                    <div style={{background:'var(--ok-soft)',border:'1px solid var(--ok-line)',borderRadius:'var(--radius-md)',padding:28,marginBottom:20,textAlign:'center'}}>
                      <div style={{width:52,height:52,borderRadius:'50%',background:'var(--ok-soft)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--ok)',margin:'0 auto 12px'}}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                      </div>
                      <div style={{fontSize:18,fontWeight:600,color:'var(--ok)'}}>Encrypted vault registered</div>
                      <div style={{fontSize:14,color:'var(--fg-2)',marginTop:6}}>Your encrypted file and manifest were created. Mint the ownership NFT with your Vaulted-derived XRPL wallet.</div>
                      {nftPreview && (
                        <div style={{width:128,aspectRatio:'2/3',borderRadius:14,overflow:'hidden',background:'#060608',margin:'16px auto 0',border:'1px solid var(--line)',boxShadow:'0 18px 40px rgba(0,0,0,0.25)'}}>
                          <img src={nftPreview.imageDataUri} alt="Deterministic Vaulted NFT preview" style={{width:'100%',height:'100%',objectFit:'cover',display:'block'}} />
                        </div>
                      )}
                      <div className="v-mono" style={{fontSize:12,color:'var(--fg-3)',marginTop:12,wordBreak:'break-all'}}>
                        Published metadata URI: {nftPreview?.metadataUri || result.nft_uri}
                      </div>
                    </div>
                    {xrplStatus && !xrplStatus.canMint && (
                      <div className="v-mint-preflight-card">
                        <div className="v-mint-preflight-title">Wallet is not funded yet</div>
                        <div className="v-mint-preflight-copy">{xrplStatus.actionHint}</div>
                        <div className="v-mono v-mint-address">{xrplStatus.address}</div>
                        <div className="v-mint-preflight-actions">
                          <button className="v-btn" onClick={copyXrplAddress}>{addressCopied ? 'Copied' : 'Copy address'}</button>
                          {xrplStatus.actionUrl && <button className="v-btn v-btn-primary" onClick={() => window.open(xrplStatus.actionUrl!, '_blank')}>Open faucet</button>}
                          <button className="v-btn" onClick={checkXrplBeforeMint} disabled={checkingXrpl}>{checkingXrpl ? 'Checking…' : 'I funded it — check again'}</button>
                        </div>
                      </div>
                    )}
                    <div style={{display:'flex',gap:10}}>
                      <button className="v-btn v-btn-primary" style={{ flex:1,justifyContent:'center',height:44,fontSize:14 }} onClick={handleLocalMint} disabled={checkingXrpl || finalizingMint || (xrplStatus ? !xrplStatus.canMint : false)}>
                        {checkingXrpl ? 'Checking wallet…' : xrplStatus?.canMint ? 'Mint vault NFT' : 'Check wallet and mint'}
                      </button>
                      <button className="v-btn" style={{ flex:1,justifyContent:'center',height:44,fontSize:14 }} onClick={() => { resetAll(); onNavigate?.('files') }}>Skip for now</button>
                    </div>
                    {mintResult?.accepted && mintResult.txHash && !mintResult.nftTokenId && (
                      <button className="v-btn v-btn-primary" style={{ width:'100%',justifyContent:'center',height:44,fontSize:14,marginTop:10 }} onClick={handlePendingMintFinalize} disabled={finalizingMint}>
                        {finalizingMint ? 'Finalizing…' : 'Finalize existing mint'}
                      </button>
                    )}
                  </div>
              )}

              {/* ── MINTING: local Vaulted XRPL submit ── */}
              {claimState === 'minting' && (
                  <div className="fade-in">
                    <div style={{background:'var(--accent-soft)',border:'1px solid var(--accent-line)',borderRadius:'var(--radius-md)',padding:28,marginBottom:20,textAlign:'center'}}>
                      <div className="v-spin" style={{width:34,height:34,margin:'0 auto 12px'}} />
                      <div style={{fontSize:18,fontWeight:600,color:'var(--accent)'}}>Minting with Vaulted Wallet</div>
                      <div style={{fontSize:14,color:'var(--fg-2)',marginTop:6}}>Publishing metadata, then building, signing, and submitting the NFTokenMint transaction locally.</div>
                    </div>
                  </div>
              )}

              {/* ── CLAIMED: success ── */}
              {claimState === 'claimed' && result && (() => {
                const nftColor = getNftColors(result.nft_token_id, '#3b82f6')
                const idShort = `${result.nft_token_id.slice(0,6)}…${result.nft_token_id.slice(-4)}`
                return (
                    <div className="fade-in" style={{display:'flex',flexDirection:'column',alignItems:'center'}}>
                      {/* NFT Portrait Card */}
                      <div style={{
                        width:300,borderRadius:'var(--radius-lg)',overflow:'hidden',
                        border:`1px solid color-mix(in srgb, ${nftColor.stroke} 35%, transparent)`,
                        background:'#060608',marginBottom:20,
                        boxShadow:`0 0 50px color-mix(in srgb, ${nftColor.stroke} 12%, transparent)`,
                      }}>
                        {/* 2:3 image */}
                        <div style={{ width:'100%',aspectRatio:'2/3' }}>
                          {nftPreview ? (
                            <img src={nftPreview.imageDataUri} alt="Vaulted NFT" style={{width:'100%',height:'100%',objectFit:'cover',display:'block'}} />
                          ) : (
                            <div style={{width:'100%',height:'100%',background:'#060608'}} />
                          )}
                        </div>
                        {/* NFT ID strip — vault card style */}
                        <div style={{
                          padding:'10px 16px',
                          background:`color-mix(in srgb, ${nftColor.stroke} 20%, #0a0c14)`,
                          borderTop:`1px solid color-mix(in srgb, ${nftColor.stroke} 50%, transparent)`,
                          display:'flex',alignItems:'center',justifyContent:'center',gap:8,
                        }}>
                        <span style={{
                          fontSize:13,fontFamily:'var(--font-mono)',fontWeight:700,
                          color:'rgba(255,255,255,0.85)',letterSpacing:'0.05em',
                          userSelect:'none',
                        }}>NFT {idShort}</span>
                        </div>
                      </div>

                      {/* Success info */}
                      <div style={{textAlign:'center',marginBottom:20}}>
                        <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:8,marginBottom:4}}>
                          <div style={{width:22,height:22,borderRadius:'50%',background:'var(--ok-soft)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--ok)'}}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                          </div>
                          <span style={{fontSize:16,fontWeight:600,color:'var(--fg-1)'}}>NFT minted successfully</span>
                        </div>
                        <div className="v-mono" style={{fontSize:13,color:'var(--fg-3)'}}>
                          {result.filename} · {fmt(result.file_size)}
                        </div>
                        {mintResult?.txHash && (
                          <div className="v-mono" style={{fontSize:12,color:'var(--fg-3)',marginTop:8,wordBreak:'break-all'}}>
                            tx: {mintResult.txHash}
                          </div>
                        )}
                      </div>

                      {/* Action buttons — compact */}
                      <div style={{display:'flex',gap:10,width:300}}>
                        <button className="v-btn v-btn-primary" style={{width:'100%',justifyContent:'center',height:38,fontSize:13}} onClick={() => { resetAll(); onNavigate?.('files'); }}>
                          Done
                        </button>
                      </div>
                    </div>
                )
              })()}

              {/* ── EXPIRED: timeout ── */}
              {claimState === 'expired' && (
                  <div className="fade-in">
                    <div style={{background:'var(--warn-soft)',border:'1px solid var(--warn-line)',borderRadius:'var(--radius-md)',padding:28,marginBottom:20,textAlign:'center'}}>
                      <div style={{width:52,height:52,borderRadius:'50%',background:'var(--warn-soft)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--warn)',margin:'0 auto 12px'}}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                      </div>
                      <div style={{fontSize:18,fontWeight:600,color:'var(--warn)'}}>QR code expired</div>
                      <div style={{fontSize:14,color:'var(--fg-2)',marginTop:6}}>The local signing request expired before it was submitted.</div>
                    </div>
                    <button className="v-btn v-btn-primary" style={{ width:'100%',justifyContent:'center',height:44,fontSize:14 }} onClick={resetAll}>Try Again</button>
                  </div>
              )}

              {/* ── CANCELLED: user cancelled ── */}
              {claimState === 'cancelled' && (
                  <div className="fade-in">
                    <div style={{background:'var(--danger-soft)',border:'1px solid rgba(224,122,106,0.3)',borderRadius:'var(--radius-md)',padding:28,marginBottom:20,textAlign:'center'}}>
                      <div style={{width:52,height:52,borderRadius:'50%',background:'var(--danger-soft)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--danger)',margin:'0 auto 12px'}}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                      </div>
                      <div style={{fontSize:18,fontWeight:600,color:'var(--danger)'}}>Upload cancelled</div>
                      <div style={{fontSize:14,color:'var(--fg-2)',marginTop:6}}>The local signing step was cancelled.</div>
                    </div>
                    <button className="v-btn v-btn-primary" style={{ width:'100%',justifyContent:'center',height:44,fontSize:14 }} onClick={resetAll}>Upload Another File</button>
                  </div>
              )}

              {/* ── ERROR state ── */}
              {claimState === 'error' && (
                  <div className="fade-in">
                    <div className="error-box" style={{marginBottom:20,textAlign:'left'}}>{error}</div>
                    <button className="v-btn v-btn-primary" style={{ width:'100%',justifyContent:'center',height:44,fontSize:14 }} onClick={resetAll}>Try Again</button>
                  </div>
              )}
            </div>
        )}
        {error && claimState !== 'error' && <div className="error-box" style={{ marginTop:20 }}>{error}</div>}
      </div>
  )
}
