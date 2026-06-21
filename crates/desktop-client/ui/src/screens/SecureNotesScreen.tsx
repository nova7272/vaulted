import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

interface SecureNoteResult { vaultId: string; nftTokenId: string; offerIndex: string; signingRequestUri: string; title: string; size: number; }
interface SigningRequestPayload { uuid: string; qrPng: string; qrUri: string; websocketUrl: string; expiresAt: string | null; }
interface ProgressEvent { filename: string; stage: string; progress: number; totalProgress: number; message: string; bytesProcessed: number; bytesTotal: number; }
interface NftInfo { nftTokenId: string; uri: string; filename: string | null; createdAt: string | null; fileStatus: string; preKeyMismatch?: boolean; }
interface SecureNoteInfo { nftTokenId: string; title: string; noteType: string; size: number; createdAt: string; status: string; }
interface SecureNoteContent { nftTokenId: string; content: string; noteType: string; mimeType: string; }

import { toast } from '../components/Toast';
import { SecureNotesScreenSkeleton } from '../components/SkeletonLoader';
import { getNftColors, getNftImageUrl } from '../utils/nft_image';

const IcoEye = (s=16) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
const IcoLock = (s=16) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
const IcoTransfer = (s=14) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
const IcoBurn = (s=14) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>
const IcoPlus = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
const IcoRefresh = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>

const NOTE_PLAINTEXT_IDLE_MS = 5 * 60 * 1000;

export function SecureNotesScreen({ oracleConnected }: { oracleConnected?: boolean }) {
    void oracleConnected
    const [showCreate, setShowCreate] = useState(false);
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [hideContent, setHideContent] = useState(true);
    const [tag, setTag] = useState('');
    const [stage, setStage] = useState<'idle' | 'encrypting' | 'encrypted' | 'creating_payload' | 'complete' | 'cancelled'>('idle');
    const [, setProgress] = useState(0);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<SecureNoteResult | null>(null);

    const [storedNotes, setStoredNotes] = useState<NftInfo[]>([]);
    const [loadingNotes, setLoadingNotes] = useState(true);

    const [viewingNote, setViewingNote] = useState<NftInfo | null>(null);
    const [noteContent, setNoteContent] = useState<SecureNoteContent | null>(null);
    const [loadingNote, setLoadingNote] = useState(false);
    const [showContent, setShowContent] = useState(false);
    const viewerRequestRef = useRef(0);

    const [transferNote, setTransferNote] = useState<NftInfo | null>(null);
    const [transferTo, setTransferTo] = useState('');
    const [transferring, setTransferring] = useState(false);
    const [transferQr, setTransferQr] = useState<string | null>(null);

    const [burnNote, setBurnNote] = useState<NftInfo | null>(null);
    const [burning, setBurning] = useState(false);
    const [burnQr, setBurnQr] = useState<string | null>(null);
    const [burnConfirm, setBurnConfirm] = useState('');

    const clearCreatePlaintext = useCallback(() => {
        setTitle('');
        setContent('');
        setTag('');
        setHideContent(true);
        setError(null);
        setResult(null);
        setStage('idle');
        setProgress(0);
    }, []);

    const closeNoteViewer = useCallback(() => {
        viewerRequestRef.current += 1;
        setViewingNote(null);
        setNoteContent(null);
        setShowContent(false);
        setLoadingNote(false);
    }, []);

    const clearStoredNoteTitles = useCallback(() => {
        setStoredNotes(notes => notes.map(note => (
            note.filename ? { ...note, filename: null } : note
        )));
    }, []);

    const closeCreate = useCallback(() => {
        if (stage === 'idle' || stage === 'complete' || stage === 'cancelled') {
            clearCreatePlaintext();
            setShowCreate(false);
        }
    }, [clearCreatePlaintext, stage]);

    useEffect(() => { const u = listen<ProgressEvent>('upload-progress', (e) => { setProgress(e.payload.totalProgress); }); return () => { u.then(f => f()); }; }, []);
    useEffect(() => { loadNotes(); }, []);

    useEffect(() => {
        return () => {
            closeNoteViewer();
            clearCreatePlaintext();
            clearStoredNoteTitles();
        };
    }, [clearCreatePlaintext, clearStoredNoteTitles, closeNoteViewer]);

    useEffect(() => {
        const clearPlaintext = () => {
            closeNoteViewer();
            clearStoredNoteTitles();
            if (showCreate) {
                clearCreatePlaintext();
                setShowCreate(false);
            }
        };
        const clearOnVisibilityChange = () => {
            if (document.visibilityState !== 'visible') clearPlaintext();
        };

        window.addEventListener('blur', clearPlaintext);
        document.addEventListener('visibilitychange', clearOnVisibilityChange);
        return () => {
            window.removeEventListener('blur', clearPlaintext);
            document.removeEventListener('visibilitychange', clearOnVisibilityChange);
        };
    }, [clearCreatePlaintext, clearStoredNoteTitles, closeNoteViewer, showCreate]);

    useEffect(() => {
        const hasPlaintext = !!noteContent || storedNotes.some(note => !!note.filename) || (showCreate && (!!title || !!content));
        if (!hasPlaintext) return;

        let timer: ReturnType<typeof setTimeout>;
        const reset = () => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                closeNoteViewer();
                clearStoredNoteTitles();
                if (showCreate) {
                    clearCreatePlaintext();
                    setShowCreate(false);
                }
            }, NOTE_PLAINTEXT_IDLE_MS);
        };

        const events: Array<keyof WindowEventMap> = ['mousemove', 'mousedown', 'keydown', 'touchstart'];
        reset();
        events.forEach(event => window.addEventListener(event, reset, { passive: true }));
        return () => {
            clearTimeout(timer);
            events.forEach(event => window.removeEventListener(event, reset));
        };
    }, [clearCreatePlaintext, clearStoredNoteTitles, closeNoteViewer, content, noteContent, showCreate, storedNotes, title]);

    // Escape key closes modals
    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => {
            if (e.key !== 'Escape') return;
            if (viewingNote) { closeNoteViewer(); return; }
            if (burnNote && !burning) { setBurnNote(null); setBurnQr(null); return; }
            if (transferNote && !transferring) { setTransferNote(null); setTransferQr(null); return; }
            if (showCreate && stage === 'idle') { closeCreate(); return; }
        };
        document.addEventListener('keydown', handleEsc);
        return () => document.removeEventListener('keydown', handleEsc);
    });

    const loadNotes = async () => {
        try {
            setLoadingNotes(true);
            const notes = await invoke<SecureNoteInfo[]>('list_secure_notes');
            setStoredNotes(notes.map(n => ({
                nftTokenId: n.nftTokenId,
                uri: '',
                filename: n.title.trim() || null,
                createdAt: n.createdAt,
                fileStatus: n.status,
            })));
        } catch {
            // Secure notes list refresh is best-effort; existing state remains visible.
        } finally { setLoadingNotes(false); }
    };

    const viewNote = async (nft: NftInfo) => {
        const requestId = viewerRequestRef.current + 1;
        viewerRequestRef.current = requestId;
        try {
            setViewingNote(nft); setLoadingNote(true); setShowContent(false); setNoteContent(null);
            const c = await invoke<SecureNoteContent>('decrypt_secure_note', { nftTokenId: nft.nftTokenId });
            if (viewerRequestRef.current !== requestId) return;
            setNoteContent(c);
        } catch (e) {
            toast({ type: 'error', title: 'Failed to decrypt', sub: String(e) });
            closeNoteViewer();
        } finally { setLoadingNote(false); }
    };

    const startTransfer = async () => {
        if (!transferNote || !transferTo.trim()) return;
        try {
            setTransferring(true);
            const r = await invoke<{ transferId: string; signingRequest: SigningRequestPayload | null }>('initiate_transfer', { nftTokenId: transferNote.nftTokenId, toAddress: transferTo.trim() });
            if (r.signingRequest?.qrPng) {
                setTransferQr(r.signingRequest.qrPng);
                toast({ type: 'info', title: 'Vaulted signing', sub: 'Approve the transfer with Vaulted wallet signing' });
            } else {
                toast({ type: 'warning', title: 'Vaulted signing pending', sub: 'Local XRPL transfer signing is not implemented yet' });
            }
        } catch (e) { toast({ type: 'error', title: 'Transfer failed', sub: String(e) }); }
        finally { setTransferring(false); }
    };

    const startBurn = async () => {
        if (!burnNote) return;
        setBurning(true);
        setBurnQr(null);
        toast({ type: 'warning', title: 'Vaulted signing pending', sub: 'Local XRPL NFT burn signing is not implemented yet' });
        setBurning(false);
    };

    const handleEncrypt = async () => {
        if (!title.trim() || !content.trim()) { setError('Enter title and content'); return; }
        setError(null); setStage('encrypting'); setProgress(0); setResult(null);
        try {
            const finalTitle = tag ? `${title.trim()}[${tag}]` : title.trim();
            const res = await invoke<SecureNoteResult>('encrypt_secure_note', { title: finalTitle, content, noteType: 'password' });
            setTitle('');
            setContent('');
            setTag('');
            setHideContent(true);
            setResult(res);
            setStage('complete');
            loadNotes();
        } catch (e) { setError(String(e)); setStage('idle'); }
    };

    const handleReset = () => { clearCreatePlaintext(); };

    return (
        <div style={{ maxWidth: 1200, margin: '0 auto' }}>
            <div className="v-section-head" style={{ marginBottom: 24 }}>
                <div>
                    <div className="v-section-title">Secure Notes</div>
                    <div className="v-section-sub">{loadingNotes ? 'Loading encrypted notes…' : `${storedNotes.length} encrypted ${storedNotes.length === 1 ? 'note' : 'notes'}`}</div>
                </div>
                <div className="v-toolbar">
                    <button onClick={loadNotes} className="v-btn" disabled={loadingNotes}><IcoRefresh /> Refresh</button>
                    <button onClick={() => setShowCreate(true)} className="v-btn v-btn-primary" disabled={loadingNotes}><IcoPlus /> New Note</button>
                </div>
            </div>

            {loadingNotes ? (
                <SecureNotesScreenSkeleton />
            ) : storedNotes.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '80px 24px', borderRadius: 'var(--radius-lg)', border: '1px dashed var(--bg-4)', background: 'var(--bg-1)' }}>
                    <div style={{ width: 72, height: 72, borderRadius: 18, background: 'var(--bg-3)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20 }}>{IcoLock(32)}</div>
                    <p style={{ fontSize: 18, fontWeight: 600, margin: '0 0 8px' }}>No secure notes yet</p>
                    <p style={{ fontSize: 15, color: 'var(--fg-2)', margin: '0 0 24px' }}>Store passwords, seed phrases, and secrets in encrypted vaults</p>
                    <button onClick={() => setShowCreate(true)} className="v-btn v-btn-primary" style={{ height: 48, fontSize: 16, padding: '0 28px' }}><IcoPlus /> Create your first note</button>
                </div>
            ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gridAutoRows: '1fr', gap: 14 }}>
                    {storedNotes.map(n => {
                        const date = n.createdAt ? new Date(n.createdAt).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' }) : null;
                        const nftColor = getNftColors(n.nftTokenId, '#a855f7');
                        const idLabel = `${n.nftTokenId.slice(0,6)}…${n.nftTokenId.slice(-4)}`;
                        const isOnChain = n.fileStatus === 'active';
                        const statusLabel = isOnChain ? 'Encrypted · On-chain owner' : 'Encrypted vault saved · NFT mint pending';
                        const idPrefix = isOnChain ? 'NFT' : 'Vault';

                        return (
                            <div key={n.nftTokenId} style={{ display: 'flex', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 'var(--radius-lg)', transition: 'border-color .15s' }}
                                 onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--line-2)')} onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--line)')}>
                                <div style={{ width: 140, minWidth: 140, backgroundImage: getNftImageUrl(n.nftTokenId, '#a855f7'), backgroundSize: 'cover', backgroundPosition: 'center', backgroundColor: '#060608' }} />
                                <div style={{ width: 34, minWidth: 34, background: `color-mix(in srgb, ${nftColor.stroke} 20%, #0a0c14)`, borderLeft: `1px solid color-mix(in srgb, ${nftColor.stroke} 50%, transparent)`, borderRight: `1px solid color-mix(in srgb, ${nftColor.stroke} 30%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                    <div style={{ writingMode: 'vertical-rl', textOrientation: 'mixed', transform: 'rotate(180deg)', fontSize: 13, fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'rgba(255,255,255,0.85)', letterSpacing: '0.05em', whiteSpace: 'nowrap', userSelect: 'none' }}>{idPrefix} {idLabel}</div>
                                </div>
                                <div style={{ flex: 1, padding: '22px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minWidth: 0, minHeight: 160, position: 'relative' }}>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                        <div style={{ fontSize: 19, fontWeight: 600, color: 'var(--fg-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.filename || 'Secure note'}</div>
                                        {date && <div style={{ fontSize: 15, color: 'var(--fg-2)' }}>{date}</div>}
                                        <div style={{ fontSize: 15, color: 'var(--fg-2)', display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ width: 7, height: 7, borderRadius: '50%', background: isOnChain ? 'var(--ok)' : 'var(--warn)', display: 'inline-block' }} />{statusLabel}</div>
                                    </div>
                                    <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                                        <button className="v-btn" style={{ flex: 1, height: 50, justifyContent: 'center', fontSize: 15, gap: 7 }} onClick={() => viewNote(n)}>{IcoEye(17)} View</button>
                                        {isOnChain ? (<>
                                            <button className="v-btn" style={{ flex: 1, height: 50, justifyContent: 'center', fontSize: 15, gap: 7 }} onClick={() => { setTransferNote(n); setTransferTo(''); }}>{IcoTransfer(17)} Transfer</button>
                                            <button className="v-btn v-btn-danger" style={{ flex: 1, height: 50, justifyContent: 'center', fontSize: 15, gap: 7 }} onClick={() => { setBurnNote(n); setBurnConfirm(''); }}>{IcoBurn(17)} Burn</button>
                                        </>) : (
                                            <button className="v-btn" style={{ flex: 1, height: 50, justifyContent: 'center', fontSize: 15, gap: 7 }} disabled>NFT actions unavailable</button>
                                        )}
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* CREATE MODAL */}
            {showCreate && (
                <div className="v-modal-backdrop" role="presentation" onClick={() => { if (stage === 'idle') closeCreate(); }}>
                    <div className="v-modal" role="dialog" aria-modal="true" aria-label="Create secure note" style={{ width: 500 }} onClick={e => e.stopPropagation()}>
                        <div className="v-row" style={{ justifyContent: 'space-between', marginBottom: 16 }}>
                            <div><h3>New Secure Note</h3><div className="sub" style={{ margin: 0 }}>Encrypted with AES-256 · stored in your vault</div></div>
                            {(stage === 'idle' || stage === 'complete' || stage === 'cancelled') && (
                                <button className="v-iconbtn" aria-label="Close create dialog" onClick={closeCreate}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
                            )}
                        </div>

                        {stage === 'idle' && (<>
                            <style>{`.sn-textarea { width:100%; min-height:140px; padding:14px 18px; padding-right:80px; background:var(--bg-1); border:1px solid var(--line); border-radius:10px; color:var(--fg-0); font-size:14px; font-family:var(--font-mono); resize:none; box-sizing:border-box; outline:none; transition:border-color .12s; line-height:1.6; } .sn-textarea.hidden-text { -webkit-text-security:disc; text-security:disc; } .sn-textarea:focus { border-color:var(--accent-line); }`}</style>
                            <div className="v-field" style={{ marginBottom: 14 }}><div className="v-label">Title</div><input className="v-input" value={title} onChange={e => setTitle(e.target.value)} placeholder="Kraken 2FA backup" /></div>
                            <div className="v-field" style={{ marginBottom: 14 }}>
                                <div className="v-label">Content</div>
                                <div style={{ position: 'relative' }}>
                                    <textarea className={`sn-textarea${hideContent ? ' hidden-text' : ''}`} value={content} onChange={e => setContent(e.target.value)} placeholder="Enter password, seed phrase or secret data..." rows={6} />
                                    <div style={{ position: 'absolute', top: 12, right: 14, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--fg-2)', fontSize: 13, cursor: 'pointer', userSelect: 'none' }} onClick={() => setHideContent(!hideContent)}>{IcoEye(15)} {hideContent ? 'Hidden' : 'Visible'}</div>
                                </div>
                            </div>
                            <div className="v-field" style={{ marginBottom: 20 }}><div className="v-label">Tag (optional)</div><input className="v-input" value={tag} onChange={e => setTag(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ''))} placeholder="password, seed, key, backup" /></div>
                            {error && <div className="error-box" style={{ marginBottom: 14 }}>{error}</div>}
                            <div className="v-row" style={{ justifyContent: 'flex-end', gap: 10 }}><button className="v-btn" onClick={closeCreate}>Cancel</button><button className="v-btn v-btn-primary" onClick={handleEncrypt} disabled={!title.trim() || !content.trim()}>{IcoLock(15)} Encrypt & Store</button></div>
                        </>)}

                        {/* ── PROCESSING: encrypting + registering ── */}
                        {(stage === 'encrypting' || stage === 'creating_payload') && (() => {
                            const steps = [
                                { key: 'encrypting', label: 'Encrypting', sub: 'AES-256 encryption', order: 1 },
                                { key: 'vault', label: 'Preparing vault', sub: 'Saving encrypted metadata', order: 2 },
                                                            ];
                            const currentOrder = stage === 'encrypting' ? 1 : 2;
                            const totalProgress = stage === 'encrypting' ? 25 : 75;
                            const statusMsg = stage === 'encrypting' ? 'Encrypting data...' : stage === 'creating_payload' ? 'Preparing vault...' : 'Saving secure note...';

                            return (<div>
                                {/* Title */}
                                <div style={{ textAlign: 'center', marginBottom: 20 }}>
                                    <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--fg-0)' }}>Saving secure note</div>
                                    <div style={{ fontSize: 14, color: 'var(--fg-2)', marginTop: 4 }}>Keep this window open</div>
                                </div>

                                {/* Progress bar */}
                                <div style={{ marginBottom: 20 }}>
                                    <div className="v-row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
                                        <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--fg-1)' }}>{statusMsg}</span>
                                        <span className="v-mono" style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-0)' }}>{totalProgress}%</span>
                                    </div>
                                    <div style={{ height: 6, background: 'var(--bg-1)', borderRadius: 3, overflow: 'hidden' }}>
                                        <div style={{ height: '100%', borderRadius: 3, background: 'linear-gradient(90deg, var(--accent), var(--accent-deep))', width: `${totalProgress}%`, transition: 'width 0.3s ease' }} />
                                    </div>
                                </div>

                                {/* Stepper */}
                                <div className="v-stepper" style={{ marginBottom: 20 }}>
                                    {steps.map(step => {
                                        const done = currentOrder > step.order;
                                        const active = currentOrder === step.order;
                                        return (
                                            <div key={step.key} className={`v-step${done ? ' done' : ''}${active ? ' active' : ''}`}>
                                                <div className="v-step-icon">
                                                    {done
                                                        ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12" /></svg>
                                                        : active
                                                            ? <div className="v-spin" style={{ width: 16, height: 16 }} />
                                                            : <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fg-3)' }} />
                                                    }
                                                </div>
                                                <div>
                                                    <div className="v-step-label">{step.label}</div>
                                                    <div className="v-step-sub">{step.sub}</div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>

                            </div>);
                        })()}

                        {stage === 'complete' && result && (() => {
                            const nftColor = getNftColors(result.nftTokenId, '#a855f7');
                            const idShort = `${result.nftTokenId.slice(0,6)}…${result.nftTokenId.slice(-4)}`;
                            const fmtSize = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`;
                            return (
                                <div style={{ display:'flex',flexDirection:'column',alignItems:'center',padding:'10px 0' }}>
                                    {/* NFT Portrait Card */}
                                    <div style={{
                                        width:300,borderRadius:'var(--radius-lg)',overflow:'hidden',
                                        border:`1px solid color-mix(in srgb, ${nftColor.stroke} 35%, transparent)`,
                                        background:'#060608',marginBottom:20,
                                        boxShadow:`0 0 50px color-mix(in srgb, ${nftColor.stroke} 12%, transparent)`,
                                    }}>
                                        {/* 2:3 image */}
                                        <div style={{
                                            width:'100%',aspectRatio:'2/3',
                                            backgroundImage: getNftImageUrl(result.nftTokenId, '#a855f7'),
                                            backgroundSize:'cover',backgroundPosition:'center',
                                        }}/>
                                        {/* Vault ID strip */}
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
                                        }}>Vault {idShort}</span>
                                        </div>
                                    </div>

                                    {/* Success info */}
                                    <div style={{textAlign:'center',marginBottom:20}}>
                                        <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:8,marginBottom:4}}>
                                            <div style={{width:22,height:22,borderRadius:'50%',background:'var(--ok-soft)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--ok)'}}>
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                                            </div>
                                            <span style={{fontSize:16,fontWeight:600,color:'var(--fg-1)'}}>Secure note saved</span>
                                        </div>
                                        <div className="v-mono" style={{fontSize:13,color:'var(--fg-3)'}}>
                                            {fmtSize(result.size)}
                                        </div>
                                    </div>

                                    {/* Action buttons */}
                                    <div style={{display:'flex',gap:10,width:300}}>
                                        <button className="v-btn v-btn-primary" style={{flex:1,justifyContent:'center',height:38,fontSize:13}} onClick={closeCreate}>
                                            Done
                                        </button>
                                        <button className="v-btn" style={{flex:1,justifyContent:'center',height:38,fontSize:13,background:'var(--bg-2)',border:'1px solid var(--line)',color:'var(--fg-2)'}} onClick={handleReset}>
                                            Create Another
                                        </button>
                                    </div>
                                </div>
                            );
                        })()}

                        {stage === 'cancelled' && (<div style={{ textAlign: 'center', padding: '30px 0' }}>
                            <div style={{ width: 56, height: 56, borderRadius: 14, background: 'var(--danger-soft)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16, color: 'var(--danger)' }}><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></div>
                            <p style={{ fontSize: 16, fontWeight: 600, margin: '0 0 6px' }}>Operation cancelled</p>
                            <div className="v-row" style={{ justifyContent: 'center', gap: 10, marginTop: 12 }}><button className="v-btn" onClick={closeCreate}>Close</button><button className="v-btn v-btn-primary" onClick={handleReset}>Try again</button></div>
                        </div>)}

                        {error && stage !== 'idle' && <div className="error-box" style={{ marginTop: 14 }}>{error}</div>}
                    </div>
                </div>
            )}

            {/* VIEW NOTE MODAL */}
            {viewingNote && (
                <div className="v-modal-backdrop" role="presentation">
                    <div className="v-modal" role="dialog" aria-modal="true" aria-label="View secure note" style={{ width: 500 }}>
                        <div className="v-row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                            <div><h3>Secure Note</h3><div className="sub" style={{ margin: 0 }}>Decrypted locally · auto-clears on close</div></div>
                            <button className="v-iconbtn" aria-label="Close note viewer" onClick={closeNoteViewer}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
                        </div>
                        {loadingNote ? (
                            <div style={{ textAlign: 'center', padding: '40px 0' }}><div className="spinner" style={{ width: 28, height: 28, margin: '0 auto 12px' }} /><p style={{ color: 'var(--fg-2)', margin: 0, fontSize: 14 }}>Decrypting...</p></div>
                        ) : noteContent ? (<>
                            <div style={{ background: 'var(--warn-soft)', borderRadius: 'var(--radius-md)', padding: '10px 14px', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ fontSize: 14 }}>⚠️</span><p style={{ fontSize: 13, color: 'var(--warn)', margin: 0 }}>Content is decrypted in memory only. Nothing is saved to disk.</p></div>
                            <div className="v-field" style={{ marginBottom: 16 }}>
                                <div className="v-row" style={{ justifyContent: 'space-between' }}><div className="v-label">Content</div><button onClick={() => setShowContent(!showContent)} style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', fontSize: 13, fontWeight: 500 }}>{IcoEye(15)} {showContent ? 'Hide' : 'Show'}</button></div>
                                <textarea className="v-textarea" rows={6} readOnly value={showContent ? noteContent.content : '•'.repeat(Math.min(noteContent.content.length, 50))} style={{ fontSize: 14, fontFamily: 'var(--font-mono)' }} />
                            </div>
                            <div className="v-row" style={{ justifyContent: 'flex-end', fontSize: 13, color: 'var(--fg-2)' }}>
                                <div className="v-row" style={{ gap: 8 }}>
                                    <button className="v-btn v-btn-primary" onClick={closeNoteViewer}>Done</button>
                                </div>
                            </div>
                        </>) : null}
                    </div>
                </div>
            )}

            {/* TRANSFER MODAL */}
            {transferNote && (
                <div className="v-modal-backdrop" role="presentation" onClick={() => { if (!transferring) { setTransferNote(null); setTransferQr(null); } }}>
                    <div className="v-modal" role="dialog" aria-modal="true" aria-label="Transfer note" style={{ width: 440 }} onClick={e => e.stopPropagation()}>
                        <div className="v-row" style={{ justifyContent: 'space-between', marginBottom: 16 }}><h3>{transferQr ? 'Sign Transfer' : 'Transfer Note'}</h3><button className="v-iconbtn" aria-label="Close transfer dialog" onClick={() => { setTransferNote(null); setTransferQr(null); setTransferring(false); }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
                        {transferQr ? (
                            <div style={{ textAlign: 'center' }}><div className="v-qr-wrap" style={{ margin: '0 auto 16px' }}><img src={transferQr} alt="QR" style={{ width: 180, height: 180, display: 'block' }} /></div><div className="v-row" style={{ justifyContent: 'center', gap: 8, color: 'var(--accent)', fontSize: 14 }}><div className="v-spin" /> Waiting for signature…</div></div>
                        ) : (<>
                            <div className="sub">Transfer this encrypted note to another wallet</div>
                            <div className="v-field" style={{ marginBottom: 16 }}><div className="v-label">Recipient address</div><input className="v-input" placeholder="r..." value={transferTo} onChange={e => setTransferTo(e.target.value)} style={{ fontFamily: 'var(--font-mono)' }} /></div>
                            <div className="v-row" style={{ justifyContent: 'flex-end' }}><button className="v-btn" onClick={() => setTransferNote(null)}>Cancel</button><button className="v-btn v-btn-primary" onClick={startTransfer} disabled={!transferTo.trim() || transferring}>{IcoTransfer(15)} {transferring ? '...' : 'Transfer'}</button></div>
                        </>)}
                    </div>
                </div>
            )}

            {/* BURN MODAL */}
            {burnNote && (
                <div className="v-modal-backdrop" role="presentation" onClick={() => { if (!burning) { setBurnNote(null); setBurnQr(null); } }}>
                    <div className="v-modal" role="dialog" aria-modal="true" aria-label="Burn note" style={{ width: 420 }} onClick={e => e.stopPropagation()}>
                        {burnQr ? (
                            <div style={{ textAlign: 'center' }}><h3 style={{ marginBottom: 14 }}>Burn Note</h3><div className="v-qr-wrap" style={{ margin: '0 auto 16px' }}><img src={burnQr} alt="QR" style={{ width: 180, height: 180, display: 'block' }} /></div><div className="v-row" style={{ justifyContent: 'center', gap: 8, color: 'var(--danger)', fontSize: 14 }}><div className="v-spin" style={{ borderTopColor: 'var(--danger)' }} /> Waiting for signature…</div></div>
                        ) : (<>
                            <div style={{ textAlign: 'center', marginBottom: 16 }}>
                                <div style={{ width: 56, height: 56, borderRadius: 14, background: 'var(--danger-soft)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 12, color: 'var(--danger)' }}>{IcoBurn(26)}</div>
                                <h3>Burn Note?</h3><div className="sub">This will permanently delete this encrypted note</div>
                            </div>
                            <div style={{ background: 'var(--danger-soft)', borderRadius: 'var(--radius-md)', padding: 14, marginBottom: 16, textAlign: 'center' }}><p style={{ fontSize: 13, color: 'var(--danger)', margin: 0 }}>This action cannot be undone. The NFT will be burned on XRPL.</p></div>
                            <div className="v-field" style={{ marginBottom: 16 }}><div className="v-label">Type DELETE to confirm</div><input className="v-input" value={burnConfirm} onChange={e => setBurnConfirm(e.target.value)} placeholder="DELETE" autoFocus style={{ fontFamily: 'var(--font-mono)' }} /></div>
                            <div className="v-row" style={{ justifyContent: 'flex-end' }}><button className="v-btn" onClick={() => setBurnNote(null)}>Cancel</button><button className="v-btn v-btn-danger" onClick={startBurn} disabled={burnConfirm !== 'DELETE' || burning} style={burnConfirm === 'DELETE' ? { background: 'var(--danger)', color: '#fff', borderColor: 'transparent' } : {}}>{burning ? '...' : 'Burn & Delete'}</button></div>
                        </>)}
                    </div>
                </div>
            )}
        </div>
    );
}
