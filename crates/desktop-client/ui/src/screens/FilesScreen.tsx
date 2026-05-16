import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { save } from '@tauri-apps/plugin-dialog'

import { toast } from '../components/Toast'
import { QrCode } from '../components/QrCode'
import { useActivityLog } from '../contexts/ActivityLogContext'

interface NftInfo { nftTokenId:string; uri:string; filename:string|null; createdAt:string|null; fileStatus:string; preKeyMismatch?:boolean; preKeyOwner?:string|null }
interface FilesScreenProps { onNavigate:(s:'files'|'upload'|'settings')=>void; searchQuery?:string; oracleConnected?:boolean }
interface SigningRequestPayload { uuid:string; qrPng:string; websocketUrl:string }
interface TransferResult { transferId:string; status:string; signingRequest:SigningRequestPayload|null }
interface IncomingOffer { offerIndex:string; nftTokenId:string; fromAddress:string; amount:string }
interface SecureNoteContent { nftTokenId:string; content:string; noteType:string; mimeType:string }
interface RecipientTrustInfo { recipientIdentityId:string; recipientEncryptionPublicKey:string; recipientEncryptionPublicKeyFingerprint?:string; displayFingerprint:string; trusted:boolean; trustLevel:string; trustSource?:string; trustedAt?:string|null; revokedAt?:string|null; activeRecipientEncryptionPublicKeyFingerprint?:string; keyRotationDetected?:boolean; trustedDifferentKeyFingerprint?:string|null; trustedDifferentKeyAt?:string|null }
interface GrantStartResult { grantRequestId:string; grantId:string; challenge:string; oracleUrl:string; expiresAt:string; grantContextHash:string; vaultObjectId:string; recipientIdentityId:string; qrPayload:unknown }
interface GrantApprovalStatus { status:string; identityId?:string|null; vaultObjectId?:string|null; grantId?:string|null; recipientIdentityId?:string|null; grantContextHash?:string|null; approvedByDeviceId?:string|null; approvalSignature?:string|null; createdGrantId?:string|null; approvedAt?:string|null; approved?:boolean }
interface IncomingGrantInfo { grantId:string; vaultObjectId:string; recipientIdentityId:string; permissions:unknown; expiresAt:string|null; status:string; nftTokenId:string|null; manifestHash:string|null; canDecryptKey:boolean; keyEnvelopeAlg:string }
interface OutgoingGrantInfo { grantId:string; vaultObjectId:string; recipientIdentityId:string; permissions:unknown; expiresAt:string|null; status:string; nftTokenId:string|null; manifestHash:string|null }
interface IncomingGrantPreview { grantId:string; vaultObjectId:string; nftTokenId:string; filename:string; size:number; mimeType:string; fragmentsCount:number }

const compactQrPayload = (payload: unknown): string => JSON.stringify(payload)
const grantDate = (value: string | null): Date | null => {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}
const isGrantExpired = (value: string | null): boolean => {
  const date = grantDate(value)
  return !!date && date.getTime() <= Date.now()
}
const isGrantExpiringSoon = (value: string | null): boolean => {
  const date = grantDate(value)
  if (!date) return false
  const remaining = date.getTime() - Date.now()
  return remaining > 0 && remaining <= 24 * 60 * 60 * 1000
}
const formatGrantExpiry = (value: string | null): string => {
  const date = grantDate(value)
  if (!date) return 'no expiration'
  const remaining = date.getTime() - Date.now()
  if (remaining <= 0) return 'expired'
  if (remaining < 60 * 60 * 1000) return `expires in ${Math.max(1, Math.ceil(remaining / 60000))} min`
  if (remaining < 24 * 60 * 60 * 1000) return `expires in ${Math.ceil(remaining / 3600000)} h`
  return `expires ${date.toLocaleString()}`
}
const formatQrExpiry = (value: string | null | undefined): string => {
  if (!value) return 'no expiration'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const remaining = date.getTime() - Date.now()
  if (remaining <= 0) return 'expired'
  if (remaining < 60 * 60 * 1000) return `expires in ${Math.max(1, Math.ceil(remaining / 60000))} min`
  if (remaining < 24 * 60 * 60 * 1000) return `expires in ${Math.ceil(remaining / 3600000)} h`
  return `expires ${date.toLocaleString()}`
}
const grantApprovalDone = (status: GrantApprovalStatus | null): boolean => !!status && (status.approved || !!status.createdGrantId || status.status.toLowerCase()==='approved')
const grantApprovalExpired = (status: GrantApprovalStatus | null, expiresAt?: string | null): boolean => {
  if (status?.status?.toLowerCase()==='expired') return true
  if (!expiresAt) return false
  const date = new Date(expiresAt)
  return !Number.isNaN(date.getTime()) && date.getTime() <= Date.now()
}
const toDatetimeLocalValue = (date: Date): string => {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000)
  return local.toISOString().slice(0, 16)
}

import { FilesScreenSkeleton } from '../components/SkeletonLoader'

const isSecureNote = (filename: string | null): boolean => filename?.toLowerCase().endsWith('.secure') ?? false

// Contour-based NFT image — same algorithm as Oracle nft_image.rs
import { getNftColors, getNftImageUrl } from '../utils/nft_image'

const IcoCopy=()=>(<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>)
const IcoRefresh=()=>(<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>)
const IcoClose=()=>(<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>)
const IcoEye=()=>(<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>)
const IcoEyeOff=()=>(<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>)

export default function FilesScreen({onNavigate,searchQuery=''}:FilesScreenProps) {
  const { addEntry } = useActivityLog()
  const [nfts,setNfts]=useState<NftInfo[]>([])
  const [loading,setLoading]=useState(true)
  const [error,setError]=useState<string|null>(null)
  const [downloading,setDownloading]=useState<string|null>(null)
  const [copiedId,setCopiedId]=useState<string|null>(null)
  const [transferNft,setTransferNft]=useState<NftInfo|null>(null)
  const [transferTo,setTransferTo]=useState('')
  const [transferring,setTransferring]=useState(false)
  const [transferQr,setTransferQr]=useState<string|null>(null)
  const [waitingSignature,setWaitingSignature]=useState(false)
  const [filterTag,setFilterTag]=useState<string|null>(null)
  const [filterExt,setFilterExt]=useState<string|null>(null)
  const [showFilters,setShowFilters]=useState(false)
  const [shareNft,setShareNft]=useState<NftInfo|null>(null)
  const [shareRecipient,setShareRecipient]=useState('')
  const [shareExpires,setShareExpires]=useState('')
  const [shareTrust,setShareTrust]=useState<RecipientTrustInfo|null>(null)
  const [checkingTrust,setCheckingTrust]=useState(false)
  const [trustingRecipient,setTrustingRecipient]=useState(false)
  const [revokingRecipientTrust,setRevokingRecipientTrust]=useState(false)
  const [startingGrant,setStartingGrant]=useState(false)
  const [grantResult,setGrantResult]=useState<GrantStartResult|null>(null)
  const [grantStatus,setGrantStatus]=useState<GrantApprovalStatus|null>(null)
  const [pollingGrant,setPollingGrant]=useState(false)
  const [grantPollError,setGrantPollError]=useState<string|null>(null)

  const [incomingGrants,setIncomingGrants]=useState<IncomingGrantInfo[]>([])
  const [outgoingGrants,setOutgoingGrants]=useState<OutgoingGrantInfo[]>([])
  const [downloadingGrant,setDownloadingGrant]=useState<string|null>(null)
  const [revokingGrant,setRevokingGrant]=useState<string|null>(null)

  const [incomingOffers,setIncomingOffers]=useState<IncomingOffer[]>([])
  const [claimingOffer,setClaimingOffer]=useState<string|null>(null)
  const [claimQr,setClaimQr]=useState<string|null>(null)
  const [claimedOffers,setClaimedOffers]=useState<Set<string>>(new Set())

  const [deleteNft,setDeleteNft]=useState<NftInfo|null>(null)
  const [deleting,setDeleting]=useState(false)
  const [burnQr,setBurnQr]=useState<string|null>(null)
  const [deleteConfirmText,setDeleteConfirmText]=useState('')

  // Secure Note viewer (RAM only)
  const [viewingNote,setViewingNote]=useState<NftInfo|null>(null)
  const [noteContent,setNoteContent]=useState<SecureNoteContent|null>(null)
  const [loadingNote,setLoadingNote]=useState(false)
  const [showContent,setShowContent]=useState(false)
  const [copiedContent,setCopiedContent]=useState(false)


  useEffect(()=>{load()},[])

  // Escape key closes modals
  useEffect(()=>{
    const handleEsc=(e:KeyboardEvent)=>{
      if(e.key!=='Escape')return
      if(viewingNote){closeNoteViewer();return}
      if(shareNft&&!startingGrant){closeShareModal();return}
      if(transferNft&&!transferring&&!waitingSignature){setTransferNft(null);setTransferTo('');setTransferQr(null);return}
      if(deleteNft&&!deleting){setDeleteNft(null);setDeleteConfirmText('');return}
    }
    document.addEventListener('keydown',handleEsc)
    return ()=>document.removeEventListener('keydown',handleEsc)
  })
  useEffect(()=>{
    if(!grantResult)return
    let cancelled=false
    let timer:ReturnType<typeof setTimeout>|null=null

    const poll=async()=>{
      try{
        setPollingGrant(true)
        const status=await invoke<GrantApprovalStatus>('poll_vaulted_file_grant_approval',{grantRequestId:grantResult.grantRequestId})
        if(cancelled)return
        setGrantStatus(status)
        setGrantPollError(null)
        if(grantApprovalDone(status)){
          toast({type:'success',title:'Grant approved',sub:status.createdGrantId ? `Grant ${status.createdGrantId.slice(0,8)}… is active` : 'Recipient grant is active'})
          addEntry('share','File grant approved',{status:'success',detail:`Recipient: ${grantResult.recipientIdentityId}`,nftTokenId:shareNft?.nftTokenId})
          load()
          return
        }
        if(grantApprovalExpired(status,grantResult.expiresAt)){
          setGrantPollError('This grant approval request expired before it was approved.')
          return
        }
        timer=setTimeout(poll,2500)
      }catch(e){
        if(cancelled)return
        setGrantPollError(String(e))
        timer=setTimeout(poll,5000)
      }finally{
        if(!cancelled)setPollingGrant(false)
      }
    }

    poll()
    return ()=>{
      cancelled=true
      if(timer)clearTimeout(timer)
    }
  // Polling intentionally keys off the active request only; addEntry/shareNft are read for UX metadata.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[grantResult])

  const load=async()=>{
    try{ setLoading(true);setError(null)
      const [list, offers, grants, outgoing]=await Promise.all([
        invoke<NftInfo[]>('list_my_nfts'),
        invoke<IncomingOffer[]>('get_incoming_offers').catch(()=>[]),
        invoke<IncomingGrantInfo[]>('list_incoming_vaulted_grants').catch(()=>[]),
        invoke<OutgoingGrantInfo[]>('list_outgoing_vaulted_grants').catch(()=>[])
      ])
      setNfts(list)
      setIncomingOffers(offers)
      setIncomingGrants(grants)
      setOutgoingGrants(outgoing)
    }catch(e){setError(String(e))}finally{setLoading(false)}
  }

  const download=async(nft:NftInfo)=>{
    try{
      setDownloading(nft.nftTokenId)
      const filename = nft.filename || `vault_${nft.nftTokenId.slice(-8)}`
      const outputPath = await save({
        defaultPath: filename,
        title: 'Save decrypted file'
      })
      if(!outputPath){
        setDownloading(null)
        return
      }
      const path=await invoke<string>('download_file',{nftTokenId:nft.nftTokenId,outputPath})
      toast({type:'success',title:'Downloaded!',sub:path})
      addEntry('download', `Downloaded ${nft.filename||'file'}`, {detail:path, nftTokenId:nft.nftTokenId})
    }catch(e){toast({type:'error',title:'Download failed',sub:String(e)}); addEntry('download',`Download failed: ${nft.filename||'file'}`,{status:'error',detail:String(e)})}
    finally{setDownloading(null)}
  }

  // View Secure Note in RAM
  const viewNote = async (nft: NftInfo) => {
    try {
      setViewingNote(nft)
      setLoadingNote(true)
      setShowContent(false)
      setNoteContent(null)
      const content = await invoke<SecureNoteContent>('decrypt_secure_note', { nftTokenId: nft.nftTokenId })
      setNoteContent(content)
    } catch (e) {
      toast({ type: 'error', title: 'Failed to decrypt', sub: String(e) })
      closeNoteViewer()
    } finally {
      setLoadingNote(false)
    }
  }

  // Close viewer and clear content from RAM
  const closeNoteViewer = () => {
    setViewingNote(null)
    setNoteContent(null)
    setShowContent(false)
    setCopiedContent(false)
  }

  // Copy content to clipboard
  const copyNoteContent = async () => {
    if (!noteContent?.content) return
    try {
      await navigator.clipboard.writeText(noteContent.content)
      setCopiedContent(true)
      toast({ type: 'success', title: 'Copied!', sub: 'Content copied to clipboard' })
      setTimeout(() => setCopiedContent(false), 2000)
    } catch (e) {
      toast({ type: 'error', title: 'Copy failed', sub: String(e) })
    }
  }

  const getNoteTypeLabel = (type: string): string => {
    switch(type) {
      case 'password': return '🔐 Password'
      case 'seed': return '🌱 Seed Phrase'
      case 'key': return '🔑 API Key'
      case 'note': return '📝 Note'
      case 'none': return '🔒 Secure'
      default: return '🔒 Secure'
    }
  }

  const copyId=async(id:string)=>{
    await navigator.clipboard.writeText(id)
    setCopiedId(id)
    toast({type:'info',title:'Copied!',sub:'NFT ID copied to clipboard'})
    setTimeout(()=>setCopiedId(null),2000)
  }

  const closeShareModal=()=>{
    setShareNft(null)
    setShareRecipient('')
    setShareExpires('')
    setShareTrust(null)
    setGrantResult(null)
    setGrantStatus(null)
    setGrantPollError(null)
    setPollingGrant(false)
    setCheckingTrust(false)
    setTrustingRecipient(false)
    setRevokingRecipientTrust(false)
    setStartingGrant(false)
  }

  const openShareModal=(nft:NftInfo)=>{
    setShareNft(nft)
    setShareRecipient('')
    setShareExpires('')
    setShareTrust(null)
    setGrantResult(null)
    setGrantStatus(null)
    setGrantPollError(null)
  }

  const checkRecipientTrust=async()=>{
    if(!shareRecipient.trim())return
    try{
      setCheckingTrust(true)
      const trust=await invoke<RecipientTrustInfo>('get_vaulted_recipient_key_trust',{recipientIdentityId:shareRecipient.trim()})
      setShareTrust(trust)
      toast({
        type:trust.trusted?'success':trust.keyRotationDetected?'warning':'info',
        title:trust.trusted?'Recipient key trusted':trust.keyRotationDetected?'Recipient key changed':'Verify recipient fingerprint',
        sub:trust.keyRotationDetected?'The recipient identity now advertises a different active encryption key. Confirm the new fingerprint before sharing.':undefined,
      })
    }catch(e){toast({type:'error',title:'Recipient lookup failed',sub:String(e)});setShareTrust(null)}
    finally{setCheckingTrust(false)}
  }

  const trustRecipient=async()=>{
    if(!shareRecipient.trim())return
    try{
      setTrustingRecipient(true)
      const trust=await invoke<RecipientTrustInfo>('trust_vaulted_recipient_key',{recipientIdentityId:shareRecipient.trim(), trustSource:'desktop-fingerprint-confirmation', trustLevel:'tofu'})
      setShareTrust(trust)
      toast({type:'success',title:'Recipient key trusted',sub:trust.displayFingerprint})
    }catch(e){toast({type:'error',title:'Trust decision failed',sub:String(e)})}
    finally{setTrustingRecipient(false)}
  }

  const revokeRecipientTrust=async()=>{
    if(!shareRecipient.trim()||!shareTrust)return
    if(!window.confirm('Revoke trust for this recipient key fingerprint? Existing grants remain active until they expire or are revoked separately.'))return
    try{
      setRevokingRecipientTrust(true)
      const trust=await invoke<RecipientTrustInfo>('revoke_vaulted_recipient_key_trust',{
        recipientIdentityId:shareRecipient.trim(),
        recipientEncryptionPublicKeyFingerprint:shareTrust.recipientEncryptionPublicKeyFingerprint || undefined,
      })
      setShareTrust(trust)
      toast({type:'success',title:'Recipient key trust revoked',sub:trust.displayFingerprint})
    }catch(e){toast({type:'error',title:'Revoke trust failed',sub:String(e)})}
    finally{setRevokingRecipientTrust(false)}
  }

  const startShareGrant=async()=>{
    if(!shareNft||!shareRecipient.trim())return
    try{
      setStartingGrant(true)
      const expiresAt=shareExpires ? new Date(shareExpires) : null
      if(expiresAt && expiresAt.getTime() <= Date.now()){
        toast({type:'error',title:'Expiration must be in the future',sub:'Choose a later date/time or leave expiration empty.'})
        return
      }
      const expiresIso=expiresAt ? expiresAt.toISOString() : null
      const result=await invoke<GrantStartResult>('start_vaulted_file_grant_for_nft',{
        nftTokenId:shareNft.nftTokenId,
        recipientIdentityId:shareRecipient.trim(),
        permissions:['read'],
        grantExpiresAt:expiresIso,
        humanSummary:`Read access to ${shareNft.filename||shareNft.nftTokenId}`,
        requireTrustedRecipient:true,
      })
      setGrantResult(result)
      setGrantStatus({status:'pending',grantId:result.grantId,vaultObjectId:result.vaultObjectId,recipientIdentityId:result.recipientIdentityId,grantContextHash:result.grantContextHash,approved:false})
      setGrantPollError(null)
      toast({type:'success',title:'Grant approval started',sub:'Scan or copy the approval payload on a trusted device'})
      addEntry('share',`Started grant for ${shareNft.filename||'file'}`,{nftTokenId:shareNft.nftTokenId,detail:`Recipient: ${shareRecipient.trim()}`})
    }catch(e){toast({type:'error',title:'Share failed',sub:String(e)})}
    finally{setStartingGrant(false)}
  }

  const copyGrantPayload=async()=>{
    if(!grantResult)return
    await navigator.clipboard.writeText(compactQrPayload(grantResult.qrPayload))
    toast({type:'success',title:'Approval payload copied'})
  }


  const downloadIncomingGrant=async(grant:IncomingGrantInfo)=>{
    try{
      setDownloadingGrant(grant.grantId)
      let preview:IncomingGrantPreview|null=null
      try{ preview=await invoke<IncomingGrantPreview>('preview_incoming_vaulted_grant',{grantId:grant.grantId}) }catch{ preview=null }
      const outputPath=await save({
        defaultPath: preview?.filename || `vaulted_grant_${grant.grantId.slice(0,8)}`,
        title:'Save shared decrypted file'
      })
      if(!outputPath){setDownloadingGrant(null);return}
      const path=await invoke<string>('download_incoming_vaulted_grant',{grantId:grant.grantId,outputPath})
      toast({type:'success',title:'Shared file downloaded',sub:path})
      addEntry('download',`Downloaded shared file ${preview?.filename||grant.grantId.slice(0,8)}`,{detail:path,nftTokenId:grant.nftTokenId||undefined})
    }catch(e){toast({type:'error',title:'Shared download failed',sub:String(e)});addEntry('download',`Shared download failed`,{status:'error',detail:String(e)})}
    finally{setDownloadingGrant(null)}
  }

  const revokeOutgoingGrant=async(grant:OutgoingGrantInfo)=>{
    const shortId=grant.grantId.slice(0,8)
    if(!window.confirm(`Revoke grant ${shortId}? The recipient will lose grant-scoped access immediately.`))return
    try{
      setRevokingGrant(grant.grantId)
      await invoke<OutgoingGrantInfo>('revoke_vaulted_grant',{grantId:grant.grantId})
      setOutgoingGrants(prev=>prev.filter(g=>g.grantId!==grant.grantId))
      toast({type:'success',title:'Grant revoked',sub:`Grant ${shortId} is no longer active`})
      addEntry('share',`Revoked shared grant ${shortId}`,{status:'success',detail:`Recipient: ${grant.recipientIdentityId}`})
    }catch(e){
      toast({type:'error',title:'Revoke failed',sub:String(e)})
      addEntry('share',`Grant revoke failed`,{status:'error',detail:String(e)})
    }finally{
      setRevokingGrant(null)
    }
  }

  const transfer=async()=>{
    if(!transferNft||!transferTo.trim())return
    try{
      setTransferring(true)
      const result=await invoke<TransferResult>('initiate_transfer',{nftTokenId:transferNft.nftTokenId,toAddress:transferTo.trim()})
      if(result.signingRequest?.qrPng){
        setTransferQr(result.signingRequest.qrPng)
        toast({type:'info',title:'Vaulted signing',sub:'Approve the transfer with Vaulted wallet signing'})
        setWaitingSignature(true)
        try{
          await invoke('wait_for_transfer_offer',{
            payloadUuid: result.signingRequest.uuid,
            websocketUrl: result.signingRequest.websocketUrl,
            transferId: result.transferId,
            nftTokenId: transferNft.nftTokenId
          })
          toast({type:'success',title:'Offer created!',sub:'Waiting for recipient to accept'})
          addEntry('transfer_sent',`Sent ${transferNft.filename||'NFT'}`,{detail:`To: ${transferTo.slice(0,6)}...${transferTo.slice(-4)}`,nftTokenId:transferNft.nftTokenId})
          setTransferQr(null);setTransferNft(null);setTransferTo('')
          load()
        }catch(e){
          toast({type:'error',title:'Transfer failed',sub:String(e)})
        }finally{
          setWaitingSignature(false)
        }
      }else{
        toast({type:'warning',title:'Vaulted signing pending',sub:'Local XRPL transfer signing is not implemented yet'})
      }
    }catch(e){toast({type:'error',title:'Transfer failed',sub:String(e)})}
    finally{setTransferring(false)}
  }

  const claimOffer=async(offer:IncomingOffer)=>{
    setClaimingOffer(offer.offerIndex)
    setClaimQr(null)
    toast({type:'warning',title:'Vaulted signing pending',sub:'Local XRPL NFT claim signing is not implemented yet'})
    setClaimingOffer(null)
  }

  const deleteVault=async()=>{
    if(!deleteNft)return
    setDeleting(true)
    setBurnQr(null)
    toast({type:'warning',title:'Vaulted signing pending',sub:'Local XRPL NFT burn signing is not implemented yet'})
    setDeleting(false)
  }

  // Extract available tags and extensions for filter
  const availableTags = [...new Set(nfts.map(n => {
    const m = (n.filename||'').match(/\[([^\]]+)\]/)
    return m ? m[1].toLowerCase() : null
  }).filter(Boolean))] as string[]

  const availableExts = [...new Set(nfts.map(n => {
    const ext = (n.filename||'').split('.').pop()?.toLowerCase()
    return ext && ext !== n.filename?.toLowerCase() ? ext : null
  }).filter(Boolean))] as string[]

  const activeIncomingGrants=incomingGrants.filter(grant=>!isGrantExpired(grant.expiresAt))
  const activeOutgoingGrants=outgoingGrants.filter(grant=>!isGrantExpired(grant.expiresAt))
  const minShareExpiration=toDatetimeLocalValue(new Date(Date.now()+60*1000))

  const filtered=nfts.filter(n=>{
    // Hide secure notes from Files - they belong in Secure Notes screen
    if (isSecureNote(n.filename)) return false
    // Search filter
    if(searchQuery){
      const q=searchQuery.toLowerCase()
      if(!(n.filename||'').toLowerCase().includes(q)&&!n.nftTokenId.toLowerCase().includes(q))return false
    }
    // Tag filter
    if(filterTag){
      const m=(n.filename||'').match(/\[([^\]]+)\]/)
      const nTag=m?m[1].toLowerCase():null
      if(nTag!==filterTag)return false
    }
    // Extension filter
    if(filterExt){
      const ext=(n.filename||'').split('.').pop()?.toLowerCase()
      if(ext!==filterExt)return false
    }
    return true
  })

  if(loading)return(
      <div style={{maxWidth:1200,margin:'0 auto'}}>
        <div className="v-section-head" style={{marginBottom:18}}>
          <div>
            <div className="v-section-title">Vault</div>
            <div className="v-section-sub">Loading encrypted items…</div>
          </div>
          <div className="v-toolbar">
            <button className="v-btn" disabled><IcoRefresh />Refresh</button>
          </div>
        </div>
        <FilesScreenSkeleton />
      </div>
  )
  if(error)return(
      <div style={{padding:60,textAlign:'center'}}>
        <p style={{color:'#e07a6a',fontSize:18,marginBottom:24}}>{error}</p>
        <button onClick={load} className="btn-primary">Retry</button>
      </div>
  )

  return (
      <div style={{maxWidth:1200,margin:'0 auto'}}>
        {incomingOffers.filter(o=>!claimedOffers.has(o.offerIndex)).length>0 && (
            <div style={{marginBottom:20}}>
              <div className="v-section-title" style={{fontSize:15,marginBottom:10}}>Incoming offers</div>
              <div className="v-col" style={{gap:8}}>
                {incomingOffers.filter(o=>!claimedOffers.has(o.offerIndex)).map(offer=>(
                    <div key={offer.offerIndex} className="v-offer-card">
                      <div style={{width:36,height:36,borderRadius:8,background:'var(--accent-soft)',color:'var(--accent)',display:'flex',alignItems:'center',justifyContent:'center'}}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
                      </div>
                      <div className="v-col" style={{flex:1,gap:2}}>
                        <div className="title">NFT transfer from {offer.fromAddress.slice(0,6)}…{offer.fromAddress.slice(-4)}</div>
                        <div className="sub">{offer.nftTokenId.slice(0,16)}…</div>
                      </div>
                      <button className="v-btn" onClick={()=>{setIncomingOffers(prev=>prev.filter(o=>o.offerIndex!==offer.offerIndex));setClaimedOffers(prev=>new Set([...prev,offer.offerIndex]))}}>Dismiss</button>
                      <button className="v-btn v-btn-primary" onClick={()=>claimOffer(offer)} disabled={claimingOffer===offer.offerIndex}>
                        {claimingOffer===offer.offerIndex?'Claiming...':'Accept'}
                      </button>
                    </div>
                ))}
              </div>
            </div>
        )}


        {activeIncomingGrants.length>0 && (
            <div style={{marginBottom:20}}>
              <div className="v-section-title" style={{fontSize:15,marginBottom:10}}>Shared with me</div>
              <div className="v-col" style={{gap:8}}>
                {activeIncomingGrants.map(grant=>(
                    <div key={grant.grantId} className="v-offer-card">
                      <div style={{width:36,height:36,borderRadius:8,background:'rgba(80,200,140,0.12)',color:'#7ce0a3',display:'flex',alignItems:'center',justifyContent:'center'}}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-7"/><path d="M16 6l-4-4-4 4"/><path d="M12 2v13"/></svg>
                      </div>
                      <div className="v-col" style={{flex:1,gap:2,minWidth:0}}>
                        <div className="title">Shared vault grant</div>
                        <div className="sub" style={{wordBreak:'break-all'}}>
                          {grant.nftTokenId ? `${grant.nftTokenId.slice(0,16)}…` : grant.vaultObjectId}
                          {' · '}{grant.keyEnvelopeAlg}
                          {' · '}{formatGrantExpiry(grant.expiresAt)}
                        </div>
                      </div>
                      {isGrantExpiringSoon(grant.expiresAt) && <span className="v-badge warn">EXPIRING SOON</span>}
                      {!grant.canDecryptKey && <span className="v-badge err">KEY MISMATCH</span>}
                      <button className="v-btn v-btn-primary" onClick={()=>downloadIncomingGrant(grant)} disabled={!grant.canDecryptKey||downloadingGrant===grant.grantId}>
                        {downloadingGrant===grant.grantId?'Downloading...':'Open'}
                      </button>
                    </div>
                ))}
              </div>
            </div>
        )}

        {activeOutgoingGrants.length>0 && (
            <div style={{marginBottom:20}}>
              <div className="v-section-title" style={{fontSize:15,marginBottom:10}}>Active shares</div>
              <div className="v-col" style={{gap:8}}>
                {activeOutgoingGrants.map(grant=>(
                    <div key={grant.grantId} className="v-offer-card">
                      <div style={{width:36,height:36,borderRadius:8,background:'rgba(228,179,99,0.12)',color:'#e4b363',display:'flex',alignItems:'center',justifyContent:'center'}}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.59 13.51l6.83 3.98"/><path d="M15.41 6.51L8.59 10.49"/></svg>
                      </div>
                      <div className="v-col" style={{flex:1,gap:2,minWidth:0}}>
                        <div className="title">Shared access to recipient {grant.recipientIdentityId.slice(0,10)}…</div>
                        <div className="sub" style={{wordBreak:'break-all'}}>
                          {grant.nftTokenId ? `${grant.nftTokenId.slice(0,16)}…` : grant.vaultObjectId}
                          {' · '}{formatGrantExpiry(grant.expiresAt)}
                        </div>
                      </div>
                      {isGrantExpiringSoon(grant.expiresAt) && <span className="v-badge warn">EXPIRING SOON</span>}
                      <button className="v-btn" onClick={()=>revokeOutgoingGrant(grant)} disabled={revokingGrant===grant.grantId}>
                        {revokingGrant===grant.grantId?'Revoking…':'Revoke'}
                      </button>
                    </div>
                ))}
              </div>
            </div>
        )}


        <div className="v-section-head" style={{marginBottom:18}}>
          <div>
            <div className="v-section-title">Vault</div>
            <div className="v-section-sub">{filtered.length} encrypted NFTs{filterTag||filterExt?' (filtered)':''}</div>
          </div>
          <div className="v-toolbar">
            {/* Filter button */}
            <div style={{position:'relative'}}>
              <button
                  onClick={()=>setShowFilters(!showFilters)}
                  className={`v-btn${filterTag||filterExt?' active':''}`}
                  style={filterTag||filterExt?{background:'var(--accent-soft)',borderColor:'var(--accent-line)',color:'var(--accent)'}:{}}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                Filter
                {(filterTag||filterExt) && <span style={{width:5,height:5,borderRadius:'50%',background:'var(--accent)'}}/>}
              </button>

              {showFilters && (
                  <div style={{position:'absolute',top:'calc(100% + 6px)',right:0,background:'var(--bg-2)',border:'1px solid var(--line)',borderRadius:'var(--radius-md)',padding:14,minWidth:200,zIndex:100,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}>
                    <p className="v-label" style={{margin:'0 0 6px'}}>Tag</p>
                    <div style={{display:'flex',flexWrap:'wrap',gap:4,marginBottom:12}}>
                      <span className={`v-chip${!filterTag?' active':''}`} onClick={()=>setFilterTag(null)}>All</span>
                      {availableTags.map(t=>(
                          <span key={t} className={`v-chip${filterTag===t?' active':''}`} onClick={()=>setFilterTag(filterTag===t?null:t)} style={{textTransform:'uppercase'}}>{t}</span>
                      ))}
                    </div>
                    <p className="v-label" style={{margin:'0 0 6px'}}>Extension</p>
                    <div style={{display:'flex',flexWrap:'wrap',gap:4,marginBottom:12}}>
                      <span className={`v-chip${!filterExt?' active':''}`} onClick={()=>setFilterExt(null)}>All</span>
                      {availableExts.map(e=>(
                          <span key={e} className={`v-chip${filterExt===e?' active':''}`} onClick={()=>setFilterExt(filterExt===e?null:e)} style={{textTransform:'uppercase'}}>.{e}</span>
                      ))}
                    </div>
                    {(filterTag||filterExt) && (
                        <button className="v-btn" style={{width:'100%',justifyContent:'center'}} onClick={()=>{setFilterTag(null);setFilterExt(null)}}>Clear filters</button>
                    )}
                  </div>
              )}
            </div>

            <button onClick={load} className="v-btn"><IcoRefresh />Refresh</button>
          </div>
        </div>

        {filtered.length===0?(
            <div style={{textAlign:'center',padding:'80px 20px',background:'var(--bg-2)',borderRadius:'var(--radius-lg)',overflow:'visible',border:'1px solid var(--line)'}}>
              <div style={{width:72,height:72,borderRadius:18,background:'var(--bg-3)',display:'inline-flex',alignItems:'center',justifyContent:'center',marginBottom:20}}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--fg-2)" strokeWidth="1.5"><path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
              </div>
              <h3 style={{fontSize:18,fontWeight:600,color:'var(--fg-0)',margin:'0 0 8px'}}>No files yet</h3>
              <p style={{fontSize:13,color:'var(--fg-2)',margin:'0 0 20px'}}>Upload your first file to get started</p>
              <button onClick={()=>onNavigate('upload')} className="v-btn v-btn-primary">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                Upload
              </button>
            </div>
        ):(
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gridAutoRows:'1fr',gap:14}}>
              {filtered.map(nft=>{
                const name=nft.filename||`Vault Asset #${nft.nftTokenId.slice(-6)}`
                const isSecure = isSecureNote(nft.filename)
                const mintDate = nft.createdAt ? new Date(nft.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : null

                // Определяем тип файла и иконку
                // Извлекаем тег из имени файла (формат: filename[tag].ext)
                const parseTag = () => {
                  if (!nft.filename) return null
                  const match = nft.filename.match(/\[([^\]]+)\]/)
                  if (match) return match[1].toLowerCase()
                  return null
                }
                const tag = parseTag()

                // ===== GRID VIEW — 2-column horizontal cards =====
                const isDeleted = nft.fileStatus === 'deleted'
                const cleanName = name.replace(/\[[^\]]+\]/g,'').trim()
                const hasExt = cleanName.includes('.') && cleanName.lastIndexOf('.') > 0
                const fileExt = hasExt ? cleanName.split('.').pop()?.toLowerCase() || '' : ''
                const baseName = hasExt ? cleanName.replace(/\.[^.]+$/, '') : cleanName
                const nftColor = getNftColors(nft.nftTokenId, '#3b82f6')
                const idLabel = `${nft.nftTokenId.slice(0,6)}…${nft.nftTokenId.slice(-4)}`

                return (
                    <div key={nft.nftTokenId}
                         style={{
                           display:'flex',background:'var(--bg-2)',border:'1px solid var(--line)',borderRadius:'var(--radius-lg)',overflow:'visible',
                           overflow:'hidden',
                           opacity: isDeleted ? 0.5 : 1,
                         }}>

                      {/* NFT strip left */}
                      <div style={{width:140,minWidth:140,position:'relative',backgroundImage:getNftImageUrl(nft.nftTokenId, '#3b82f6'),backgroundSize:'cover',backgroundPosition:'center',backgroundColor:'#060608'}}>
                        {isDeleted && <div style={{position:'absolute',top:0,left:0,right:0,bottom:0,background:'rgba(0,0,0,0.5)'}}/>}
                      </div>

                      {/* Vertical ID strip */}
                      <div
                          onClick={()=>copyId(nft.nftTokenId)}
                          title="Copy NFT ID"
                          style={{
                            width:34,minWidth:34,
                            background:`color-mix(in srgb, ${nftColor.stroke} 20%, #0a0c14)`,borderLeft:`1px solid color-mix(in srgb, ${nftColor.stroke} 50%, transparent)`,borderRight:`1px solid color-mix(in srgb, ${nftColor.stroke} 30%, transparent)`,
                            cursor:'pointer',
                            display:'flex',alignItems:'center',justifyContent:'center',
                            position:'relative',transition:'filter 0.15s',
                          }}
                          onMouseEnter={e=>(e.currentTarget.style.filter='brightness(1.5)')}
                          onMouseLeave={e=>(e.currentTarget.style.filter='none')}
                      >
                        <div style={{
                          writingMode:'vertical-rl',textOrientation:'mixed',
                          transform:'rotate(180deg)',
                          fontSize:13,fontFamily:'var(--font-mono)',fontWeight:700,
                          color:'rgba(255,255,255,0.85)',letterSpacing:'0.05em',
                          whiteSpace:'nowrap',userSelect:'none',
                        }}>
                          {copiedId===nft.nftTokenId ? '✓ COPIED' : `NFT ${idLabel}`}
                        </div>
                      </div>

                      {/* Card body */}
                      <div style={{flex:1,padding:'22px 24px',display:'flex',flexDirection:'column',justifyContent:'space-between',minWidth:0,minHeight:160,position:'relative'}}>
                        {/* Tag — top right corner */}
                        {tag && (
                            <span style={{position:'absolute',top:14,right:16,padding:'4px 12px', fontSize:13, fontFamily:'var(--font-mono)', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.05em', borderRadius:6,
                              background:'rgba(106,160,255,0.12)', color:'#7ba3e0',
                            }}>{tag}</span>
                        )}

                        <div style={{display:'flex',flexDirection:'column',gap:8}}>
                          <div className="v-file-name" style={{fontSize:19,flexWrap:'wrap',gap:8}}>
                            <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{baseName}</span>
                            {fileExt && !isSecure && <span className="v-ext" style={{fontSize:17}}>.{fileExt}</span>}
                            {isDeleted && <span className="v-badge err" style={{fontSize:11}}>DELETED</span>}
                          </div>

                          {mintDate && <div style={{fontSize:15,color:'var(--fg-2)'}}>{mintDate}</div>}

                          {isDeleted ? (
                              <span className="v-file-status burned" style={{fontSize:15}}>
                                  <span className="dot" style={{background:'var(--fg-3)',boxShadow:'none'}}/>
                                  Burned · no longer accessible
                                </span>
                          ) : nft.preKeyMismatch ? (
                              <span className="v-file-status warn" style={{fontSize:15}}>
                                  <span className="dot"/>
                                  Vaulted keys: different owner
                                </span>
                          ) : (
                              <span className="v-file-status" style={{fontSize:15}}>
                                  <span className="dot"/>
                                  Encrypted · Owner
                                </span>
                          )}
                        </div>

                        {/* Buttons — full width with icons */}
                        <div style={{display:'flex',gap:8,marginTop:14}}>
                          {isDeleted ? (
                              <button className="v-btn v-btn-danger" style={{height:50,justifyContent:'center',fontSize:15,gap:7,padding:'0 24px'}}
                                      onClick={()=>{setDeleteNft(nft);setDeleteConfirmText('')}}>
                                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>
                                Burn
                              </button>
                          ) : (
                              <>
                                {isSecure ? (
                                    <button className="v-btn" style={{flex:1,height:50,justifyContent:'center',fontSize:15,gap:7}}
                                            onClick={()=>viewNote(nft)}>
                                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                      View
                                    </button>
                                ) : (
                                    <button className="v-btn" style={{flex:1,height:50,justifyContent:'center',fontSize:15,gap:7}}
                                            onClick={()=>download(nft)}
                                            disabled={downloading===nft.nftTokenId||!!nft.preKeyMismatch}>
                                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                      {downloading===nft.nftTokenId?'...':'Download'}
                                    </button>
                                )}
                                <button className="v-btn" style={{flex:1,height:50,justifyContent:'center',fontSize:15,gap:7}}
                                        onClick={()=>openShareModal(nft)}>
                                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
                                  Share
                                </button>
                                <button className="v-btn" style={{flex:1,height:50,justifyContent:'center',fontSize:15,gap:7}}
                                        onClick={()=>setTransferNft(nft)}>
                                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
                                  Transfer
                                </button>
                                <button className="v-btn v-btn-danger" style={{flex:1,height:50,justifyContent:'center',fontSize:15,gap:7}}
                                        onClick={()=>{setDeleteNft(nft);setDeleteConfirmText('')}}>
                                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>
                                  Burn
                                </button>
                              </>
                          )}
                        </div>
                      </div>
                    </div>
                )
              })}
            </div>
        )}

        {shareNft && (
            <div className="v-modal-backdrop" role="presentation" onClick={()=>{if(!startingGrant)closeShareModal()}}>
              <div className="v-modal" role="dialog" aria-modal="true" aria-label="Share file" style={{width:560}} onClick={e=>e.stopPropagation()}>
                <div className="v-row" style={{justifyContent:'space-between',marginBottom:16}}>
                  <h3>{grantResult?'Approve Grant':'Share encrypted access'}</h3>
                  <button className="v-iconbtn" aria-label="Close share dialog" onClick={closeShareModal}><IcoClose/></button>
                </div>

                {!grantResult ? (
                  <>
                    <p style={{fontSize:14,color:'#868b98',marginBottom:16}}>
                      Create a recipient-bound KeyEnvelope grant for <strong style={{color:'#f2f3f7'}}>{shareNft.filename||'Vault Asset'}</strong>. The file key is sealed locally to the recipient identity key.
                    </p>
                    <label className="v-label" style={{display:'block',marginBottom:8}}>Recipient Vaulted identity ID</label>
                    <input type="text" placeholder="vaulted identity id" value={shareRecipient} onChange={e=>{setShareRecipient(e.target.value);setShareTrust(null)}}
                           style={{width:'100%',padding:'12px 14px',borderRadius:10,border:'1px solid #262c3a',fontSize:13,marginBottom:12,outline:'none',fontFamily:'monospace',background:'#1f2430',color:'#f2f3f7'}} />
                    <label className="v-label" style={{display:'block',marginBottom:8}}>Expiration (optional)</label>
                    <input type="datetime-local" value={shareExpires} min={minShareExpiration} onChange={e=>setShareExpires(e.target.value)}
                           style={{width:'100%',padding:'12px 14px',borderRadius:10,border:'1px solid #262c3a',fontSize:13,marginBottom:6,outline:'none',background:'#1f2430',color:'#f2f3f7'}} />
                    <p style={{fontSize:12,color:'var(--fg-2)',margin:'0 0 14px'}}>Expired grants are hidden from active lists and rejected by the grant-scoped access endpoint.</p>

                    <div style={{display:'flex',gap:10,marginBottom:14}}>
                      <button className="v-btn" style={{flex:1,justifyContent:'center'}} onClick={checkRecipientTrust} disabled={!shareRecipient.trim()||checkingTrust}>{checkingTrust?'Checking…':'Check fingerprint'}</button>
                      <button className="v-btn v-btn-primary" style={{flex:1,justifyContent:'center'}} onClick={startShareGrant} disabled={!shareRecipient.trim()||!shareTrust?.trusted||startingGrant}>{startingGrant?'Starting…':'Start grant'}</button>
                    </div>

                    {shareTrust && (
                      <div style={{border:'1px solid var(--line)',borderRadius:12,padding:14,background:'var(--bg-3)',marginBottom:12}}>
                        <div style={{display:'flex',justifyContent:'space-between',gap:12,alignItems:'center',marginBottom:8}}>
                          <span style={{fontSize:13,color:'var(--fg-2)'}}>Recipient key fingerprint</span>
                          <span className={`v-badge ${shareTrust.trusted?'ok':'warn'}`}>{shareTrust.trusted?'TRUSTED':'UNTRUSTED'}</span>
                        </div>
                        <div style={{fontFamily:'var(--font-mono)',fontSize:14,color:'var(--fg-0)',wordBreak:'break-word',letterSpacing:'0.03em'}}>{shareTrust.displayFingerprint}</div>
                        <div style={{fontSize:12,color:'var(--fg-2)',marginTop:8}}>
                          {shareTrust.trusted
                            ? `Trusted${shareTrust.trustedAt ? ` at ${new Date(shareTrust.trustedAt).toLocaleString()}` : ''}`
                            : shareTrust.revokedAt
                              ? `Revoked at ${new Date(shareTrust.revokedAt).toLocaleString()}`
                              : 'Not trusted yet'}
                        </div>
                        {shareTrust.keyRotationDetected && !shareTrust.trusted && (
                          <div style={{marginTop:12,border:'1px solid rgba(228,179,99,.45)',borderRadius:10,padding:12,background:'rgba(228,179,99,.08)'}}>
                            <div style={{fontSize:12,fontWeight:700,color:'#e4b363',marginBottom:6}}>Recipient encryption key changed</div>
                            <p style={{fontSize:12,color:'#e9d7aa',margin:'0 0 8px'}}>
                              You previously trusted a different fingerprint for this recipient. This can be legitimate key rotation, but it can also indicate a wrong identity or compromised directory entry.
                            </p>
                            {shareTrust.trustedDifferentKeyFingerprint && (
                              <div style={{fontSize:11,color:'#c9a86a',fontFamily:'var(--font-mono)',wordBreak:'break-word'}}>Previous trusted: {shareTrust.trustedDifferentKeyFingerprint}</div>
                            )}
                            {shareTrust.trustedDifferentKeyAt && (
                              <div style={{fontSize:11,color:'var(--fg-2)',marginTop:4}}>Trusted at {new Date(shareTrust.trustedDifferentKeyAt).toLocaleString()}</div>
                            )}
                          </div>
                        )}
                        {!shareTrust.trusted ? (
                          <div style={{marginTop:12,display:'flex',gap:10,alignItems:'center'}}>
                            <p style={{fontSize:12,color:shareTrust.keyRotationDetected?'#e4b363':'#e4b363',margin:0,flex:1}}>
                              {shareTrust.keyRotationDetected
                                ? 'Confirm the new active fingerprint with the recipient over a trusted channel before sharing again.'
                                : 'Confirm this fingerprint with the recipient over a trusted channel before sharing.'}
                            </p>
                            <button className="v-btn" onClick={trustRecipient} disabled={trustingRecipient}>{trustingRecipient?'Saving…':shareTrust.keyRotationDetected?'Trust new key':'Trust key'}</button>
                          </div>
                        ) : (
                          <div style={{marginTop:12,display:'flex',gap:10,alignItems:'center'}}>
                            <p style={{fontSize:12,color:'var(--fg-2)',margin:0,flex:1}}>Revoking trust blocks future shares to this fingerprint until you confirm it again. It does not revoke already-created grants.</p>
                            <button className="v-btn" onClick={revokeRecipientTrust} disabled={revokingRecipientTrust}>{revokingRecipientTrust?'Revoking…':'Revoke trust'}</button>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <div>
                    <p style={{fontSize:14,color:'#868b98',marginBottom:14}}>Grant request is ready for trusted-device approval. Scan this QR with a paired Vaulted device, or copy the canonical payload for scanner/debug flows.</p>
                    <div style={{border:'1px solid var(--line)',borderRadius:12,padding:12,background:'var(--bg-3)',marginBottom:14}}>
                      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:10,marginBottom:8}}>
                        <div style={{fontSize:12,color:'var(--fg-2)'}}>Approval status</div>
                        <span className={`v-badge ${grantApprovalDone(grantStatus)?'ok':grantApprovalExpired(grantStatus,grantResult.expiresAt)?'err':'warn'}`}>
                          {grantApprovalDone(grantStatus)?'APPROVED':grantApprovalExpired(grantStatus,grantResult.expiresAt)?'EXPIRED':(grantStatus?.status||'PENDING').toUpperCase()}
                        </span>
                      </div>
                      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,fontSize:12,color:'var(--fg-2)'}}>
                        <div><strong style={{color:'var(--fg-0)'}}>Request</strong><br/>{grantResult.grantRequestId}</div>
                        <div><strong style={{color:'var(--fg-0)'}}>Expires</strong><br/>{formatQrExpiry(grantResult.expiresAt)}</div>
                        <div><strong style={{color:'var(--fg-0)'}}>Polling</strong><br/>{pollingGrant?'checking…':grantApprovalDone(grantStatus)||grantApprovalExpired(grantStatus,grantResult.expiresAt)?'stopped':'waiting for device'}</div>
                        <div><strong style={{color:'var(--fg-0)'}}>Created grant</strong><br/>{grantStatus?.createdGrantId||'not approved yet'}</div>
                      </div>
                      {grantStatus?.approvedByDeviceId && (
                        <div style={{fontSize:12,color:'var(--fg-2)',marginTop:10,wordBreak:'break-all'}}>
                          <strong style={{color:'var(--fg-0)'}}>Approved by device</strong><br/>{grantStatus.approvedByDeviceId}
                        </div>
                      )}
                      {grantStatus?.approvedAt && <div style={{fontSize:12,color:'var(--fg-2)',marginTop:8}}>Approved at {new Date(grantStatus.approvedAt).toLocaleString()}</div>}
                      {grantStatus?.approvalSignature && (
                        <details style={{marginTop:10}}>
                          <summary style={{fontSize:12,color:'var(--fg-2)',cursor:'pointer'}}>Approval signature</summary>
                          <div style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--fg-1)',wordBreak:'break-all',marginTop:6}}>{grantStatus.approvalSignature}</div>
                        </details>
                      )}
                      {grantPollError && <div style={{fontSize:12,color:'#e07a6a',marginTop:10}}>{grantPollError}</div>}
                    </div>
                    <div style={{display:'grid',gridTemplateColumns:'240px 1fr',gap:16,alignItems:'start',marginBottom:14}}>
                      <div style={{display:'flex',justifyContent:'center'}}>
                        <QrCode value={compactQrPayload(grantResult.qrPayload)} label="Vaulted grant approval QR" size={220} />
                      </div>
                      <div style={{border:'1px solid var(--line)',borderRadius:12,padding:12,background:'#11151f',maxHeight:240,overflow:'auto'}}>
                        <pre style={{margin:0,fontSize:11,color:'var(--fg-1)',whiteSpace:'pre-wrap',wordBreak:'break-word'}}>{JSON.stringify(grantResult.qrPayload,null,2)}</pre>
                      </div>
                    </div>
                    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,fontSize:12,color:'var(--fg-2)',marginBottom:14}}>
                      <div><strong style={{color:'var(--fg-0)'}}>Grant</strong><br/>{grantResult.grantId}</div>
                      <div><strong style={{color:'var(--fg-0)'}}>Vault object</strong><br/>{grantResult.vaultObjectId}</div>
                    </div>
                    <div style={{display:'flex',gap:10}}>
                      <button className="v-btn" style={{flex:1,justifyContent:'center'}} onClick={copyGrantPayload}>Copy payload</button>
                      <button className="v-btn" style={{flex:1,justifyContent:'center'}} onClick={load}>Refresh grants</button>
                      <button className="v-btn v-btn-primary" style={{flex:1,justifyContent:'center'}} onClick={closeShareModal}>{grantApprovalDone(grantStatus)?'Done':'Close'}</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
        )}

        {transferNft && (
            <div className="v-modal-backdrop" role="presentation" onClick={()=>{if(!transferring&&!waitingSignature){setTransferNft(null);setTransferTo('');setTransferQr(null)}}}>
              <div className="v-modal" role="dialog" aria-modal="true" aria-label="Transfer NFT" style={{width:440}} onClick={e=>e.stopPropagation()}>
                <div className="v-row" style={{justifyContent:'space-between',marginBottom:16}}>
                  <h3>{transferQr?'Sign Transfer':'Transfer NFT'}</h3>
                  <button className="v-iconbtn" aria-label="Close transfer dialog" onClick={()=>{setTransferNft(null);setTransferTo('');setTransferQr(null);setWaitingSignature(false);setTransferring(false)}}>
                    <IcoClose/>
                  </button>
                </div>

                {transferQr?(
                    <div style={{textAlign:'center'}}>
                      <p style={{fontSize:14,color:'#868b98',marginBottom:8}}>
                        Scan QR code to send <strong style={{color:'#f2f3f7'}}>{transferNft.filename||'Vault Asset'}</strong>
                      </p>
                      <p style={{fontSize:13,color:'#868b98',marginBottom:20,fontFamily:'monospace'}}>
                        To: {transferTo.slice(0,4)}...{transferTo.slice(-4)}
                      </p>
                      <img src={transferQr} alt="QR" style={{width:200,height:200,borderRadius:12,margin:'0 auto 20px',display:'block'}}/>
                      <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:12,marginBottom:16}}>
                        <div className="spinner" style={{width:18,height:18}}/>
                        <p style={{fontSize:13,color:'#6aa0ff',margin:0}}>Waiting for signature...</p>
                      </div>
                      <button onClick={()=>{setTransferNft(null);setTransferTo('');setTransferQr(null);setWaitingSignature(false);setTransferring(false)}} style={{padding:'10px 24px',borderRadius:10,border:'1px solid #555',background:'transparent',color:'#868b98',fontSize:13,fontWeight:500,cursor:'pointer'}}>Cancel Transfer</button>
                    </div>
                ):(
                    <>
                      <p style={{fontSize:14,color:'#868b98',marginBottom:20}}>
                        Transfer <strong style={{color:'#f2f3f7'}}>{transferNft.filename||'Vault Asset'}</strong> to another wallet
                      </p>
                      <input type="text" placeholder="Recipient wallet address (r...)" value={transferTo} onChange={e=>setTransferTo(e.target.value)}
                             style={{width:'100%',padding:'14px 16px',borderRadius:10,border:'1px solid #262c3a',fontSize:14,marginBottom:20,outline:'none',fontFamily:'monospace',background:'#1f2430',color:'#f2f3f7'}}
                             onFocus={e=>e.target.style.borderColor='#6aa0ff'} onBlur={e=>e.target.style.borderColor='#262c3a'}/>
                      <div style={{display:'flex',gap:10}}>
                        <button onClick={()=>{setTransferNft(null);setTransferTo('')}} style={{flex:1,padding:'12px',borderRadius:10,border:'none',background:'#1f2430',color:'#868b98',fontSize:14,fontWeight:500,cursor:'pointer'}}>Cancel</button>
                        <button onClick={transfer} disabled={!transferTo.trim()||transferring} style={{flex:1,padding:'12px',borderRadius:10,border:'none',background:!transferTo.trim()?'#262c3a':'#6aa0ff',color:'#fff',fontSize:14,fontWeight:500,cursor:transferTo.trim()?'pointer':'not-allowed'}}>{transferring?'Processing...':'Transfer'}</button>
                      </div>
                    </>
                )}
              </div>
            </div>
        )}

        {claimQr && (
            <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000}}>
              <div style={{background:'#262c3a',borderRadius:20,padding:28,width:'100%',maxWidth:380,textAlign:'center'}}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
                  <h3 style={{fontSize:20,fontWeight:600,color:'#f2f3f7',margin:0}}>Accept NFT</h3>
                  <button onClick={()=>{setClaimQr(null);setClaimingOffer(null)}} style={{background:'none',border:'none',cursor:'pointer',color:'#868b98',padding:4}}><IcoClose/></button>
                </div>
                <p style={{fontSize:14,color:'#868b98',marginBottom:20}}>Vaulted claim signing is pending</p>
                <img src={claimQr} alt="QR" style={{width:200,height:200,borderRadius:12,margin:'0 auto 20px',display:'block'}}/>
                <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:12,marginBottom:16}}>
                  <div className="spinner" style={{width:18,height:18}}/>
                  <p style={{fontSize:13,color:'#6ac79a',margin:0}}>Waiting for signature...</p>
                </div>
                <button onClick={()=>{setClaimQr(null);setClaimingOffer(null)}} style={{padding:'10px 24px',borderRadius:10,border:'1px solid #555',background:'transparent',color:'#868b98',fontSize:13,fontWeight:500,cursor:'pointer'}}>Cancel</button>
              </div>
            </div>
        )}

        {deleteNft && (
            <div className="v-modal-backdrop" role="presentation" onClick={()=>{if(!deleting&&!burnQr){setDeleteNft(null);setDeleteConfirmText('')}}}>
              <div className="v-modal" role="dialog" aria-modal="true" aria-label="Delete vault" style={{width:420}} onClick={e=>e.stopPropagation()}>
                {burnQr ? (
                    <div style={{textAlign:'center'}}>
                      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
                        <h3 style={{fontSize:20,fontWeight:600,color:'#f2f3f7',margin:0}}>Burn NFT</h3>
                        <button onClick={()=>{setBurnQr(null);setDeleteNft(null);setDeleteConfirmText('')}} style={{background:'none',border:'none',cursor:'pointer',color:'#868b98',padding:4}}><IcoClose/></button>
                      </div>
                      <p style={{fontSize:14,color:'#868b98',marginBottom:20}}>Vaulted burn signing is pending</p>
                      <img src={burnQr} alt="QR" style={{width:200,height:200,borderRadius:12,margin:'0 auto 20px',display:'block'}}/>
                      <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:12,marginBottom:16}}>
                        <div className="spinner" style={{width:18,height:18}}/>
                        <p style={{fontSize:13,color:'#e07a6a',margin:0}}>Waiting for signature...</p>
                      </div>
                      <button onClick={()=>{setBurnQr(null);setDeleteNft(null);setDeleteConfirmText('')}} style={{padding:'10px 24px',borderRadius:10,border:'1px solid #555',background:'transparent',color:'#868b98',fontSize:13,fontWeight:500,cursor:'pointer'}}>Cancel</button>
                    </div>
                ) : (
                    <>
                      <div style={{textAlign:'center',marginBottom:20}}>
                        <div style={{width:56,height:56,borderRadius:14,background:'rgba(239,68,68,0.15)',display:'inline-flex',alignItems:'center',justifyContent:'center',marginBottom:14,fontSize:28}}>
                          🔥
                        </div>
                        <h3 style={{fontSize:18,fontWeight:600,color:'#f2f3f7',margin:'0 0 8px'}}>Burn NFT?</h3>
                        <p style={{fontSize:14,color:'#868b98',margin:0}}>
                          This will permanently delete <strong style={{color:'#f2f3f7'}}>{deleteNft.filename||'this file'}</strong> and burn the NFT.
                        </p>
                      </div>
                      <div style={{background:'rgba(239,68,68,0.08)',borderRadius:10,padding:14,marginBottom:16}}>
                        <p style={{fontSize:12,color:'#e07a6a',margin:0,textAlign:'center'}}>
                          This action cannot be undone. The NFT will be burned on XRPL and all encrypted data will be permanently deleted.
                        </p>
                      </div>
                      <div style={{marginBottom:18}}>
                        <label style={{display:'block',fontSize:12,color:'#868b98',marginBottom:8}}>
                          Type <strong style={{color:'#f2f3f7',fontFamily:'monospace'}}>{deleteNft.filename ? deleteNft.filename.replace(/\[[^\]]+\]/g,'').trim().split('.')[0] : 'DELETE'}</strong> to confirm
                        </label>
                        <input
                            type="text"
                            value={deleteConfirmText}
                            onChange={e=>setDeleteConfirmText(e.target.value)}
                            placeholder="Type to confirm..."
                            autoFocus
                            style={{width:'100%',padding:'10px 14px',borderRadius:8,border:'1px solid #555',background:'#1f2430',color:'#f2f3f7',fontSize:14,outline:'none',boxSizing:'border-box',fontFamily:'monospace'}}
                            onFocus={e=>e.currentTarget.style.borderColor='#e07a6a'}
                            onBlur={e=>e.currentTarget.style.borderColor='#555'}
                        />
                      </div>
                      <div style={{display:'flex',gap:10}}>
                        <button onClick={()=>{setDeleteNft(null);setDeleteConfirmText('')}} disabled={deleting} style={{flex:1,padding:'12px',borderRadius:10,border:'none',background:'#1f2430',color:'#868b98',fontSize:14,fontWeight:500,cursor:'pointer'}}>Cancel</button>
                        <button
                            onClick={deleteVault}
                            disabled={deleting || deleteConfirmText !== (deleteNft.filename ? deleteNft.filename.replace(/\[[^\]]+\]/g,'').trim().split('.')[0] : 'DELETE')}
                            style={{flex:1,padding:'12px',borderRadius:10,border:'none',fontSize:14,fontWeight:500,cursor:'pointer',
                              ...(deleteConfirmText === (deleteNft.filename ? deleteNft.filename.replace(/\[[^\]]+\]/g,'').trim().split('.')[0] : 'DELETE')
                                  ? {background:'#e07a6a',color:'#fff'}
                                  : {background:'#555',color:'#888',cursor:'not-allowed'})
                            }}
                        >{deleting ? 'Processing...' : 'Burn & Delete'}</button>
                      </div>
                    </>
                )}
              </div>
            </div>
        )}

        {/* Secure Note Viewer Modal */}
        {viewingNote && (
            <div className="v-modal-backdrop" role="presentation">
              <div className="v-modal" role="dialog" aria-modal="true" aria-label="Secure note viewer" style={{width:480}} onClick={e=>e.stopPropagation()}>
                <div className="v-row" style={{justifyContent:'space-between',alignItems:'flex-start',marginBottom:16}}>
                  <div className="v-row" style={{gap:12}}>
                    <div style={{width:38,height:38,borderRadius:8,background:'rgba(99,102,241,0.15)',display:'flex',alignItems:'center',justifyContent:'center',color:'#818cf8'}}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                    </div>
                    <div>
                      <h3>{viewingNote.filename?.replace('.secure', '') || 'Secure Note'}</h3>
                      {noteContent && <div className="sub" style={{margin:0}}>{getNoteTypeLabel(noteContent.noteType)}</div>}
                    </div>
                  </div>
                  <button className="v-iconbtn" aria-label="Close note viewer" onClick={closeNoteViewer}><IcoClose/></button>
                </div>

                {loadingNote ? (
                    <div style={{textAlign:'center',padding:'40px 0'}}>
                      <div className="spinner" style={{width:28,height:28,margin:'0 auto 12px'}}/>
                      <p style={{color:'#868b98',margin:0,fontSize:13}}>Decrypting...</p>
                    </div>
                ) : noteContent ? (
                    <>
                      {/* Security notice */}
                      <div style={{background:'rgba(251,191,36,0.1)',border:'1px solid rgba(251,191,36,0.3)',borderRadius:10,padding:'10px 14px',marginBottom:16,display:'flex',alignItems:'center',gap:10}}>
                        <span style={{fontSize:16}}>🔒</span>
                        <p style={{fontSize:12,color:'#e6b35a',margin:0}}>Content is decrypted in memory only. Nothing is saved to disk.</p>
                      </div>

                      {/* Content area */}
                      <div style={{marginBottom:20}}>
                        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}>
                          <label style={{fontSize:11,fontWeight:500,color:'#868b98',textTransform:'uppercase',letterSpacing:'0.05em'}}>Content</label>
                          <button onClick={()=>setShowContent(!showContent)} style={{display:'flex',alignItems:'center',gap:6,background:'none',border:'none',cursor:'pointer',color:'#818cf8',fontSize:12,fontWeight:500}}>
                            {showContent ? <><IcoEyeOff/>Hide</> : <><IcoEye/>Show</>}
                          </button>
                        </div>
                        <div style={{
                          background:'#1f2430',
                          border:'1px solid #262c3a',
                          borderRadius:10,
                          padding:'14px 16px',
                          fontFamily:'monospace',
                          fontSize:14,
                          color:'#f2f3f7',
                          wordBreak:'break-all',
                          lineHeight:1.6,
                          minHeight:70,
                          whiteSpace:'pre-wrap'
                        }}>
                          {showContent ? noteContent.content : '•'.repeat(Math.min(noteContent.content.length, 40))}
                        </div>
                        <p style={{fontSize:10,color:'#868b98',margin:'6px 0 0'}}>{noteContent.content.length} characters</p>
                      </div>

                      {/* Actions */}
                      <div style={{display:'flex',gap:10}}>
                        <button onClick={closeNoteViewer} style={{flex:1,padding:'12px',borderRadius:10,border:'none',background:'#1f2430',color:'#868b98',fontSize:14,fontWeight:500,cursor:'pointer'}}>
                          Close
                        </button>
                        <button onClick={copyNoteContent} style={{flex:1,padding:'12px',borderRadius:10,border:'none',background:copiedContent?'#6ac79a':'#6366f1',color:'#fff',fontSize:14,fontWeight:500,cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center',gap:8}}>
                          <IcoCopy/>{copiedContent ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </>
                ) : null}
              </div>
            </div>
        )}
      </div>
  )
}