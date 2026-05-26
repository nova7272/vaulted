import { useCallback, useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { QrCode } from '../components/QrCode'
import { formatError } from '../utils/formatError'

interface WalletOverview {
    classicAddress: string
    network: string
    status: string
    connected: boolean
    funded: boolean
    balanceXrp: string | null
    reserveRequirementXrp: string
    actionHint: string
    actionLabel: string | null
    actionUrl: string | null
}

interface WalletHistoryItem {
    txHash: string
    transactionType: string
    direction: string | null
    amountXrp: string | null
    counterparty: string | null
    ledgerIndex: number | null
    date: string | null
    status: string
}

interface SendXrpPaymentResponse {
    engineResult: string
    engineResultMessage: string
    txHash: string
}

function shortHash(value: string) {
    if (value.length <= 16) return value
    return `${value.slice(0, 8)}…${value.slice(-8)}`
}

function shortAddress(value: string | null) {
    if (!value) return '—'
    if (value.length <= 14) return value
    return `${value.slice(0, 6)}…${value.slice(-6)}`
}

function formatDate(value: string | null) {
    if (!value) return '—'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleString()
}

function validateAmount(value: string) {
    const trimmed = value.trim()
    if (!trimmed) return 'Amount is required.'
    if (!/^\d+(\.\d{1,6})?$/.test(trimmed)) return 'Enter a positive XRP amount with at most 6 decimals.'
    const numeric = Number(trimmed)
    if (!Number.isFinite(numeric) || numeric <= 0) return 'Amount must be greater than 0 XRP.'
    return null
}

function validateDestination(value: string) {
    const trimmed = value.trim()
    if (!trimmed) return 'Destination is required.'
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(trimmed)) return 'Enter a valid XRPL classic address.'
    return null
}

function validateDestinationTag(value: string) {
    const trimmed = value.trim()
    if (!trimmed) return null
    if (!/^\d+$/.test(trimmed)) return 'Destination tag must be a non-negative integer.'
    const numeric = Number(trimmed)
    if (!Number.isSafeInteger(numeric) || numeric > 4294967295) return 'Destination tag must be 4294967295 or less.'
    return null
}

export default function WalletScreen() {
    const [overview, setOverview] = useState<WalletOverview | null>(null)
    const [history, setHistory] = useState<WalletHistoryItem[]>([])
    const [overviewLoading, setOverviewLoading] = useState(false)
    const [historyLoading, setHistoryLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [copied, setCopied] = useState(false)
    const [sendDestination, setSendDestination] = useState('')
    const [sendAmount, setSendAmount] = useState('')
    const [sendDestinationTag, setSendDestinationTag] = useState('')
    const [sendError, setSendError] = useState<string | null>(null)
    const [sendResult, setSendResult] = useState<SendXrpPaymentResponse | null>(null)
    const [confirmingSend, setConfirmingSend] = useState(false)
    const [sending, setSending] = useState(false)

    const refreshOverview = useCallback(async () => {
        try {
            setOverviewLoading(true)
            setError(null)
            setOverview(await invoke<WalletOverview>('get_wallet_overview'))
        } catch (e) {
            setError(formatError(e))
        } finally {
            setOverviewLoading(false)
        }
    }, [])

    const refreshHistory = useCallback(async () => {
        try {
            setHistoryLoading(true)
            setError(null)
            setHistory(await invoke<WalletHistoryItem[]>('get_xrpl_transaction_history', { limit: 20 }))
        } catch (e) {
            setError(formatError(e))
        } finally {
            setHistoryLoading(false)
        }
    }, [])

    useEffect(() => {
        void refreshOverview()
        void refreshHistory()
    }, [refreshOverview, refreshHistory])

    const copyAddress = async () => {
        if (!overview?.classicAddress) return
        await navigator.clipboard.writeText(overview.classicAddress)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1800)
    }

    const validateSendForm = () => {
        return validateDestination(sendDestination)
            || validateAmount(sendAmount)
            || validateDestinationTag(sendDestinationTag)
            || (!overview?.funded ? 'Wallet must be funded before sending XRP.' : null)
    }

    const requestSendConfirmation = () => {
        const validation = validateSendForm()
        setSendResult(null)
        setSendError(validation)
        setConfirmingSend(!validation)
    }

    const submitSend = async () => {
        const validation = validateSendForm()
        if (validation) {
            setSendError(validation)
            setConfirmingSend(false)
            return
        }
        try {
            setSending(true)
            setSendError(null)
            const result = await invoke<SendXrpPaymentResponse>('send_xrp_payment', {
                request: {
                    destination: sendDestination.trim(),
                    amountXrp: sendAmount.trim(),
                    destinationTag: sendDestinationTag.trim() || null,
                },
            })
            setSendResult(result)
            setConfirmingSend(false)
            if (result.engineResult.startsWith('tes')) {
                setSendDestination('')
                setSendAmount('')
                setSendDestinationTag('')
                await Promise.all([refreshOverview(), refreshHistory()])
            }
        } catch (e) {
            setSendError(formatError(e))
        } finally {
            setSending(false)
        }
    }

    const statusClass = overview?.funded ? 'ok' : overview?.connected ? 'warn' : 'syncing'

    return (
        <div className="wallet-screen">
            <div className="wallet-grid">
                <section className="wallet-panel wallet-summary">
                    <div className="wallet-panel-head">
                        <div>
                            <h2>Vaulted XRPL Wallet</h2>
                            <p>Receive testnet XRP and inspect recent public ledger activity.</p>
                        </div>
                        <button className="v-btn-secondary" onClick={refreshOverview} disabled={overviewLoading}>
                            {overviewLoading ? 'Refreshing…' : 'Refresh'}
                        </button>
                    </div>

                    {error && <div className="wallet-error">{error}</div>}

                    <div className="wallet-balance-row">
                        <div>
                            <div className="wallet-label">Balance</div>
                            <div className="wallet-balance">
                                {overview?.balanceXrp ?? '—'} <span>XRP</span>
                            </div>
                        </div>
                        <div className={`wallet-status ${statusClass}`}>
                            <span />
                            {overview?.status?.replaceAll('_', ' ') ?? 'checking'}
                        </div>
                    </div>

                    <div className="wallet-facts">
                        <div>
                            <span>Network</span>
                            <strong>{overview?.network ?? '—'}</strong>
                        </div>
                        <div>
                            <span>Reserve</span>
                            <strong>{overview?.reserveRequirementXrp ?? '—'} XRP</strong>
                        </div>
                        <div>
                            <span>Connection</span>
                            <strong>{overview?.connected ? 'Connected' : 'Checking'}</strong>
                        </div>
                    </div>

                    {overview && !overview.funded && (
                        <div className="wallet-faucet">
                            <div>
                                <strong>Wallet is not funded yet</strong>
                                <p>{overview.actionHint}</p>
                            </div>
                            {overview.actionUrl && (
                                <a className="v-btn-secondary" href={overview.actionUrl} target="_blank" rel="noreferrer">
                                    {overview.actionLabel || 'Open faucet'}
                                </a>
                            )}
                        </div>
                    )}
                </section>

                <section className="wallet-panel wallet-send">
                    <div className="wallet-panel-head">
                        <div>
                            <h2>Send XRP</h2>
                            <p>Send testnet XRP from your local Vaulted wallet.</p>
                        </div>
                    </div>

                    <div className="wallet-send-form">
                        <label>
                            <span>Destination</span>
                            <input
                                value={sendDestination}
                                onChange={event => setSendDestination(event.target.value)}
                                placeholder="r..."
                                disabled={sending}
                                autoComplete="off"
                            />
                        </label>
                        <div className="wallet-send-row">
                            <label>
                                <span>Amount XRP</span>
                                <input
                                    value={sendAmount}
                                    onChange={event => setSendAmount(event.target.value)}
                                    placeholder="0.000001"
                                    inputMode="decimal"
                                    disabled={sending}
                                    autoComplete="off"
                                />
                            </label>
                            <label>
                                <span>Destination tag</span>
                                <input
                                    value={sendDestinationTag}
                                    onChange={event => setSendDestinationTag(event.target.value)}
                                    placeholder="Optional"
                                    inputMode="numeric"
                                    disabled={sending}
                                    autoComplete="off"
                                />
                            </label>
                        </div>

                        {sendError && <div className="wallet-error">{sendError}</div>}

                        {confirmingSend && (
                            <div className="wallet-confirm">
                                <strong>Confirm testnet XRP send</strong>
                                <span>Destination: <code>{shortAddress(sendDestination.trim())}</code></span>
                                <span>Amount: {sendAmount.trim()} XRP</span>
                                {sendDestinationTag.trim() && <span>Destination tag: {sendDestinationTag.trim()}</span>}
                                <span>Reserve kept: {overview?.reserveRequirementXrp ?? '10'} XRP plus network fee.</span>
                                <div className="wallet-send-actions">
                                    <button className="v-btn-secondary" onClick={() => setConfirmingSend(false)} disabled={sending}>Cancel</button>
                                    <button className="v-btn-vaulted" onClick={submitSend} disabled={sending}>
                                        {sending ? 'Submitting…' : 'Confirm send'}
                                    </button>
                                </div>
                            </div>
                        )}

                        {sendResult && (
                            <div className="wallet-send-result">
                                <span>{sendResult.engineResult}</span>
                                <p>{sendResult.engineResultMessage || 'XRPL submit completed.'}</p>
                                <code>{sendResult.txHash || 'No transaction hash returned'}</code>
                            </div>
                        )}

                        {!confirmingSend && (
                            <button className="v-btn-vaulted wallet-send-submit" onClick={requestSendConfirmation} disabled={sending || !overview?.funded}>
                                {sending ? 'Submitting…' : 'Review send'}
                            </button>
                        )}
                    </div>
                </section>

                <section className="wallet-panel wallet-receive">
                    <div className="wallet-panel-head">
                        <div>
                            <h2>Receive</h2>
                            <p>QR encodes only your public XRPL classic address.</p>
                        </div>
                    </div>
                    <div className="wallet-qr-wrap">
                        {overview?.classicAddress ? (
                            <QrCode value={overview.classicAddress} label="XRPL receive address" size={210} />
                        ) : (
                            <div className="wallet-qr-placeholder">Loading</div>
                        )}
                    </div>
                    <div className="wallet-address-box">
                        <span>{overview?.classicAddress ?? '—'}</span>
                        <button className="v-btn-secondary" onClick={copyAddress} disabled={!overview?.classicAddress}>
                            {copied ? 'Copied' : 'Copy'}
                        </button>
                    </div>
                </section>
            </div>

            <section className="wallet-panel wallet-history">
                <div className="wallet-panel-head">
                    <div>
                        <h2>Transaction History</h2>
                        <p>Compact public rows from XRPL account_tx.</p>
                    </div>
                    <button className="v-btn-secondary" onClick={refreshHistory} disabled={historyLoading}>
                        {historyLoading ? 'Refreshing…' : 'Refresh'}
                    </button>
                </div>

                <div className="wallet-history-table">
                    <div className="wallet-history-head">
                        <span>Hash</span>
                        <span>Type</span>
                        <span>Direction</span>
                        <span>Amount</span>
                        <span>Counterparty</span>
                        <span>Ledger</span>
                        <span>Status</span>
                    </div>
                    {history.length === 0 && (
                        <div className="wallet-history-empty">
                            {historyLoading ? 'Loading recent ledger activity…' : 'No recent transactions found.'}
                        </div>
                    )}
                    {history.map(item => (
                        <div className="wallet-history-row" key={item.txHash}>
                            <span className="mono" title={item.txHash}>{shortHash(item.txHash)}</span>
                            <span>{item.transactionType}</span>
                            <span>{item.direction ?? '—'}</span>
                            <span>{item.amountXrp ? `${item.amountXrp} XRP` : '—'}</span>
                            <span className="mono" title={item.counterparty ?? undefined}>{shortAddress(item.counterparty)}</span>
                            <span title={formatDate(item.date)}>{item.ledgerIndex ?? '—'}</span>
                            <span>{item.status}</span>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    )
}
