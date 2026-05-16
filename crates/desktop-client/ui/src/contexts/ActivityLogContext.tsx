/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import { listen } from '@tauri-apps/api/event'

export type ActivityType =
    | 'encrypt'
    | 'upload'
    | 'download'
    | 'decrypt'
    | 'transfer_sent'
    | 'transfer_received'
    | 'transfer_failed'
    | 'nft_claimed'
    | 'nft_burned'
    | 'file_deleted'
    | 'auth_login'
    | 'auth_logout'
    | 'info'

export type ActivityStatus = 'pending' | 'success' | 'error'

export interface ActivityEntry {
    id: number
    type: ActivityType
    message: string
    detail?: string
    timestamp: Date
    status: ActivityStatus
    nftTokenId?: string
}

interface ActivityLogContextType {
    entries: ActivityEntry[]
    addEntry: (type: ActivityType, message: string, opts?: { detail?: string; status?: ActivityStatus; nftTokenId?: string }) => void
    updateEntry: (id: number, updates: Partial<Pick<ActivityEntry, 'status' | 'message' | 'detail'>>) => void
    clearAll: () => void
    unreadCount: number
    markAllRead: () => void
}

const ActivityLogContext = createContext<ActivityLogContextType | null>(null)

let _nextId = 1

export function ActivityLogProvider({ children }: { children: ReactNode }) {
    const [entries, setEntries] = useState<ActivityEntry[]>([])
    const [lastReadTimestamp, setLastReadTimestamp] = useState<number>(Date.now())

    const addEntry = useCallback((
        type: ActivityType,
        message: string,
        opts?: { detail?: string; status?: ActivityStatus; nftTokenId?: string }
    ) => {
        const entry: ActivityEntry = {
            id: _nextId++,
            type,
            message,
            detail: opts?.detail,
            timestamp: new Date(),
            status: opts?.status ?? 'success',
            nftTokenId: opts?.nftTokenId,
        }
        setEntries(prev => [entry, ...prev].slice(0, 200))
        return entry.id
    }, [])

    const updateEntry = useCallback((id: number, updates: Partial<Pick<ActivityEntry, 'status' | 'message' | 'detail'>>) => {
        setEntries(prev => prev.map(e => e.id === id ? { ...e, ...updates } : e))
    }, [])

    const clearAll = useCallback(() => setEntries([]), [])

    const unreadCount = entries.filter(e => e.timestamp.getTime() > lastReadTimestamp).length
    const markAllRead = useCallback(() => setLastReadTimestamp(Date.now()), [])

    // Listen to Tauri file-progress events and auto-log
    useEffect(() => {
        const unlisten = listen<{
            operationType: 'upload' | 'download'
            stage: string
            message: string
            totalProgress: number
        }>('file-progress', (event) => {
            const d = event.payload
            if (d.stage === 'complete') {
                const type: ActivityType = d.operationType === 'upload' ? 'upload' : 'download'
                addEntry(type, d.message, { status: 'success' })
            }
        })
        return () => { unlisten.then(fn => fn()) }
    }, [addEntry])

    return (
        <ActivityLogContext.Provider value={{ entries, addEntry, updateEntry, clearAll, unreadCount, markAllRead }}>
            {children}
        </ActivityLogContext.Provider>
    )
}

export function useActivityLog() {
    const ctx = useContext(ActivityLogContext)
    if (!ctx) throw new Error('useActivityLog must be used within ActivityLogProvider')
    return ctx
}