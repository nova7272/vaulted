import { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react'
import { invoke } from '@tauri-apps/api/core'

interface OracleAuthState {
    isAuthenticated: boolean
    isLoading: boolean
    walletAddress: string | null
    role: string | null
    error: string | null
    hasRefreshToken: boolean
    needsRefresh: boolean
    deviceFingerprint: string | null
}

interface OracleAuthContextType extends OracleAuthState {
    login: () => Promise<void>
    logout: () => Promise<void>
    checkAuth: () => Promise<boolean>
    refreshToken: () => Promise<boolean>
}

const OracleAuthContext = createContext<OracleAuthContextType | null>(null)

export function useOracleAuth() {
    const ctx = useContext(OracleAuthContext)
    if (!ctx) throw new Error('useOracleAuth must be used within OracleAuthProvider')
    return ctx
}

interface OracleAuthProviderProps {
    children: ReactNode
    onLoginRequired?: () => void
}

export function OracleAuthProvider({ children, onLoginRequired }: OracleAuthProviderProps) {
    const [state, setState] = useState<OracleAuthState>({
        isAuthenticated: false,
        isLoading: true,
        walletAddress: null,
        role: null,
        error: null,
        hasRefreshToken: false,
        needsRefresh: false,
        deviceFingerprint: null,
    })

    const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

    const checkAuth = useCallback(async (): Promise<boolean> => {
        try {
            const status = await invoke<{
                authenticated: boolean
                walletAddress: string | null
                expiresAt: string | null
                hasRefreshToken: boolean
                role: string | null
                deviceFingerprint: string
                needsRefresh: boolean
            }>('get_oracle_auth_status_extended')

            setState(prev => ({
                ...prev,
                isAuthenticated: status.authenticated,
                walletAddress: status.walletAddress,
                role: status.role,
                hasRefreshToken: status.hasRefreshToken,
                needsRefresh: status.needsRefresh,
                deviceFingerprint: status.deviceFingerprint,
                isLoading: false,
                error: null,
            }))

            return status.authenticated
        } catch (e) {
            try {
                const basicStatus = await invoke<{
                    authenticated: boolean
                    walletAddress: string | null
                    expiresAt: string | null
                }>('get_oracle_auth_status')

                setState(prev => ({
                    ...prev,
                    isAuthenticated: basicStatus.authenticated,
                    walletAddress: basicStatus.walletAddress,
                    isLoading: false,
                    error: null,
                }))

                return basicStatus.authenticated
            } catch (e2) {
                console.error('Failed to check Oracle auth:', e2)
                setState(prev => ({
                    ...prev,
                    isAuthenticated: false,
                    isLoading: false,
                    error: String(e2),
                }))
                return false
            }
        }
    }, [])

    const refreshToken = useCallback(async (): Promise<boolean> => {
        try {
            console.log('Attempting token refresh...')
            const success = await invoke<boolean>('oracle_refresh_token')
            if (success) {
                console.log('Token refreshed successfully')
                await checkAuth()
                return true
            }
            return false
        } catch (e) {
            console.error('Token refresh failed:', e)
            setState(prev => ({
                ...prev,
                isAuthenticated: false,
                error: 'Session expired. Please sign in again.',
            }))
            onLoginRequired?.()
            return false
        }
    }, [checkAuth, onLoginRequired])

    useEffect(() => {
        checkAuth()
    }, [checkAuth])

    // Auto-refresh timer: check every 30 seconds
    useEffect(() => {
        if (refreshTimerRef.current) {
            clearInterval(refreshTimerRef.current)
        }

        if (state.isAuthenticated && state.hasRefreshToken) {
            refreshTimerRef.current = setInterval(async () => {
                try {
                    const status = await invoke<{
                        authenticated: boolean
                        needsRefresh: boolean
                        hasRefreshToken: boolean
                    }>('get_oracle_auth_status_extended')

                    if (status.needsRefresh && status.hasRefreshToken) {
                        console.log('Token expires soon, auto-refreshing...')
                        await refreshToken()
                    } else if (!status.authenticated && status.hasRefreshToken) {
                        console.log('Token expired, attempting refresh...')
                        await refreshToken()
                    }
                } catch (e) {
                    console.error('Auto-refresh check failed:', e)
                }
            }, 30000)
        }

        return () => {
            if (refreshTimerRef.current) {
                clearInterval(refreshTimerRef.current)
            }
        }
    }, [state.isAuthenticated, state.hasRefreshToken, refreshToken])

    const login = useCallback(async () => {
        setState(prev => ({ ...prev, isLoading: true, error: null }))

        try {
            const loginPayload = await invoke<{
                challenge: string
                xamanPayload: {
                    uuid: string
                    qrPng: string
                    qrUri: string
                    websocketUrl: string
                }
            }>('oracle_login_start')

            if (loginPayload.xamanPayload.qrUri) {
                window.open(loginPayload.xamanPayload.qrUri, '_blank')
            }

            const success = await invoke<boolean>('oracle_login_wait', {
                payloadUuid: loginPayload.xamanPayload.uuid,
                websocketUrl: loginPayload.xamanPayload.websocketUrl,
                qrPng: loginPayload.xamanPayload.qrPng,
                challenge: loginPayload.challenge,
            })

            if (success) {
                await checkAuth()
            } else {
                throw new Error('Login failed')
            }
        } catch (e) {
            console.error('Oracle login failed:', e)
            setState(prev => ({
                ...prev,
                isLoading: false,
                error: String(e),
            }))
            throw e
        }
    }, [checkAuth])

    const logout = useCallback(async () => {
        try {
            await invoke('oracle_logout')
            setState(prev => ({
                isAuthenticated: false,
                isLoading: false,
                walletAddress: null,
                role: null,
                error: null,
                hasRefreshToken: false,
                needsRefresh: false,
                deviceFingerprint: prev.deviceFingerprint,
            }))
        } catch (e) {
            console.error('Oracle logout failed:', e)
        }
    }, [])

    return (
        <OracleAuthContext.Provider value={{ ...state, login, logout, checkAuth, refreshToken }}>
            {children}
        </OracleAuthContext.Provider>
    )
}
