/**
 * Format error messages for user-friendly display
 *
 * Maps technical error strings from Rust backend to clear,
 * actionable messages that non-technical users can understand.
 */

interface ErrorMapping {
    /** Patterns to match against the raw error string */
    patterns: string[]
    /** Human-readable message shown to user */
    message: string
    /** Optional hint with next steps */
    hint?: string
}

const ERROR_MAP: ErrorMapping[] = [
    // ── Crypto / key access errors ──
    {
        patterns: ['PRE decryption failed', 'Pre decryption', 'Re-decryption failed'],
        message: 'Unable to decrypt this file.',
        hint: 'The encryption key may have changed after an NFT transfer outside the app.',
    },
    {
        patterns: ['Capsule fragment verification failed', 'cfrag verification failed'],
        message: 'File integrity check failed.',
        hint: 'The encryption data may have been tampered with. Contact the sender.',
    },
    {
        patterns: ['AES decryption failed', 'Authentication failed', 'AES-GCM'],
        message: 'Decryption failed — wrong key or corrupted data.',
    },
    {
        patterns: ['Invalid key', 'Invalid public key', 'key does not match'],
        message: 'Encryption key mismatch.',
        hint: 'Try re-deriving your keys in Settings.',
    },
    {
        patterns: ['key derivation', 'KeyDerivationFailed'],
        message: 'Failed to derive encryption keys.',
        hint: 'Please unlock your Vaulted wallet and try key derivation again.',
    },
    {
        patterns: ['PRE key mismatch', 'pre_key_mismatch'],
        message: 'This NFT was transferred outside the app.',
        hint: 'The previous owner\'s encryption key is still active. Ask them to transfer via the app instead.',
    },

    // ── Auth errors ──
    {
        patterns: ['Not authenticated', 'Unauthorized', 'Session expired', 'Token expired'],
        message: 'Your session has expired.',
        hint: 'Please sign in again with Vaulted identity.',
    },
    {
        patterns: ['valid XRPL public key is required'],
        message: 'Wallet authentication failed.',
        hint: 'Your wallet did not provide a public key. Please try signing in again.',
    },
    {
        patterns: ['Device fingerprint mismatch'],
        message: 'This token was issued for a different device.',
        hint: 'Sign in again from this device.',
    },
    {
        patterns: ['Refresh token has been revoked', 'token theft'],
        message: 'Security alert: possible unauthorized access detected.',
        hint: 'All sessions have been revoked. Please sign in again immediately.',
    },

    // ── Transfer errors ──
    {
        patterns: ['Recipient', 'not registered'],
        message: 'Recipient is not registered in the vault.',
        hint: 'Ask them to create a Vaulted identity first.',
    },
    {
        patterns: ['Only the owner can', 'Not NFT owner', 'not the owner'],
        message: 'You don\'t have permission for this action.',
        hint: 'Only the current NFT owner can perform this operation.',
    },
    {
        patterns: ['Active transfer already exists'],
        message: 'A transfer is already in progress for this file.',
        hint: 'Cancel the existing transfer first, or wait for it to complete.',
    },
    {
        patterns: ['NFT ownership could not be verified'],
        message: 'Could not verify your NFT ownership on the blockchain.',
        hint: 'The XRPL network may be temporarily unavailable. Try again in a few minutes.',
    },

    // ── File / Storage errors ──
    {
        patterns: ['File not found', 'Vault not found', 'NFT not found'],
        message: 'File not found.',
        hint: 'It may have been deleted or the NFT burned.',
    },
    {
        patterns: ['File too large', 'Payload too large'],
        message: 'File is too large to upload.',
        hint: 'Maximum file size is 25 MB.',
    },
    {
        patterns: ['No active storage nodes', 'Storage service', 'storage-node', 'missing from all storage'],
        message: 'Storage service is temporarily unavailable.',
        hint: 'Your encrypted data is safe. Try downloading again later.',
    },

    // ── Network / Connection errors ──
    {
        patterns: ['Oracle API error', 'HTTP error', 'error sending request', 'localhost:3000'],
        message: 'Cannot connect to the vault server.',
        hint: 'Check your internet connection or try again later.',
    },
    {
        patterns: ['HTTP 404'],
        message: 'The requested resource was not found.',
    },
    {
        patterns: ['HTTP 401', 'HTTP 403'],
        message: 'Access denied.',
        hint: 'Your session may have expired. Try signing in again.',
    },
    {
        patterns: ['HTTP 429', 'Rate limit', 'Too many requests'],
        message: 'Too many requests.',
        hint: 'Please wait a moment and try again.',
    },
    {
        patterns: ['HTTP 500', 'HTTP 502', 'HTTP 503', 'Internal error'],
        message: 'Server error.',
        hint: 'The team has been notified. Try again in a few minutes.',
    },
    {
        patterns: ['connection refused', 'Connection refused', 'Failed to connect', 'ECONNREFUSED', 'Connection reset'],
        message: 'Cannot connect to server.',
        hint: 'Please check your internet connection.',
    },
    {
        patterns: ['XRPL error: Request timeout', 'XRPL connection timed out'],
        message: 'XRPL connection timed out.',
        hint: 'The network did not answer in time. Try minting again.',
    },
    {
        patterns: ['timeout', 'Timeout', 'timed out'],
        message: 'Request timed out.',
        hint: 'The server took too long to respond. Please try again.',
    },
    {
        patterns: ['network', 'Network'],
        message: 'Network error.',
        hint: 'Please check your internet connection.',
    },

    // ── XRPL errors ──
    {
        patterns: ['actNotFound', 'Account not found', 'xrpl_account_not_found'],
        message: 'Wallet is not funded yet.',
        hint: 'Add testnet XRP to this address, then try minting again.',
    },
    {
        patterns: ['tecINSUFF_RESERVE'],
        message: 'Not enough XRP reserve.',
        hint: 'Add more testnet XRP to this wallet, then try minting again.',
    },
    {
        patterns: ['tefPAST_SEQ'],
        message: 'Transaction sequence is stale.',
        hint: 'Retry minting so Vaulted can build the transaction with a fresh sequence.',
    },
    {
        patterns: ['terQUEUED'],
        message: 'Transaction queued on XRPL.',
        hint: 'Check the wallet status shortly before retrying.',
    },
    {
        patterns: ['could not extract the minted NFTokenID', 'Missing NFTokenID'],
        message: 'XRPL mint succeeded, but Vaulted could not read the NFTokenID yet.',
        hint: 'Do not remint. Use finalize existing mint to complete the Oracle link.',
    },
    {
        patterns: ['Vault mint recovery is not available', 'Public metadata must be published before mint recovery'],
        message: 'Previous mint cannot be finalized from the current vault state.',
        hint: 'Check the vault ID and transaction hash before trying recovery again.',
    },
    {
        patterns: ['Missing authorization', 'Cannot create vault for different wallet', 'JWT', 'Oracle token'],
        message: 'Vault access needs to be refreshed.',
        hint: 'Sign in with your Vaulted wallet again and retry the action.',
    },
    {
        patterns: ['insufficient', 'Balance critically low'],
        message: 'Insufficient XRP balance.',
        hint: 'You need at least 15 XRP to perform this transaction.',
    },
    {
        patterns: ['XRPL error', 'xrpl error', 'Transaction failed'],
        message: 'Blockchain transaction failed.',
        hint: 'The XRPL network may be congested. Try again in a few moments.',
    },
    {
        patterns: ['Transaction validation timeout'],
        message: 'Transaction is taking longer than expected.',
        hint: 'It may still go through. Check your wallet in a minute.',
    },

    // ── Wallet signing errors ──
    {
        patterns: ['External wallet', 'Vaulted signing', 'Sign request', 'QR expired'],
        message: 'Wallet signing request failed.',
        hint: 'Open the Vaulted signer and try again. Make sure the app is updated.',
    },
]

export function formatError(error: unknown): string {
    const msg = String(error)

    for (const { patterns, message, hint } of ERROR_MAP) {
        if (patterns.some(p => msg.toLowerCase().includes(p.toLowerCase()))) {
            return hint ? `${message} ${hint}` : message
        }
    }

    // Fallback: clean up technical details
    const cleaned = msg
        .replace(/^Error:\s*/i, '')
        .replace(/Oracle API error:\s*/i, '')
        .replace(/HTTP \d+\s*/, '')
        .replace(/:\s*$/, '')
        .trim()

    // If still too technical, return generic message
    if (cleaned.length > 120 || cleaned.includes('stack') || cleaned.includes('at ') || cleaned.includes('panicked')) {
        return 'Something went wrong. Please try again.'
    }

    return cleaned || 'Something went wrong. Please try again.'
}

/**
 * Structured error with title and detail for Toast display
 */
export function formatErrorForToast(error: unknown): { title: string; sub?: string } {
    const msg = String(error)

    for (const { patterns, message, hint } of ERROR_MAP) {
        if (patterns.some(p => msg.toLowerCase().includes(p.toLowerCase()))) {
            return { title: message, sub: hint }
        }
    }

    const cleaned = msg
        .replace(/^Error:\s*/i, '')
        .replace(/Oracle API error:\s*/i, '')
        .trim()

    if (cleaned.length > 80) {
        return { title: 'Something went wrong', sub: cleaned.slice(0, 80) + '…' }
    }

    return { title: cleaned || 'Something went wrong' }
}
