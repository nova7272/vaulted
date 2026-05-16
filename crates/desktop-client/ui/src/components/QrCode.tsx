import { useEffect, useState } from 'react'
import QRCode from 'qrcode'

interface QrCodeProps {
  value: string
  label?: string
  size?: number
}

interface QrCodeState {
  value: string
  dataUrl: string | null
  error: string | null
}

export function QrCode({ value, label = 'QR code', size = 220 }: QrCodeProps) {
  const [state, setState] = useState<QrCodeState>({ value: '', dataUrl: null, error: null })

  useEffect(() => {
    let cancelled = false

    QRCode.toDataURL(value, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: size,
      color: {
        dark: '#0b0f17',
        light: '#ffffff',
      },
    })
      .then(url => {
        if (!cancelled) setState({ value, dataUrl: url, error: null })
      })
      .catch(err => {
        if (!cancelled) setState({ value, dataUrl: null, error: String(err) })
      })

    return () => {
      cancelled = true
    }
  }, [value, size])

  if (state.value === value && state.error) {
    return (
      <div style={{ border: '1px solid var(--line)', borderRadius: 14, padding: 14, color: '#e07a6a', fontSize: 13 }}>
        QR generation failed: {state.error}
      </div>
    )
  }

  if (state.value !== value || !state.dataUrl) {
    return (
      <div style={{ width: size, height: size, display: 'grid', placeItems: 'center', border: '1px solid var(--line)', borderRadius: 14, background: 'var(--bg-3)' }}>
        <div className="spinner" style={{ width: 22, height: 22 }} />
      </div>
    )
  }

  return (
    <img
      src={state.dataUrl}
      width={size}
      height={size}
      alt={label}
      style={{ display: 'block', borderRadius: 14, padding: 10, background: '#ffffff', border: '1px solid var(--line)' }}
    />
  )
}
