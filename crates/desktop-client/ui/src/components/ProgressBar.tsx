import { useState, useEffect } from 'react'
import { listen } from '@tauri-apps/api/event'

interface ProgressEvent {
  operationId: string
  operationType: 'upload' | 'download'
  stage: string
  progress: number
  totalProgress: number
  message: string
  bytesProcessed: number
  bytesTotal: number
}

interface ProgressBarProps {
  operationId?: string
  onComplete?: () => void
  hideOnScreens?: string[]
  currentScreen?: string
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function ProgressBar({ operationId, onComplete, hideOnScreens, currentScreen }: ProgressBarProps) {
  const [progress, setProgress] = useState<ProgressEvent | null>(null)
  const [visible, setVisible] = useState(false)

  // Hide when on screens that have their own progress UI
  const hiddenByScreen = hideOnScreens && currentScreen && hideOnScreens.includes(currentScreen)

  useEffect(() => {
    const unlisten = listen<ProgressEvent>('file-progress', (event) => {
      const data = event.payload

      // Фильтруем по operationId если указан
      if (operationId && data.operationId !== operationId) {
        return
      }

      setProgress(data)
      setVisible(true)

      // Скрываем через 2 секунды после завершения
      if (data.stage === 'complete') {
        setTimeout(() => {
          setVisible(false)
          setProgress(null)
          onComplete?.()
        }, 2000)
      }
    })

    return () => {
      unlisten.then(fn => fn())
    }
  }, [operationId, onComplete])

  if (!visible || !progress || hiddenByScreen) {
    return null
  }

  const isUpload = progress.operationType === 'upload'
  const icon = isUpload ? '⬆️' : '⬇️'
  const color = isUpload ? '#6aa0ff' : '#6ac79a'
  const bgColor = isUpload ? 'rgba(106,160,255,0.15)' : 'rgba(106,199,154,0.15)'

  return (
      <div style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        width: 360,
        background: '#181c25',
        borderRadius: 16,
        boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
        padding: 20,
        zIndex: 1000,
        border: `1px solid ${bgColor}`,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <span style={{ fontSize: 24 }}>{icon}</span>
          <div style={{ flex: 1 }}>
            <h4 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: '#f2f3f7' }}>
              {isUpload ? 'Uploading' : 'Downloading'}
            </h4>
            <p style={{ margin: 0, fontSize: 12, color: '#868b98' }}>
              {progress.message}
            </p>
          </div>
          {progress.stage === 'complete' && (
              <span style={{
                background: 'rgba(106,199,154,0.1)',
                color: '#6ac79a',
                padding: '4px 10px',
                borderRadius: 99,
                fontSize: 12,
                fontWeight: 600
              }}>
            ✓ Done
          </span>
          )}
        </div>

        {/* Progress Bar */}
        <div style={{
          height: 8,
          background: '#c5c8d1',
          borderRadius: 99,
          overflow: 'hidden',
          marginBottom: 8,
        }}>
          <div style={{
            height: '100%',
            width: `${progress.totalProgress}%`,
            background: `linear-gradient(90deg, ${color} 0%, ${color}dd 100%)`,
            borderRadius: 99,
            transition: 'width 0.3s ease',
          }} />
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#868b98' }}>
        <span>
          {progress.bytesProcessed > 0 && progress.bytesTotal > 0
              ? `${formatBytes(progress.bytesProcessed)} / ${formatBytes(progress.bytesTotal)}`
              : progress.stage
          }
        </span>
          <span style={{ fontWeight: 600, color: color }}>
          {progress.totalProgress}%
        </span>
        </div>
      </div>
  )
}

// Hook для использования в компонентах
export function useFileProgress() {
  const [activeProgress, setActiveProgress] = useState<ProgressEvent | null>(null)

  useEffect(() => {
    const unlisten = listen<ProgressEvent>('file-progress', (event) => {
      setActiveProgress(event.payload)

      if (event.payload.stage === 'complete') {
        setTimeout(() => setActiveProgress(null), 2000)
      }
    })

    return () => {
      unlisten.then(fn => fn())
    }
  }, [])

  return activeProgress
}