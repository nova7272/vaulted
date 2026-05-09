import { useMemo } from 'react'
import { generateNftSvg } from '../utils/nft_image'

interface Props {
    tokenId: string
    style?: React.CSSProperties
}

/**
 * NFT contour image rendered as inline SVG.
 * Deterministic: same tokenId → same image.
 * Replaces the old pixel-based fingerprint renderer.
 */
export default function NftContourImage({ tokenId, style }: Props) {
    const dataUrl = useMemo(() => {
        const svg = generateNftSvg(tokenId)
        return `data:image/svg+xml,${encodeURIComponent(svg)}`
    }, [tokenId])

    return (
        <img
            src={dataUrl}
            alt=""
            style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                width: '100%',
                height: '100%',
                objectFit: 'cover',
                display: 'block',
                ...style,
            }}
        />
    )
}