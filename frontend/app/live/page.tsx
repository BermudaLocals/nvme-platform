'use client'
import { useEffect, useRef, useState } from 'react'
import { useParams } from 'next/navigation'
import io from 'socket.io-client'
import BattleRoom from '../../../src/components/BattleRoom'

let socket: any

export default function LivePage() {
  const params = useParams() as any
  const battleId = params?.id || 'test123'
  const localVideo = useRef<HTMLVideoElement>(null)
  const [joined, setJoined] = useState(false)
  const [remoteCount, setRemoteCount] = useState(0)

  useEffect(() => {
    // 1. get camera
    navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then(stream => {
      if (localVideo.current) {
        localVideo.current.srcObject = stream
      }
    })

    // 2. join same room
    socket = io()
    socket.emit('battle:join', { battleId })
    socket.on('battle:joined', (data: any) => {
      setJoined(true)
      setRemoteCount(data.count - 1)
    })
    socket.on('battle:peer-joined', () => setRemoteCount(c => c + 1))
    socket.on('battle:peer-left', () => setRemoteCount(c => Math.max(0, c - 1)))

    return () => {
      socket.emit('battle:leave', { battleId })
      socket.disconnect()
    }
  }, [battleId])

  return (
    <div className="live-page">
      <div className="video-grid">
        <video ref={localVideo} autoPlay muted playsInline className="local" />
        <div className="remote-placeholder">
          {remoteCount === 0? (
            <div className="waiting">
              <p>Waiting for opponent...</p>
              <small>Share this link:</small>
              <code>nvme.live/live/{battleId}</code>
              <p>Open SAME link on 2nd phone — DON'T click Go LIVE again</p>
            </div>
          ) : (
            <div className="remote-live">🔴 LIVE OPPONENT {remoteCount + 1} watching</div>
          )}
        </div>
      </div>

      <BattleRoom socket={socket} battleId={battleId} />

      <style jsx>{`
       .live-page{position:relative;min-height:100vh;background:black;padding-bottom:83px}
       .video-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px;height:60vh;background:#111}
       .video-grid video{width:100%;height:100%;object-fit:cover;background:#222}
       .remote-placeholder{background:#1a1a1a;display:flex;align-items:center;justify-content:center;color:white;text-align:center;padding:20px}
       .waiting code{display:block;background:#333;padding:8px;border-radius:6px;margin:8px 0;color:gold;font-size:12px;word-break:break-all}
       .remote-live{color:#ff2d55;font-weight:900;animation:pulse 1s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
      `}</style>
    </div>
  )
}
