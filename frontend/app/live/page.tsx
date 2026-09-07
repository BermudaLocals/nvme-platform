'use client'
import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import io from 'socket.io-client'
import { Room, RoomEvent, Track, RemoteParticipant, LocalParticipant } from 'livekit-client'
import BattleRoom from '../../../src/components/BattleRoom'
import { authHeaders } from '../../lib/api'

let socket: any

const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''

export default function LivePage() {
  const params = useParams() as any
  const searchParams = useSearchParams()
  const streamId = params?.id || 'test123'

  // ?host=1 is set by the "Go Live" button when it sends the
  // broadcaster into this page. Anyone opening the plain share link
  // joins as a viewer. This mirrors how go-live vs join are two
  // separate, differently-permissioned backend calls.
  const isHost = searchParams?.get('host') === '1'

  const localVideoRef = useRef<HTMLVideoElement>(null)
  const remoteContainerRef = useRef<HTMLDivElement>(null)
  const roomRef = useRef<Room | null>(null)

  const [joined, setJoined] = useState(false)
  const [remoteCount, setRemoteCount] = useState(0)
  const [connectError, setConnectError] = useState<string | null>(null)

  const attachRemoteTrack = useCallback(
    (track: Track, participant: RemoteParticipant) => {
      if (track.kind !== Track.Kind.Video && track.kind !== Track.Kind.Audio) return
      const el = track.attach()
      el.setAttribute('data-participant', participant.identity)
      el.style.width = '100%'
      el.style.height = '100%'
      el.style.objectFit = 'cover'
      remoteContainerRef.current?.appendChild(el)
    },
    []
  )

  const detachParticipantTracks = useCallback((participant: RemoteParticipant) => {
    if (!remoteContainerRef.current) return
    const els = remoteContainerRef.current.querySelectorAll(
      `[data-participant="${participant.identity}"]`
    )
    els.forEach((el) => el.remove())
  }, [])

  useEffect(() => {
    let cancelled = false

    async function connect() {
      try {
        // 1. Ask the backend for a LiveKit token — go-live for the
        //    broadcaster (also flips the stream to "live" in the DB),
        //    join for everyone else (fails with 409 if not live yet).
        const endpoint = isHost
          ? `/api/streams/${streamId}/go-live`
          : `/api/streams/${streamId}/join`

        const res = await fetch(`${API_BASE}${endpoint}`, {
          method: 'POST',
          headers: authHeaders()
        })

        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.error || `HTTP ${res.status}`)
        }

        const data = await res.json()
        const { url, token } = data.livekit || {}
        if (!url || !token) throw new Error('No LiveKit credentials returned')

        if (cancelled) return

        // 2. Connect to the room.
        const room = new Room({ adaptiveStream: true, dynacast: true })
        roomRef.current = room

        room
          .on(RoomEvent.TrackSubscribed, (track, _pub, participant) =>
            attachRemoteTrack(track, participant)
          )
          .on(RoomEvent.TrackUnsubscribed, (track) => {
            track.detach().forEach((el) => el.remove())
          })
          .on(RoomEvent.ParticipantDisconnected, (participant) => {
            detachParticipantTracks(participant)
            setRemoteCount((c) => Math.max(0, c - 1))
          })
          .on(RoomEvent.ParticipantConnected, () => setRemoteCount((c) => c + 1))
          .on(RoomEvent.Disconnected, () => setJoined(false))

        await room.connect(url, token)
        if (cancelled) {
          room.disconnect()
          return
        }

        setRemoteCount(room.remoteParticipants.size)

        // 3. Broadcaster publishes camera + mic. Viewers publish nothing.
        if (isHost) {
          await room.localParticipant.setCameraEnabled(true)
          await room.localParticipant.setMicrophoneEnabled(true)

          const camPub = room.localParticipant.getTrackPublication(Track.Source.Camera)
          if (camPub?.track && localVideoRef.current) {
            camPub.track.attach(localVideoRef.current)
          }
        }

        setJoined(true)
      } catch (err: any) {
        if (!cancelled) setConnectError(err.message || 'Failed to connect')
      }
    }

    connect()

    // Chat/gifts/battle-score socket — unchanged from before, still
    // completely separate from the LiveKit video connection above.
    socket = io()
    socket.emit('battle:join', { battleId: streamId })
    socket.on('battle:peer-joined', () => {})
    socket.on('battle:peer-left', () => {})

    return () => {
      cancelled = true
      roomRef.current?.disconnect()
      roomRef.current = null
      socket.emit('battle:leave', { battleId: streamId })
      socket.disconnect()
    }
  }, [streamId, isHost, attachRemoteTrack, detachParticipantTracks])

  return (
    <div className="live-page">
      <div className="video-grid">
        {isHost && (
          <video ref={localVideoRef} autoPlay muted playsInline className="local" />
        )}
        <div ref={remoteContainerRef} className="remote-container">
          {!joined && !connectError && (
            <div className="waiting">
              <p>Connecting…</p>
            </div>
          )}
          {connectError && (
            <div className="waiting error">
              <p>Couldn't connect: {connectError}</p>
              {!isHost && <p>The stream may not be live yet.</p>}
            </div>
          )}
          {joined && remoteCount === 0 && (
            <div className="waiting">
              <p>{isHost ? 'Waiting for viewers…' : 'Waiting for the broadcaster…'}</p>
              <small>Share this link:</small>
              <code>nvme.live/live/{streamId}</code>
            </div>
          )}
        </div>
      </div>

      <BattleRoom socket={socket} battleId={streamId} />

      <style jsx>{`
        .live-page { position: relative; min-height: 100vh; background: black; padding-bottom: 83px; }
        .video-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2px; height: 60vh; background: #111; }
        .video-grid video { width: 100%; height: 100%; object-fit: cover; background: #222; }
        .remote-container { position: relative; background: #1a1a1a; display: flex; align-items: center; justify-content: center; }
        .waiting { color: white; text-align: center; padding: 20px; }
        .waiting.error { color: #ff6b6b; }
        .waiting code { display: block; background: #333; padding: 8px; border-radius: 6px; margin: 8px 0; color: gold; font-size: 12px; word-break: break-all; }
      `}</style>
    </div>
  )
}
