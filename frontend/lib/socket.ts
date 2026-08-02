'use client';
import { io, type Socket } from 'socket.io-client';

let socket: Socket | null = null;

export function getSocket(): Socket {
  if (!socket) {
    const url = process.env.NEXT_PUBLIC_API_URL || (typeof window !== 'undefined' ? window.location.origin : '');
    socket = io(url, { transports: ['websocket', 'polling'], reconnectionDelayMax: 8000 });
  }
  return socket;
}

export type NvmeNotification = {
  type: 'follow' | 'like' | 'comment' | 'gift' | 'live' | string;
  message: string;
  from?: string;
  ts?: number;
};
