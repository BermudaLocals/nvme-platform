'use client';
import { create } from 'zustand';
import type { NvmeUser } from '@/lib/api';

interface AuthState {
  user: NvmeUser | null;
  token: string | null;
  hydrated: boolean;
  authModalOpen: boolean;
  authMode: 'signin' | 'signup';
  setAuth: (user: NvmeUser, token: string) => void;
  setUser: (user: NvmeUser | null) => void;
  setHydrated: () => void;
  openAuth: (mode?: 'signin' | 'signup') => void;
  closeAuth: () => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: null,
  hydrated: false,
  authModalOpen: false,
  authMode: 'signin',
  setAuth: (user, token) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('nvme_token', token);
      try { localStorage.setItem('nvme_user', JSON.stringify(user)); } catch { /* quota */ }
    }
    set({ user, token, authModalOpen: false });
  },
  setUser: (user) => {
    if (typeof window !== 'undefined' && user) {
      try { localStorage.setItem('nvme_user', JSON.stringify(user)); } catch { /* quota */ }
    }
    set({ user });
  },
  setHydrated: () => set({ hydrated: true }),
  openAuth: (mode = 'signin') => set({ authModalOpen: true, authMode: mode }),
  closeAuth: () => set({ authModalOpen: false }),
  logout: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('nvme_token');
      localStorage.removeItem('nvme_user');
      localStorage.removeItem('empire_token');
      sessionStorage.removeItem('nvme_token');
    }
    set({ user: null, token: null });
  }
}));
