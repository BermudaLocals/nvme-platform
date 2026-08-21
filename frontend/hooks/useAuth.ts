'use client';
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { auth } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';

export function useAuth() {
  const { user, token, hydrated, setAuth, setUser, setHydrated, logout, openAuth, closeAuth, authModalOpen, authMode } = useAuthStore();

  // Hydrate from localStorage (nvme_token + nvme_user) and catch the OAuth
  // handoff: ?code= (one-time, 5min) is exchanged for tokens.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const qs = new URLSearchParams(window.location.search);
    const code = qs.get('code');
    if (code) {
      window.history.replaceState({}, '', window.location.pathname);
      auth
        .oauthExchange(code)
        .then((d: any) => {
          if (d?.token) {
            localStorage.setItem('nvme_token', d.token);
            if (d.refreshToken) localStorage.setItem('nvme_refresh', d.refreshToken);
            if (d.user) setUser(d.user);
            useAuthStore.setState({ token: d.token });
          }
        })
        .catch(() => { /* invalid/expired code — stay logged out */ })
        .finally(() => setHydrated());
      return;
    }
    const stored = localStorage.getItem('nvme_token') || sessionStorage.getItem('nvme_token');
    if (stored && !user) {
      try {
        const cached = localStorage.getItem('nvme_user');
        if (cached) setUser(JSON.parse(cached));
      } catch { /* bad cache */ }
      useAuthStore.setState({ token: stored });
    }
    setHydrated();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Live user refresh — staleTime Infinity, refetch on focus (per spec)
  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      const d: any = await auth.me();
      const u = d.user || d;
      setUser(u);
      return u;
    },
    enabled: hydrated && !!token,
    staleTime: Infinity,
    refetchOnWindowFocus: true,
    retry: false
  });

  useEffect(() => {
    if (meQuery.isError) logout();
  }, [meQuery.isError]); // eslint-disable-line react-hooks/exhaustive-deps

  return { user, token, hydrated, isAuthenticated: !!user, openAuth, closeAuth, authModalOpen, authMode, logout };
}
