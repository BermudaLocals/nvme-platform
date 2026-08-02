/* Centralized API layer — wired to the VERIFIED live NVME monolith.
   Same-origin by default (Next rewrites proxy /api + /auth + /socket.io). */

const BASE = process.env.NEXT_PUBLIC_API_URL || '';

export interface NvmeUser {
  id: string;
  username: string;
  display_name?: string;
  email?: string;
  avatar_url?: string;
  bio?: string;
  profile_link?: string;
  followers?: number;
  online?: boolean;
  is_private?: boolean;
}

export interface NvmeVideo {
  id: string;
  url: string;
  thumbnail?: string;
  title?: string;
  description?: string;
  username?: string;
  author_id?: string;
  avatar_url?: string;
  like_count?: number;
  comment_count?: number;
  views?: number;
  created_at?: string;
}

export interface NvmeComment {
  id: string;
  text?: string;
  image_url?: string;
  username?: string;
  display_name?: string;
  avatar_url?: string;
  created_at?: string;
}

function token(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('nvme_token') || sessionStorage.getItem('nvme_token') || localStorage.getItem('empire_token');
}

export function authHeaders(json = true): Record<string, string> {
  const h: Record<string, string> = {};
  if (json) h['Content-Type'] = 'application/json';
  const t = token();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { ...authHeaders(!(opts.body instanceof FormData)), ...(opts.headers || {}) }
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch { /* non-json */ }
    throw new Error(msg);
  }
  return res.json();
}

/* ---------- AUTH ---------- */
export const auth = {
  login: (email: string, password: string) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  register: (username: string, email: string, password: string) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) }),
  me: () => req<{ user: NvmeUser } | NvmeUser>('/api/auth/me'),
  googleUrl: () => `${BASE}/auth/google`
};

/* ---------- FEED / VIDEOS ---------- */
export const videos = {
  feed: async (cursor?: string): Promise<{ items: NvmeVideo[]; nextCursor?: string }> => {
    const d = await req<any>(`/api/feed${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`);
    const items: NvmeVideo[] = d.feed || d.videos || (Array.isArray(d) ? d : []);
    return { items: items.filter(v => v && v.url), nextCursor: d.nextCursor };
  },
  get: (id: string) => req<NvmeVideo>(`/api/videos/${id}`),
  like: (id: string) => req<any>(`/api/videos/${id}/like`, { method: 'POST' }),
  view: (id: string) => fetch(`${BASE}/api/videos/${id}/view`, { method: 'POST' }).catch(() => {}),
  comments: async (id: string): Promise<NvmeComment[]> => {
    const d = await req<any>(`/api/videos/${id}/comments`);
    return d.comments || d || [];
  },
  postComment: (id: string, text: string, image?: string | null) =>
    req<any>(`/api/videos/${id}/comments`, { method: 'POST', body: JSON.stringify({ text, image: image || undefined }) }),
  byUser: async (username: string): Promise<NvmeVideo[]> => {
    const d = await req<any>(`/api/users/${encodeURIComponent(username)}/videos`);
    return d.videos || [];
  }
};

/* ---------- USERS / SOCIAL ---------- */
export const users = {
  discover: async (): Promise<NvmeUser[]> => {
    const d = await req<any>('/api/users/discover');
    return d.users || d || [];
  },
  follow: (userId: string) => req<{ ok: boolean; following?: boolean }>(`/api/users/${userId}/follow`, { method: 'POST' }),
  stats: (username: string) => req<any>(`/api/users/${encodeURIComponent(username)}/stats`),
  updateProfile: (body: Partial<NvmeUser>) => req<{ ok: boolean; user: NvmeUser }>('/api/profile', { method: 'PUT', body: JSON.stringify(body) })
};

/* ---------- SEARCH ---------- */
export async function search(q: string): Promise<{ users: NvmeUser[]; videos: NvmeVideo[] }> {
  const d = await req<any>(`/api/search?q=${encodeURIComponent(q)}`);
  return { users: d.users || [], videos: (d.videos || []).filter((v: NvmeVideo) => v.url) };
}

/* ---------- UPLOAD ---------- */
export async function uploadVideo(file: File, title: string, description: string): Promise<{ url?: string; thumbnail?: string }> {
  const fd = new FormData();
  fd.append('video', file);
  fd.append('title', title);
  fd.append('description', description);
  return req('/api/upload', { method: 'POST', body: fd });
}

/* ---------- AI STUDIO ---------- */
export const ai = {
  status: () => req<any>('/api/ai/status'),
  captions: (topic: string) => req<any>('/api/ai/captions', { method: 'POST', body: JSON.stringify({ topic }) }),
  hashtags: (topic: string) => req<any>('/api/ai/hashtags', { method: 'POST', body: JSON.stringify({ topic }) }),
  script: (topic: string) => req<any>('/api/ai/script', { method: 'POST', body: JSON.stringify({ topic }) }),
  generate: (prompt: string) => req<any>('/api/ai/generate', { method: 'POST', body: JSON.stringify({ prompt }) })
};

/* ---------- WALLET ---------- */
export const wallet = {
  balance: () => req<{ balance?: number; coins?: number }>('/api/wallet/balance'),
  transactions: () => req<any>('/api/wallet/transactions'),
  connect: (address: string) => req<any>('/api/wallet/connect', { method: 'POST', body: JSON.stringify({ address }) })
};

/* ---------- PAYMENTS ---------- */
export const payments = {
  createOrder: (plan: string) => req<any>('/api/payments/paypal/create-order', { method: 'POST', body: JSON.stringify({ plan }) }),
  captureOrder: (orderId: string) => req<any>('/api/payments/paypal/capture-order', { method: 'POST', body: JSON.stringify({ orderId }) })
};
