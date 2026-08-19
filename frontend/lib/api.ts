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
  tags?: string[];
  is_trending?: boolean;
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

  return (
    localStorage.getItem('nvme_token') ||
    sessionStorage.getItem('nvme_token') ||
    localStorage.getItem('empire_token')
  );
}

export function authHeaders(json = true): Record<string, string> {
  const headers: Record<string, string> = {};

  if (json) {
    headers['Content-Type'] = 'application/json';
  }

  const t = token();

  if (t) {
    headers['Authorization'] = `Bearer ${t}`;
  }

  return headers;
}

async function req<T>(
  path: string,
  opts: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      ...authHeaders(!(opts.body instanceof FormData)),
      ...(opts.headers || {})
    }
  });

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;

    try {
      const data = await res.json();
      msg = data.error || data.message || msg;
    } catch {}

    throw new Error(msg);
  }

  return res.json();
}

export const auth = {
  login: (email: string, password: string) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    }),

  register: (
    username: string,
    email: string,
    password: string
  ) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    }),

  me: () =>
    req<{ user: NvmeUser } | NvmeUser>('/api/auth/me'),

  googleUrl: () => `${BASE}/auth/google`
};

export const videos = {
  feed: async (
    cursor?: string,
    sessionId?: string
  ): Promise<{
    items: NvmeVideo[];
    nextCursor?: string;
    sessionId?: string;
  }> => {
    const params = new URLSearchParams();

    if (cursor) {
      params.set('cursor', cursor);
    }

    if (sessionId) {
      params.set('session_id', sessionId);
    }

    const query = params.toString();

    const d = await req<{
      feed?: NvmeVideo[];
      items?: NvmeVideo[];
      videos?: NvmeVideo[];
      nextCursor?: string;
      sessionId?: string;
    }>(
      `/api/feed/v2${query ? `?${query}` : ''}`
    );

    const items =
      d.items ||
      d.feed ||
      d.videos ||
      [];

    return {
      items: items.filter(
        (video) => video && video.url
      ),
      nextCursor: d.nextCursor,
      sessionId: d.sessionId
    };
  },

  event: (
    eventType: string,
    videoId?: string,
    payload: Record<string, unknown> = {}
  ) => {
    const sessionId =
      typeof window !== 'undefined'
        ? sessionStorage.getItem('nvme_feed_session') ||
          (() => {
            const value = crypto.randomUUID();
            sessionStorage.setItem(
              'nvme_feed_session',
              value
            );
            return value;
          })()
        : undefined;

    return req('/api/feed/events', {
      method: 'POST',
      body: JSON.stringify({
        event_type: eventType,
        video_id: videoId,
        session_id: sessionId,
        ...payload
      })
    });
  },

  notInterested: (videoId: string) => {
    const sessionId =
      typeof window !== 'undefined'
        ? sessionStorage.getItem('nvme_feed_session') || undefined
        : undefined;

    return req('/api/feed/not-interested', {
      method: 'POST',
      body: JSON.stringify({
        video_id: videoId,
        session_id: sessionId
      })
    });
  },

  get: (id: string) =>
    req(`/api/videos/${id}`),

  like: (id: string) =>
    req(`/api/videos/${id}/like`, {
      method: 'POST'
    }),

  view: (id: string) =>
    fetch(`${BASE}/api/videos/${id}/view`, {
      method: 'POST',
      headers: authHeaders(false)
    }).catch(() => {}),

  comments: async (
    id: string
  ): Promise<NvmeComment[]> => {
    const d = await req<{
      comments?: NvmeComment[];
    }>(`/api/videos/${id}/comments`);

    return d.comments || [];
  },

  postComment: (
    id: string,
    text: string,
    image?: string | null
  ) =>
    req(`/api/videos/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({
        text,
        image: image || undefined
      })
    }),

  byUser: async (
    username: string
  ): Promise<NvmeVideo[]> => {
    const d = await req<{
      videos?: NvmeVideo[];
    }>(
      `/api/users/${encodeURIComponent(username)}/videos`
    );

    return d.videos || [];
  }
};

export async function uploadVideo(
  file: File,
  title: string,
  description: string
): Promise<{
  url?: string;
  thumbnail?: string;
}> {
  const fd = new FormData();

  fd.append('video', file);
  fd.append('title', title);
  fd.append('description', description);

  return req('/api/upload', {
    method: 'POST',
    body: fd
  });
}

export const ai = {
  status: () => req('/api/ai/status'),

  captions: (topic: string) =>
    req('/api/ai/captions', {
      method: 'POST',
      body: JSON.stringify({ topic })
    }),

  hashtags: (topic: string) =>
    req('/api/ai/hashtags', {
      method: 'POST',
      body: JSON.stringify({ topic })
    }),

  script: (topic: string) =>
    req('/api/ai/script', {
      method: 'POST',
      body: JSON.stringify({ topic })
    }),

  generate: (prompt: string) =>
    req('/api/ai/generate', {
      method: 'POST',
      body: JSON.stringify({ prompt })
    })
};

export const wallet = {
  balance: () =>
    req<{ balance?: number; coins?: number }>(
      '/api/wallet/balance'
    ),

  transactions: () =>
    req('/api/wallet/transactions'),

  connect: (address: string) =>
    req('/api/wallet/connect', {
      method: 'POST',
      body: JSON.stringify({ address })
    })
};

export const payments = {
  createOrder: (plan: string) =>
    req('/api/payments/paypal/create-order', {
      method: 'POST',
      body: JSON.stringify({ plan })
    }),

  captureOrder: (orderId: string) =>
    req('/api/payments/paypal/capture-order', {
      method: 'POST',
      body: JSON.stringify({ orderId })
    })
};
