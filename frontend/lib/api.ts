const BASE = process.env.NEXT_PUBLIC_API_URL || '';

/* =========================================================
   TYPES
========================================================= */

export interface NvmeUser {
  id: string;
  username: string;
  display_name?: string;
  email?: string;
  avatar_url?: string;
  bio?: string;
  profile_link?: string;
  followers?: number;
  following?: number;
  online?: boolean;
  is_private?: boolean;
  verified?: boolean;
}

export interface NvmeVideo {
  id: string;
  url: string;
  thumbnail?: string;
  title?: string;
  description?: string;
  username?: string;
  display_name?: string;
  author_id?: string;
  avatar_url?: string;

  like_count?: number;
  comment_count?: number;
  share_count?: number;
  views?: number;

  created_at?: string;
  updated_at?: string;

  tags?: string[];

  is_trending?: boolean;
  trending_score?: number;
  trending_rank?: number;

  is_following?: boolean;
  is_saved?: boolean;

  duration?: number;
  width?: number;
  height?: number;
}

export interface NvmeComment {
  id: string;
  text?: string;
  image_url?: string;

  username?: string;
  display_name?: string;
  avatar_url?: string;

  user_id?: string;
  video_id?: string;

  created_at?: string;
  updated_at?: string;
}

export interface NvmeTrendingTopic {
  id: string;
  topic?: string;
  hashtag?: string;
  name?: string;

  video_count?: number;
  views?: number;
  engagement_count?: number;

  trending_score?: number;
  rank?: number;

  created_at?: string;
  updated_at?: string;

  nvme_version_id?: string;
}

export interface NvmeTrendingVideo extends NvmeVideo {
  trending_score?: number;
  trending_rank?: number;
  trend_direction?: 'up' | 'down' | 'stable';
}

export interface NvmeFeedResponse {
  items: NvmeVideo[];
  nextCursor?: string;
  sessionId?: string;
}

export interface NvmeAuthResponse {
  token: string;
  user: NvmeUser;
  refreshToken?: string;
}

export interface NvmeMeResponse {
  user: NvmeUser;
}

export interface NvmeWalletBalance {
  balance?: number;
  coins?: number;
}


/* =========================================================
   AUTH / TOKEN
========================================================= */

function token(): string | null {
  if (typeof window === 'undefined') {
    return null;
  }

  return (
    localStorage.getItem('nvme_token') ||
    sessionStorage.getItem('nvme_token') ||
    localStorage.getItem('empire_token') ||
    sessionStorage.getItem('empire_token')
  );
}

export function authHeaders(
  json = true
): Record<string, string> {
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


/* =========================================================
   REQUEST HELPER
========================================================= */

async function req<T>(
  path: string,
  opts: RequestInit = {}
): Promise<T> {
  const isFormData =
    typeof FormData !== 'undefined' &&
    opts.body instanceof FormData;

  const res = await fetch(`${BASE}${path}`, {
    ...opts,

    headers: {
      ...authHeaders(!isFormData),
      ...(opts.headers || {})
    }
  });

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;

    try {
      const data = await res.json();

      msg =
        data?.error ||
        data?.message ||
        data?.details ||
        msg;
    } catch {
      // Ignore invalid JSON error responses.
    }

    throw new Error(msg);
  }

  /*
   * Some endpoints may return 204 No Content.
   */
  if (res.status === 204) {
    return undefined as T;
  }

  const contentType =
    res.headers.get('content-type') || '';

  if (!contentType.includes('application/json')) {
    return (await res.text()) as T;
  }

  return res.json();
}


/* =========================================================
   AUTH
========================================================= */

export const auth = {
  login: (
    email: string,
    password: string
  ) =>
    req<NvmeAuthResponse>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({
          email,
          password
        })
      }
    ),

  register: (
    username: string,
    email: string,
    password: string
  ) =>
    req<NvmeAuthResponse>(
      '/api/auth/register',
      {
        method: 'POST',
        body: JSON.stringify({
          username,
          email,
          password
        })
      }
    ),

  me: () =>
    req<
      NvmeMeResponse | NvmeUser
    >('/api/auth/me'),

  oauthExchange: (code: string) =>
    req<NvmeAuthResponse>(
      '/api/auth/oauth-exchange',
      {
        method: 'POST',
        body: JSON.stringify({
          code
        })
      }
    ),

  googleUrl: () =>
    `${BASE}/auth/google`,

  logout: () => {
    if (typeof window === 'undefined') {
      return;
    }

    localStorage.removeItem('nvme_token');
    sessionStorage.removeItem('nvme_token');

    localStorage.removeItem('empire_token');
    sessionStorage.removeItem('empire_token');
  },

  getToken: () => token()
};


/* =========================================================
   FEED
========================================================= */

export const videos = {
  feed: async (
    cursor?: string,
    sessionId?: string
  ): Promise<NvmeFeedResponse> => {
    const params = new URLSearchParams();

    if (cursor) {
      params.set('cursor', cursor);
    }

    if (sessionId) {
      params.set(
        'session_id',
        sessionId
      );
    }

    const query = params.toString();

    const d = await req<{
      feed?: NvmeVideo[];
      items?: NvmeVideo[];
      videos?: NvmeVideo[];

      nextCursor?: string;
      next_cursor?: string;

      sessionId?: string;
      session_id?: string;
    }>(
      `/api/feed${
        query ? `?${query}` : ''
      }`
    );

    const items =
      d.items ||
      d.feed ||
      d.videos ||
      [];

    return {
      items: items.filter(
        (video) =>
          video &&
          typeof video.url === 'string' &&
          video.url.length > 0
      ),

      nextCursor:
        d.nextCursor ||
        d.next_cursor,

      sessionId:
        d.sessionId ||
        d.session_id
    };
  },


  /* =======================================================
     FEED EVENTS
  ======================================================= */

  event: (
    eventType: string,
    videoId?: string,
    payload: Record<string, unknown> = {}
  ) => {
    const sessionId =
      typeof window !== 'undefined'
        ? getFeedSession()
        : undefined;

    return req(
      '/api/videos/events',
      {
        method: 'POST',
        body: JSON.stringify({
          events: [
            {
              event_type: eventType,
              video_id: videoId,
              session_id: sessionId,
              ...payload
            }
          ]
        })
      }
    );
  },


  /* =======================================================
     NOT INTERESTED
  ======================================================= */

  notInterested: (
    videoId: string
  ) => {
    return req(
      `/api/videos/${videoId}/feedback`,
      {
        method: 'POST',
        body: JSON.stringify({
          feedback_type:
            'not_interested'
        })
      }
    );
  },


  /* =======================================================
     GET VIDEO
  ======================================================= */

  get: (id: string) =>
    req<NvmeVideo>(
      `/api/videos/${encodeURIComponent(id)}`
    ),


  /* =======================================================
     LIKE
  ======================================================= */

  like: (id: string) =>
    req(
      `/api/videos/${encodeURIComponent(id)}/like`,
      {
        method: 'POST'
      }
    ),


  /* =======================================================
     SAVE
  ======================================================= */

  save: (id: string) =>
    req<{
      success?: boolean;
      saved?: boolean;
      save_count?: number;
    }>(
      `/api/videos/${encodeURIComponent(id)}/save`,
      {
        method: 'POST'
      }
    ),


  /* =======================================================
     VIEW
  ======================================================= */

  view: (
    id: string
  ) =>
    fetch(
      `${BASE}/api/videos/${encodeURIComponent(id)}/view`,
      {
        method: 'POST',
        headers: authHeaders(false)
      }
    ).catch(() => {
      // View tracking should never break playback.
    }),


  /* =======================================================
     COMMENTS
  ======================================================= */

  comments: async (
    id: string
  ): Promise<NvmeComment[]> => {
    const d = await req<{
      comments?: NvmeComment[];
    }>(
      `/api/videos/${encodeURIComponent(id)}/comments`
    );

    return d.comments || [];
  },


  /* =======================================================
     POST COMMENT
  ======================================================= */

  postComment: (
    id: string,
    text: string,
    image?: string | null
  ) =>
    req(
      `/api/videos/${encodeURIComponent(id)}/comments`,
      {
        method: 'POST',

        body: JSON.stringify({
          text,
          image: image || undefined
        })
      }
    ),


  /* =======================================================
     VIDEOS BY USER
  ======================================================= */

  byUser: async (
    username: string
  ): Promise<NvmeVideo[]> => {
    const d = await req<{
      videos?: NvmeVideo[];
      items?: NvmeVideo[];
    }>(
      `/api/users/${encodeURIComponent(username)}/videos`
    );

    return (
      d.videos ||
      d.items ||
      []
    );
  }
};


/* =========================================================
   TRENDING
========================================================= */

export const trending = {

  /* -------------------------------------------------------
     Trending Topics
  ------------------------------------------------------- */

  topics: async (
    limit = 20
  ): Promise<NvmeTrendingTopic[]> => {
    const params = new URLSearchParams();

    params.set(
      'limit',
      String(limit)
    );

    const d = await req<{
      topics?: NvmeTrendingTopic[];
      trending_topics?: NvmeTrendingTopic[];
      items?: NvmeTrendingTopic[];
    }>(
      `/api/trending/topics?${params.toString()}`
    );

    return (
      d.topics ||
      d.trending_topics ||
      d.items ||
      []
    );
  },


  /* -------------------------------------------------------
     Trending Videos
  ------------------------------------------------------- */

  videos: async (
    limit = 20,
    cursor?: string
  ): Promise<{
    items: NvmeTrendingVideo[];
    nextCursor?: string;
  }> => {
    const params = new URLSearchParams();

    params.set(
      'limit',
      String(limit)
    );

    if (cursor) {
      params.set(
        'cursor',
        cursor
      );
    }

    const d = await req<{
      videos?: NvmeTrendingVideo[];
      items?: NvmeTrendingVideo[];
      feed?: NvmeTrendingVideo[];

      nextCursor?: string;
      next_cursor?: string;
    }>(
      `/api/trending/videos?${params.toString()}`
    );

    return {
      items:
        d.videos ||
        d.items ||
        d.feed ||
        [],

      nextCursor:
        d.nextCursor ||
        d.next_cursor
    };
  },


  /* -------------------------------------------------------
     Trending Feed
  ------------------------------------------------------- */

  feed: async (
    cursor?: string,
    sessionId?: string
  ): Promise<NvmeFeedResponse> => {
    const params = new URLSearchParams();

    if (cursor) {
      params.set(
        'cursor',
        cursor
      );
    }

    if (sessionId) {
      params.set(
        'session_id',
        sessionId
      );
    }

    const query =
      params.toString();

    const d = await req<{
      feed?: NvmeVideo[];
      videos?: NvmeVideo[];
      items?: NvmeVideo[];

      nextCursor?: string;
      next_cursor?: string;

      sessionId?: string;
      session_id?: string;
    }>(
      `/api/trending/feed${
        query
          ? `?${query}`
          : ''
      }`
    );

    return {
      items:
        d.items ||
        d.feed ||
        d.videos ||
        [],

      nextCursor:
        d.nextCursor ||
        d.next_cursor,

      sessionId:
        d.sessionId ||
        d.session_id
    };
  },


  /* -------------------------------------------------------
     Trending Topic Videos
  ------------------------------------------------------- */

  topicVideos: async (
    topic: string,
    limit = 20
  ): Promise<NvmeVideo[]> => {
    const params =
      new URLSearchParams();

    params.set(
      'topic',
      topic
    );

    params.set(
      'limit',
      String(limit)
    );

    const d = await req<{
      videos?: NvmeVideo[];
      items?: NvmeVideo[];
    }>(
      `/api/trending/topic-videos?${params.toString()}`
    );

    return (
      d.videos ||
      d.items ||
      []
    );
  }
};


/* =========================================================
   USERS
========================================================= */

export const users = {
  discover: async (): Promise<NvmeUser[]> => {
    const d = await req<{
      users?: NvmeUser[];
      items?: NvmeUser[];
    }>('/api/users/discover');

    return d.users || d.items || [];
  },

  stats: (username: string) =>
    req<{
      followers?: number;
      following?: number;
      videos?: number;
      total_views?: number;
    }>(
      `/api/users/${encodeURIComponent(username)}/stats`
    ),

  follow: (userId: string) =>
    req(
      `/api/users/${encodeURIComponent(userId)}/follow`,
      {
        method: 'POST'
      }
    )
};


/* =========================================================
   SEARCH
========================================================= */

export async function search(
  q: string
): Promise<{
  videos: NvmeVideo[];
  users: NvmeUser[];
}> {
  const params = new URLSearchParams();

  params.set('q', q);

  const d = await req<{
    videos?: NvmeVideo[];
    users?: NvmeUser[];
  }>(`/api/search?${params.toString()}`);

  return {
    videos: d.videos || [],
    users: d.users || []
  };
}


/* =========================================================
   UPLOAD
========================================================= */

export async function uploadVideo(
  file: File,
  title: string,
  description: string
): Promise<{
  url?: string;
  thumbnail?: string;
  video?: NvmeVideo;
}> {
  const fd =
    new FormData();

  fd.append(
    'video',
    file
  );

  fd.append(
    'title',
    title
  );

  fd.append(
    'description',
    description
  );

  return req(
    '/api/upload',
    {
      method: 'POST',
      body: fd
    }
  );
}


/* =========================================================
   AI
========================================================= */

export const ai = {

  status: () =>
    req<{
      model?: string;
      online?: boolean;
    }>(
      '/api/ai/status'
    ),

  captions: (
    topic: string
  ) =>
    req(
      '/api/ai/captions',
      {
        method: 'POST',

        body: JSON.stringify({
          topic
        })
      }
    ),

  hashtags: (
    topic: string
  ) =>
    req(
      '/api/ai/hashtags',
      {
        method: 'POST',

        body: JSON.stringify({
          topic
        })
      }
    ),

  script: (
    topic: string
  ) =>
    req(
      '/api/ai/script',
      {
        method: 'POST',

        body: JSON.stringify({
          topic
        })
      }
    ),

  generate: (
    prompt: string
  ) =>
    req(
      '/api/ai/generate',
      {
        method: 'POST',

        body: JSON.stringify({
          prompt
        })
      }
    )
};


/* =========================================================
   WALLET
========================================================= */

export const wallet = {

  balance: () =>
    req<NvmeWalletBalance>(
      '/api/wallet/balance'
    ),

  transactions: () =>
    req(
      '/api/wallet/transactions'
    ),

  connect: (
    address: string
  ) =>
    req(
      '/api/wallet/connect',
      {
        method: 'POST',

        body: JSON.stringify({
          address
        })
      }
    )
};


/* =========================================================
   PAYMENTS
========================================================= */

export const payments = {

  createOrder: (
    plan: string
  ) =>
    req(
      '/api/payments/paypal/create-order',
      {
        method: 'POST',

        body: JSON.stringify({
          plan
        })
      }
    ),

  captureOrder: (
    orderId: string
  ) =>
    req(
      '/api/payments/paypal/capture-order',
      {
        method: 'POST',

        body: JSON.stringify({
          orderId
        })
      }
    )
};


/* =========================================================
   FEED SESSION HELPER
========================================================= */

function getFeedSession(): string {
  if (
    typeof window === 'undefined'
  ) {
    return '';
  }

  const existing =
    sessionStorage.getItem(
      'nvme_feed_session'
    );

  if (existing) {
    return existing;
  }

  let value: string;

  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.randomUUID === 'function'
  ) {
    value =
      crypto.randomUUID();
  } else {
    value =
      `${Date.now()}-${Math.random()
        .toString(36)
        .slice(2)}`;
  }

  sessionStorage.setItem(
    'nvme_feed_session',
    value
  );

  return value;
}


/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
  auth,
  videos,
  trending,
  users,
  search,
  ai,
  wallet,
  payments,
  uploadVideo
};
