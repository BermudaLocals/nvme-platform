/** @type {import('next').NextConfig} */
const API = process.env.API_BASE_URL || process.env.NEXT_PUBLIC_API_URL || 'https://nvme.live';
const nextConfig = {
  reactStrictMode: true,
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: '**' },
      { protocol: 'https', hostname: 'images.unsplash.com' }
    ]
  },
  async rewrites() {
    // Proxy API + socket + auth to the monolith so the frontend can be same-origin
    return [
      { source: '/api/:path*', destination: `${API}/api/:path*` },
      { source: '/auth/:path*', destination: `${API}/auth/:path*` },
      { source: '/socket.io/:path*', destination: `${API}/socket.io/:path*` }
    ];
  }
};
module.exports = nextConfig;
