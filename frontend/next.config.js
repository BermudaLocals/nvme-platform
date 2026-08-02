/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Static export — served by the Express monolith from public/next/
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true }
};
module.exports = nextConfig;
