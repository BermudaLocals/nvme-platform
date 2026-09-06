import type { Metadata, Viewport } from 'next';
import './globals.css';
import Providers from '@/components/Providers';
import Navbar from '@/components/Navbar';
import BottomNav from './components/BottomNav';

export const metadata: Metadata = {
  title: 'NVME — Watch. Create. Earn.',
  description: 'NVME is where audiences earn, creators grow, and digital ownership expands. The future of short video entertainment.',
  openGraph: { title: 'NVME — Watch. Create. Earn.', description: 'The future of short video entertainment.', siteName: 'NVME' }
};

export const viewport: Viewport = { 
  themeColor: '#0a0a0a', 
  width: 'device-width', 
  initialScale: 1, 
  viewportFit: 'cover' 
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=Inter:wght@400;600;700;900&display=swap" rel="stylesheet" />
      </head>
      <body>
        <Providers>
          <div className="grain-overlay" aria-hidden="true" />
          <Navbar />
          <main style={{ paddingBottom: '83px' }}>{children}</main>
          <BottomNav />
        </Providers>
      </body>
    </html>
  );
}
