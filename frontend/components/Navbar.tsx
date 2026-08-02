'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Bell, Menu, X, Compass, Users, Clapperboard, Music2, Store } from 'lucide-react';
import NVMELogo from './NVMELogo';
import AuthModal from './AuthModal';
import { useAuth } from '@/hooks/useAuth';
import { getSocket, type NvmeNotification } from '@/lib/socket';
import { cn } from '@/lib/utils';

const LINKS = [
  { href: '/discover', label: 'Discover', icon: Compass },
  { href: '/feed', label: 'Creators', icon: Users },
  { href: '/studio', label: 'Studio', icon: Clapperboard },
  { href: '/discover?cat=Music', label: 'Music', icon: Music2 },
  { href: 'https://store.nvme.live', label: 'Store', icon: Store, external: true }
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [notifs, setNotifs] = useState<NvmeNotification[]>([]);
  const [bellOpen, setBellOpen] = useState(false);
  const pathname = usePathname();
  const { user, isAuthenticated, openAuth, logout, authModalOpen, authMode, closeAuth } = useAuth();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 50);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    const s = getSocket();
    const onNotif = (n: NvmeNotification) => setNotifs((p) => [{ ...n, ts: Date.now() }, ...p].slice(0, 20));
    s.on('notification', onNotif);
    s.on('notify', onNotif);
    return () => { s.off('notification', onNotif); s.off('notify', onNotif); };
  }, []);

  const unread = notifs.length;

  return (
    <>
      <nav className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        scrolled ? 'glass' : 'bg-transparent'
      )}>
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
          <Link href="/" aria-label="NVME home" className="focus-ring rounded-lg"><NVMELogo /></Link>

          <div className="hidden items-center gap-7 md:flex">
            {LINKS.map((l) => (
              <Link key={l.label} href={l.href} target={l.external ? '_blank' : undefined}
                className={cn('text-sm font-semibold tracking-wide text-nvme-muted transition-colors hover:text-nvme-gold',
                  pathname === l.href && 'text-nvme-gold')}>
                {l.label}
              </Link>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <Link href="/discover" aria-label="Search" className="focus-ring rounded-full p-2 text-nvme-muted transition-colors hover:text-nvme-gold">
              <Search size={19} />
            </Link>

            <div className="relative">
              <button aria-label="Notifications" onClick={() => { setBellOpen(!bellOpen); if (!bellOpen) setNotifs([]); }}
                className="focus-ring relative rounded-full p-2 text-nvme-muted transition-colors hover:text-nvme-gold">
                <Bell size={19} />
                {unread > 0 && (
                  <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-nvme-coral px-1 text-[10px] font-bold text-white animate-pulse">
                    {unread > 9 ? '9+' : unread}
                  </span>
                )}
              </button>
              <AnimatePresence>
                {bellOpen && (
                  <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 6 }}
                    className="absolute right-0 mt-2 w-72 rounded-xl border border-nvme-border bg-nvme-surface p-3 shadow-2xl">
                    <p className="mb-2 text-xs font-bold uppercase tracking-wider text-nvme-muted">Notifications</p>
                    {notifs.length === 0
                      ? <p className="py-4 text-center text-sm text-nvme-muted">You&apos;re all caught up ✨</p>
                      : notifs.slice(0, 6).map((n, i) => (
                        <div key={i} className="border-t border-white/5 py-2 text-sm first:border-0">{n.message}</div>
                      ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {isAuthenticated && user ? (
              <Link href="/studio" className="focus-ring flex items-center gap-2 rounded-full border border-nvme-gold/40 bg-nvme-surface py-1 pl-1 pr-3 transition-all hover:border-nvme-gold">
                <span className="flex h-7 w-7 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br from-nvme-gold to-nvme-coral text-xs font-black text-black">
                  {user.avatar_url ? <img src={user.avatar_url} alt="" className="h-full w-full object-cover" /> : (user.username || 'U')[0].toUpperCase()}
                </span>
                <span className="hidden text-xs font-bold sm:inline">@{user.username}</span>
              </Link>
            ) : (
              <button onClick={() => openAuth('signin')} className="btn-gold !px-5 !py-2 text-xs">Sign In</button>
            )}

            <button aria-label="Menu" onClick={() => setDrawer(true)} className="focus-ring rounded-full p-2 text-white md:hidden">
              <Menu size={22} />
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile drawer */}
      <AnimatePresence>
        {drawer && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] bg-black/70" onClick={() => setDrawer(false)} />
            <motion.aside initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', damping: 28, stiffness: 260 }}
              className="fixed right-0 top-0 z-[70] flex h-full w-72 flex-col bg-nvme-surface p-6">
              <div className="mb-8 flex items-center justify-between">
                <NVMELogo size={34} />
                <button aria-label="Close menu" onClick={() => setDrawer(false)} className="focus-ring rounded-full p-2 text-nvme-muted hover:text-white"><X size={20} /></button>
              </div>
              <div className="flex flex-col gap-1">
                {LINKS.map((l) => (
                  <Link key={l.label} href={l.href} target={l.external ? '_blank' : undefined} onClick={() => setDrawer(false)}
                    className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-semibold text-nvme-muted transition-colors hover:bg-white/5 hover:text-nvme-gold">
                    <l.icon size={18} /> {l.label}
                  </Link>
                ))}
              </div>
              <div className="mt-auto">
                {isAuthenticated ? (
                  <button onClick={() => { logout(); setDrawer(false); }} className="btn-outline w-full">Sign out</button>
                ) : (
                  <button onClick={() => { setDrawer(false); openAuth('signup'); }} className="btn-gold w-full">Join NVME</button>
                )}
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <AuthModal open={authModalOpen} mode={authMode} onClose={closeAuth} />
    </>
  );
}
