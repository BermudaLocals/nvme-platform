'use client';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Users, Crown, Globe2, Music2, UploadCloud, BadgeDollarSign, Film, Sparkles } from 'lucide-react';
import SectionWrapper, { SectionTitle } from '@/components/SectionWrapper';
import AnimatedCounter from '@/components/AnimatedCounter';
import Footer from '@/components/Footer';
import { useAuth } from '@/hooks/useAuth';
import { useQuery } from '@tanstack/react-query';
import { users as usersApi, type NvmeUser } from '@/lib/api';
import { formatCount, gradientFor, cn } from '@/lib/utils';

const CATS = ['Music', 'Comedy', 'Film', 'Dance', 'Fashion', 'Gaming'];
const TEES = [
  { name: 'Blackout Tee', grad: 'from-zinc-900 to-zinc-700' },
  { name: 'Gold Standard', grad: 'from-[#c9a227] to-[#7a5f10]' },
  { name: 'Coral Run', grad: 'from-[#ff3e3e] to-[#7a1414]' },
  { name: 'White Label', grad: 'from-zinc-200 to-zinc-400' }
];

export default function LandingPage() {
  const { isAuthenticated, openAuth } = useAuth();

  const statsQ = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      try {
        const r = await fetch('/api/stats');
        if (!r.ok) throw new Error();
        return r.json();
      } catch {
        return { creators: 2847291, watched: 892000000 };
      }
    },
    staleTime: 5 * 60 * 1000
  });

  const creatorsQ = useQuery({
    queryKey: ['creators', 'featured'],
    queryFn: () => usersApi.discover(),
    staleTime: 5 * 60 * 1000,
    retry: false
  });

  const featured: NvmeUser[] = (creatorsQ.data || []).slice(0, 6);

  return (
    <div className="relative">
      {/* ---------- HERO ---------- */}
      <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-[radial-gradient(ellipse_at_top,rgba(201,162,39,0.12),transparent_55%)] px-6 text-center">
        <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="mb-5 inline-flex items-center gap-2 rounded-full border border-nvme-gold/30 bg-nvme-gold/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.25em] text-nvme-gold">
          <Sparkles size={13} /> The Future of Short Video Entertainment
        </motion.p>
        <h1 className="font-display text-[13vw] leading-[0.95] tracking-wider sm:text-7xl md:text-8xl">
          {['WATCH.', 'CREATE.', 'EARN.'].map((w, i) => (
            <motion.span key={w} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 + i * 0.15, duration: 0.6 }}
              className={cn('block', i === 2 && 'bg-gradient-to-r from-nvme-gold to-nvme-coral bg-clip-text text-transparent')}>
              {w}
            </motion.span>
          ))}
        </h1>
        <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.7, duration: 0.6 }}
          className="mt-6 max-w-xl text-base leading-relaxed text-nvme-muted sm:text-lg">
          NVME is where audiences earn, creators grow, and digital ownership expands.
          This is bigger than content. This is an economy.
        </motion.p>
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-4">
          {isAuthenticated
            ? <Link href="/studio" className="btn-gold animate-pulse-gold">Start Creating</Link>
            : <button onClick={() => openAuth('signup')} className="btn-gold animate-pulse-gold">Start Creating</button>}
          <Link href="/feed" className="btn-outline">Explore Feed</Link>
        </motion.div>

        {/* Stats bar */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.1 }}
          className="absolute bottom-0 left-0 right-0 border-t border-white/5 bg-black/50 backdrop-blur-md">
          <div className="mx-auto grid max-w-5xl grid-cols-1 divide-y divide-white/5 py-5 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <div className="py-2 text-center">
              <p className="font-display text-2xl text-nvme-gold"><AnimatedCounter target={statsQ.data?.creators ?? 2847291} /></p>
              <p className="text-xs uppercase tracking-widest text-nvme-muted">Creators on NVME</p>
            </div>
            <div className="py-2 text-center">
              <p className="font-display text-2xl text-nvme-gold"><AnimatedCounter target={statsQ.data?.watched ?? 892000000} /></p>
              <p className="text-xs uppercase tracking-widest text-nvme-muted">Videos Watched</p>
            </div>
            <div className="flex items-center justify-center gap-2 py-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-nvme-gold opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-nvme-gold" />
              </span>
              <p className="text-sm font-semibold text-white">New creators joining now</p>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ---------- FEATURED CREATORS ---------- */}
      <SectionWrapper>
        <SectionTitle title="Featured Creators" subtitle="Support creators building with the NVME community." />
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {(featured.length > 0 ? featured : Array.from({ length: 6 }).map((_, i) => ({ id: `ph-${i}`, username: ['Nova', 'KingMel', 'AyoBeats', 'QueenJ', 'TrapScribe', 'LunaVibe'][i], followers: 12000 + i * 3700 } as NvmeUser))).map((c, i) => (
            <motion.div key={c.id}
              initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
              className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-6">
              <div className="flex items-center gap-4">
                <span className={cn('flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-lg font-black text-black ring-2 ring-nvme-gold/40', gradientFor(c.username))}>
                  {c.avatar_url ? <img src={c.avatar_url} alt="" className="h-full w-full object-cover" /> : (c.username || 'N')[0].toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-bold">{c.display_name || c.username}</p>
                  <p className="text-xs text-nvme-muted">{CATS[i % CATS.length]} · {formatCount(c.followers)} followers</p>
                </div>
              </div>
              <button
                onClick={async () => { try { await usersApi.follow(c.id); } catch { /* not signed in */ } }}
                className="mt-5 w-full rounded-full border border-nvme-gold/50 py-2 text-sm font-bold text-nvme-gold transition-all hover:bg-nvme-gold hover:text-black">
                Follow
              </button>
            </motion.div>
          ))}
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.6 }}
            className="flex flex-col items-center justify-center rounded-2xl bg-gradient-to-br from-nvme-gold to-[#8a6d15] p-6 text-center text-black">
            <Crown size={30} />
            <p className="mt-3 font-display text-lg leading-snug">BE ONE OF THE FIRST FEATURED CREATORS</p>
            <Link href="/studio" className="mt-4 rounded-full bg-black px-6 py-2.5 text-sm font-bold text-nvme-gold transition-all hover:scale-[1.03]">Apply Now</Link>
          </motion.div>
        </div>
      </SectionWrapper>

      {/* ---------- NVME UNIFORM ---------- */}
      <SectionWrapper className="!max-w-none bg-nvme-surface/40">
        <div className="mx-auto max-w-7xl">
          <SectionTitle title="THE NVME UNIFORM" subtitle="Wear The Platform. Represent The Culture." />
          <div className="grid items-center gap-10 lg:grid-cols-2">
            <div>
              <ul className="space-y-4">
                {['Support creator-owned digital infrastructure', 'Help fund creators, films, and original content', 'Represent the movement everywhere you go'].map((b, i) => (
                  <motion.li key={b} initial={{ opacity: 0, x: -16 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
                    className="flex items-start gap-3 text-base text-white/90">
                    <span className="mt-1 h-2 w-2 shrink-0 rotate-45 bg-nvme-gold" /> {b}
                  </motion.li>
                ))}
              </ul>
              <a href="https://store.nvme.live" target="_blank" rel="noreferrer" className="btn-gold mt-8">ORDER NOW — STORE.NVME.LIVE</a>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {TEES.map((t, i) => (
                <motion.div key={t.name} initial={{ opacity: 0, scale: 0.94 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} transition={{ delay: i * 0.08 }}
                  className={cn('card-hover flex aspect-[3/4] flex-col items-center justify-end rounded-2xl border border-white/10 bg-gradient-to-br p-4', t.grad)}>
                  <p className="font-display text-sm tracking-wider drop-shadow">{t.name.toUpperCase()}</p>
                  <p className="text-[10px] uppercase tracking-[0.3em] opacity-80">NVME</p>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </SectionWrapper>

      {/* ---------- NVME NATION ---------- */}
      <SectionWrapper>
        <SectionTitle title="NVME Nation" subtitle="This is more than a platform. This is a digital kingdom." />
        <div className="grid gap-5 md:grid-cols-3">
          {[
            { icon: Users, t: 'Be part of a powerful creator community' },
            { icon: Crown, t: 'Create, shop, and own your content' },
            { icon: Globe2, t: 'Connect with creators worldwide' }
          ].map((f, i) => (
            <motion.div key={f.t} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
              className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-8 text-center">
              <f.icon size={34} className="mx-auto text-nvme-gold" />
              <p className="mt-4 font-semibold leading-relaxed">{f.t}</p>
            </motion.div>
          ))}
        </div>
        <div className="mt-10 text-center">
          {isAuthenticated
            ? <Link href="/feed" className="btn-gold">Enter the Nation</Link>
            : <button onClick={() => openAuth('signup')} className="btn-gold">Join NVME Nation</button>}
        </div>
      </SectionWrapper>

      {/* ---------- NVME MUSIC ---------- */}
      <SectionWrapper className="!max-w-none bg-[radial-gradient(ellipse_at_bottom,rgba(255,62,62,0.08),transparent_60%)]">
        <div className="mx-auto max-w-7xl">
          <SectionTitle title="NVME Music" subtitle="A new era for independent artists." />
          <div className="grid gap-5 md:grid-cols-3">
            {[
              { icon: Globe2, t: 'Get discovered globally' },
              { icon: UploadCloud, t: 'Upload and monetize instantly' },
              { icon: BadgeDollarSign, t: 'Earn 70%+ revenue' }
            ].map((f, i) => (
              <motion.div key={f.t} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
                className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-8 text-center">
                <f.icon size={34} className="mx-auto text-nvme-gold" />
                <p className="mt-4 font-semibold">{f.t}</p>
              </motion.div>
            ))}
          </div>
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="mt-10 flex flex-col items-center gap-4 rounded-2xl border border-nvme-gold/25 bg-black/40 p-8 text-center">
            <Film size={30} className="text-nvme-gold" />
            <h3 className="font-display text-2xl tracking-wide">Distribute Your Film on NVME Networks</h3>
            <p className="max-w-2xl text-sm leading-relaxed text-nvme-muted">
              Filmmakers: bring your shorts, docs, and features to a platform built for ownership.
              Keep your rights, reach a global audience, and get paid directly by the culture you move.
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <Link href="/discover?cat=Music" className="btn-gold">Explore NVME Music</Link>
              <Link href="/studio" className="btn-outline">Submit Your Film</Link>
            </div>
          </motion.div>
        </div>
      </SectionWrapper>

      <Footer />
    </div>
  );
}
