import Link from 'next/link';
import NVMELogo from './NVMELogo';
import { Instagram, Twitter, Youtube, Facebook } from 'lucide-react';

const COLS = [
  { title: 'Platform', links: [['Discover', '/discover'], ['Creators', '/feed'], ['Studio', '/studio'], ['Music', '/discover?cat=Music']] },
  { title: 'Community', links: [['Store', 'https://store.nvme.live'], ['Support', '/discover'], ['Contact', 'mailto:team@nvme.live']] },
  { title: 'Legal', links: [['Terms', '/#'], ['Privacy', '/#'], ['DMCA', '/#']] }
];

export default function Footer() {
  return (
    <footer className="relative z-10 border-t border-white/5 bg-nvme-surface/60">
      <div className="mx-auto grid max-w-7xl gap-10 px-6 py-14 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <NVMELogo />
          <p className="mt-4 max-w-xs text-sm leading-relaxed text-nvme-muted">
            The Future of Short Video Entertainment. Watch. Create. Earn.
          </p>
          <div className="mt-5 flex gap-3">
            {[Instagram, Twitter, Youtube, Facebook].map((Icon, i) => (
              <a key={i} href="#" aria-label="Social link" className="focus-ring flex h-9 w-9 items-center justify-center rounded-full border border-white/10 text-nvme-muted transition-all hover:border-nvme-gold hover:text-nvme-gold">
                <Icon size={16} />
              </a>
            ))}
          </div>
        </div>
        {COLS.map((c) => (
          <div key={c.title}>
            <h3 className="mb-4 text-xs font-black uppercase tracking-[0.2em] text-nvme-gold">{c.title}</h3>
            <ul className="space-y-2.5">
              {c.links.map(([label, href]) => (
                <li key={label}>
                  <Link href={href} className="text-sm text-nvme-muted transition-colors hover:text-white">{label}</Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-white/5 py-6 text-center text-xs text-nvme-muted">
        © 2026 NVME. All rights reserved. — Pronounced &quot;Envy Me&quot;
      </div>
    </footer>
  );
}
