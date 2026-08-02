import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatCount(n?: number | null): string {
  const v = Number(n || 0);
  if (v >= 1_000_000) return (v / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (v >= 1_000) return (v / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
  return v.toLocaleString();
}

export function gradientFor(seed?: string): string {
  const gradients = [
    'from-[#c9a227] to-[#ff3e3e]',
    'from-[#7c3aed] to-[#c9a227]',
    'from-[#ff3e3e] to-[#7c3aed]',
    'from-[#06b6d4] to-[#c9a227]',
    'from-[#c9a227] to-[#06b6d4]',
    'from-[#f59e0b] to-[#ff3e3e]'
  ];
  let h = 0;
  const s = seed || 'nvme';
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return gradients[h % gradients.length];
}
