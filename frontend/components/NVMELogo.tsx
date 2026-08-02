'use client';

export default function NVMELogo({ size = 40, withWordmark = true }: { size?: number; withWordmark?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 select-none" aria-label="NVME">
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" className="drop-shadow-[0_0_12px_rgba(201,162,39,0.5)]">
        <defs>
          <linearGradient id="nvmeg" x1="0" y1="0" x2="48" y2="48">
            <stop offset="0" stopColor="#e8c84a" />
            <stop offset="0.55" stopColor="#c9a227" />
            <stop offset="1" stopColor="#ff3e3e" />
          </linearGradient>
        </defs>
        <rect x="2" y="2" width="44" height="44" rx="12" fill="#141414" stroke="url(#nvmeg)" strokeWidth="2" />
        {/* Play triangle integrated as the V */}
        <path d="M19 15 L33 24 L19 33 Z" fill="url(#nvmeg)" />
        {/* Wordmark strokes: N _ M E around the V */}
        <text x="10" y="31" fontFamily="Archivo Black, Inter, sans-serif" fontSize="15" fontWeight="900" fill="#ffffff">N</text>
        <text x="32" y="31" fontFamily="Archivo Black, Inter, sans-serif" fontSize="15" fontWeight="900" fill="#ffffff" opacity="0.9">E</text>
      </svg>
      {withWordmark && (
        <span className="font-display text-xl tracking-[0.22em] text-white">
          NV<span className="text-nvme-gold">M</span>E
        </span>
      )}
    </span>
  );
}
