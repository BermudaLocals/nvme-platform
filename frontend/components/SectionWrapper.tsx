'use client';
import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

export default function SectionWrapper({ children, className = '', id }: { children: ReactNode; className?: string; id?: string }) {
  return (
    <motion.section
      id={id}
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
      className={`relative z-10 mx-auto w-full max-w-7xl px-6 py-20 ${className}`}
    >
      {children}
    </motion.section>
  );
}

export function SectionTitle({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-12 text-center">
      <motion.h2
        initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.5 }}
        className="font-display text-3xl tracking-wide sm:text-4xl"
      >
        {title}
      </motion.h2>
      {subtitle && (
        <motion.p
          initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay: 0.15, duration: 0.5 }}
          className="mt-3 text-nvme-muted"
        >
          {subtitle}
        </motion.p>
      )}
    </div>
  );
}
