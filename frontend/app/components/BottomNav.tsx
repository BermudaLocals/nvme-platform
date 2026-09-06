'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

export default function BottomNav() {
  const path = usePathname()
  const isActive = (p: string) => path === p || (p !== '/' && path?.startsWith(p))

  return (
    <nav className="bottom-nav">
      <Link href="/" className={path === '/' ? 'active' : ''}>
        <svg viewBox="0 0 24 24"><path d="M12 3L2 12h3v8h6v-6h2v6h6v-8h3L12 3z"/></svg>
        <span>Home</span>
      </Link>
      <Link href="/discover" className={isActive('/discover') ? 'active' : ''}>
        <svg viewBox="0 0 24 24"><path d="M10 18a7.5 7.5 0 115.2-2.2l5.5 5.5-1.5 1.5-5.5-5.5A7.5 7.5 0 0110 18zM10 16a6 6 0 100-12 6 6 0 000 12z"/></svg>
        <span>Friends</span>
      </Link>
      <Link href="/create" className="plus-link">
        <div className="plus-box"><span>+</span></div>
      </Link>
      <Link href="/inbox" className={isActive('/inbox') ? 'active' : ''}>
        <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h14l4 4V4c0-1.1-.9-2-2-2zM6 9h12v2H6V9zm8 5H6v-2h8v2zm4-6H6V6h12v2z"/></svg>
        <span>Inbox</span>
      </Link>
      <Link href="/profile" className={isActive('/profile') ? 'active' : ''}>
        <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4S14.21 4 12 4 8 5.79 8 8s1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
        <span>Profile</span>
      </Link>

      <style jsx>{`
        .bottom-nav{position:fixed;bottom:0;left:0;right:0;height:83px;background:black;border-top:1px solid #222;display:flex;justify-content:space-around;align-items:flex-start;padding-top:8px;padding-bottom:calc(8px + env(safe-area-inset-bottom));z-index:100}
        .bottom-nav a{display:flex;flex-direction:column;align-items:center;gap:3px;color:#8a8a8a;text-decoration:none;font-size:10px;min-width:48px}
        .bottom-nav a.active{color:white}.bottom-nav a.active svg{fill:white}
        .bottom-nav svg{width:27px;height:27px;fill:#8a8a8a}
        .plus-link{padding-top:2px}
        .plus-box{width:44px;height:30px;background:white;border-radius:8px;display:flex;align-items:center;justify-content:center;position:relative}
        .plus-box::before{content:'';position:absolute;left:-4px;top:0;width:44px;height:30px;background:#25F4EE;border-radius:8px;z-index:-1;transform:translateX(-2px)}
        .plus-box::after{content:'';position:absolute;left:4px;top:0;width:44px;height:30px;background:#FE2C55;border-radius:8px;z-index:-2;transform:translateX(2px)}
        .plus-box span{font-size:22px;font-weight:900;color:black;line-height:1}
      `}</style>
    </nav>
  )
}
