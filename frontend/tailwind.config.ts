import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        nvme: {
          bg: '#0a0a0a',
          surface: '#141414',
          card: '#181818',
          gold: '#c9a227',
          goldlight: '#e8c84a',
          coral: '#ff3e3e',
          text: '#ffffff',
          muted: '#a3a3a3',
          border: 'rgba(255,255,255,0.06)'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Archivo Black', 'Inter', 'sans-serif']
      },
      animation: {
        'grain': 'grain 8s steps(10) infinite',
        'pulse-gold': 'pulseGold 3s ease-in-out infinite',
        'float': 'float 6s ease-in-out infinite'
      },
      keyframes: {
        grain: {
          '0%,100%': { transform: 'translate(0,0)' },
          '10%': { transform: 'translate(-5%,-10%)' },
          '30%': { transform: 'translate(3%,-15%)' },
          '50%': { transform: 'translate(12%,9%)' },
          '70%': { transform: 'translate(9%,4%)' },
          '90%': { transform: 'translate(-1%,7%)' }
        },
        pulseGold: {
          '0%,100%': { boxShadow: '0 0 20px rgba(201,162,39,0.35)' },
          '50%': { boxShadow: '0 0 44px rgba(201,162,39,0.65)' }
        },
        float: {
          '0%,100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-12px)' }
        }
      }
    }
  },
  plugins: []
};
export default config;
