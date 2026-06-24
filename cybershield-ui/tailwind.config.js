/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      '#0a0e1a',
          bg2:     '#0f1626',
          bg3:     '#141c30',
          card:    '#151d35',
          card2:   '#1a2440',
          border:  'rgba(255,255,255,0.08)',
          text:    '#e8eaf0',
          text2:   '#a8b2c8',
          text3:   '#6b7a9e',
          accent:  '#4f7cff',
          accent2: '#7c3aed',
          safe:    '#10b981',
          low:     '#3b82f6',
          sus:     '#f59e0b',
          high:    '#ef4444',
          mal:     '#a855f7',
        }
      },
      fontFamily: {
        sans: ['Inter','system-ui','sans-serif'],
        mono: ['IBM Plex Mono','Courier New','monospace'],
      },
      boxShadow: {
        glow:    '0 0 24px rgba(79,124,255,0.25)',
        'glow-lg':'0 0 48px rgba(79,124,255,0.35)',
      },
      animation: {
        'spin-slow': 'spin 2s linear infinite',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
      },
      keyframes: {
        pulseGlow: {
          '0%,100%': { boxShadow: '0 0 10px rgba(79,124,255,0.3)' },
          '50%':     { boxShadow: '0 0 30px rgba(79,124,255,0.7)' },
        },
        fadeIn:  { from: { opacity: 0 },            to: { opacity: 1 } },
        slideUp: { from: { opacity: 0, transform: 'translateY(16px)' },
                   to:   { opacity: 1, transform: 'translateY(0)' } },
      }
    },
  },
  plugins: [],
}
