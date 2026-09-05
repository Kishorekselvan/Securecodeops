/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0f1d',
          surface: '#11192e',
          panel: '#16203a',
          border: '#1f2e4d',
          cyan: '#00f0ff',
          blue: '#3b82f6',
          green: '#10b981',
          yellow: '#f59e0b',
          red: '#ef4444',
          purple: '#8b5cf6',
          muted: '#94a3b8'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'cyber-cyan': '0 0 20px rgba(0, 240, 255, 0.15)',
        'cyber-red': '0 0 20px rgba(239, 68, 68, 0.2)',
        'cyber-green': '0 0 20px rgba(16, 185, 129, 0.2)',
      }
    },
  },
  plugins: [],
}
