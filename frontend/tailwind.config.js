/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'hacker-black': '#0b0f19',
        'hacker-dark': '#0f172a',
        'neon-green': '#00ff41',
        'neon-red': '#ff0033',
        'neon-blue': '#00f3ff',
        'dim-gray': '#1e293b',
      },
      fontFamily: {
        mono: ['"Fira Code"', '"Courier New"', 'monospace'],
      },
      animation: {
        'scanline': 'scanline 8s linear infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        }
      }
    },
  },
  plugins: [],
}
