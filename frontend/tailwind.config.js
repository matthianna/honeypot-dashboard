/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Background colors
        'bg-primary': '#0a0a0f',
        'bg-secondary': '#12121a',
        'bg-card': '#1a1a25',
        'bg-hover': '#252532',
        // Neon accent colors
        'neon-green': '#39ff14',
        'neon-blue': '#00d4ff',
        'neon-orange': '#ff6600',
        'neon-purple': '#bf00ff',
        'neon-red': '#ff3366',
        'neon-yellow': '#ffff00',
        // Text colors
        'text-primary': '#e0e0e0',
        'text-secondary': '#888888',
        'text-muted': '#555555',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
        'display': ['Orbitron', 'sans-serif'],
      },
      boxShadow: {
        'neon-green': '0 0 20px rgba(57, 255, 20, 0.3)',
        'neon-blue': '0 0 20px rgba(0, 212, 255, 0.3)',
        'neon-orange': '0 0 20px rgba(255, 102, 0, 0.3)',
        'neon-purple': '0 0 20px rgba(191, 0, 255, 0.3)',
        'neon-red': '0 0 20px rgba(255, 51, 102, 0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px currentColor' },
          '100%': { boxShadow: '0 0 20px currentColor, 0 0 30px currentColor' },
        },
      },
    },
  },
  plugins: [],
}

