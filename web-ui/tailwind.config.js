/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Custom dark theme colors
        background: '#0a0a0a',
        foreground: '#fafafa',
        muted: '#27272a',
        'muted-foreground': '#a1a1aa',
        border: '#27272a',
        input: '#27272a',
        ring: '#3b82f6',
        primary: {
          DEFAULT: '#3b82f6',
          foreground: '#fafafa',
        },
        secondary: {
          DEFAULT: '#27272a',
          foreground: '#fafafa',
        },
        destructive: {
          DEFAULT: '#ef4444',
          foreground: '#fafafa',
        },
        accent: {
          DEFAULT: '#27272a',
          foreground: '#fafafa',
        },
        success: {
          DEFAULT: '#22c55e',
          foreground: '#fafafa',
        },
        warning: {
          DEFAULT: '#f59e0b',
          foreground: '#fafafa',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SF Mono', 'Monaco', 'Cascadia Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'blink': 'blink 1s ease-in-out infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
      },
    },
  },
  plugins: [],
}
