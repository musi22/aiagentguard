import type { Config } from 'tailwindcss';
export default {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: { extend: { colors: { ink: '#0b1220', surface: '#101a2e', lime: '#9ef01a' } } },
  plugins: [],
} satisfies Config;
