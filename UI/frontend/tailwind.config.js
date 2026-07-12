/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                primary: '#3B82F6', // Professional Blue
                secondary: '#8B5CF6', // Muted Violet
                background: '#0F1117', // Clean near-black
                surface: '#1A1D27', // Charcoal panel
                success: '#22C55E', // Natural Green
                warning: '#F59E0B', // Amber
                error: '#EF4444', // Standard Red
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
        },
    },
    plugins: [],
}
