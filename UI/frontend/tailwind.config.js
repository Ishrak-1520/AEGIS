/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                primary: '#00F3FF', // Cyan
                secondary: '#BC13FE', // Neon Purple
                background: '#050B14', // Deep Dark Blue/Black
                surface: '#0F1926', // Lighter Dark
                success: '#00FF9D', // Neon Green
                warning: '#FFB800',
                error: '#FF003C', // Neon Red
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
        },
    },
    plugins: [],
}
