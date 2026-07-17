/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        brand: {
          light: '#F8F9FA',
          accent: '#13B497',
          accentHover: '#0f967d',
          dark: '#1B2939',
          gray: '#6E7A8A',
          border: '#EAEFF4'
        }
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Outfit', 'system-ui', 'sans-serif'],
      }
    }
  },
  plugins: [],
}
