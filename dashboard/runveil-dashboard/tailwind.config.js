/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{html,ts}"],
  theme: {
    extend: {
      colors: {
        rv: {
          bg: "#0B0F17",        // app background
          surface: "#101826",   // cards/panels
          surface2: "#0F1623",  // slightly different surface
          border: "#1E2A3B",    // subtle borders
          text: "#E6EDF6",      // primary text
          muted: "#9AA9BD",     // secondary text
          accent: "#FF6A00"     // Runveil orange
        }
      }
    },
  },
  plugins: [],
};
