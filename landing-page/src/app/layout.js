import { Inter, Instrument_Serif } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const serif = Instrument_Serif({
  weight: "400",
  style: ["normal", "italic"],
  subsets: ["latin"],
  variable: "--font-serif",
});

export const metadata = {
  title: "AEGIS — Advanced Endpoint Guard & Intelligence System",
  description:
    "An open-source cybersecurity suite combining local machine learning PE inspection, real-time network packet filtering, bilingual scam detection, and LLM code auditing for Windows.",
  icons: {
    icon: "/logo.jpg",
    shortcut: "/logo.jpg",
    apple: "/logo.jpg",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${inter.variable} ${serif.variable} antialiased`}>
      <body className="bg-[#0D0D0E] text-[#F3F3F3] font-sans antialiased selection:bg-white selection:text-black">
        {children}
      </body>
    </html>
  );
}
