import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Ticker from "@/components/Ticker";
import FeatureShowcase from "@/components/FeatureShowcase";
import SetupGuide from "@/components/SetupGuide";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <main className="min-h-screen bg-[#0D0D0E] text-[#F3F3F3]">
      <Navbar />
      <Hero />
      <Ticker />
      <FeatureShowcase />
      <SetupGuide />
      <Footer />
    </main>
  );
}
