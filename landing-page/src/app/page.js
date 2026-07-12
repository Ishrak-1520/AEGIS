import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import FeatureShowcase from "@/components/FeatureShowcase";
import SetupGuide from "@/components/SetupGuide";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <main className="min-h-screen bg-[#070B14] text-[#F1F5F9] selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar />
      <Hero />
      <FeatureShowcase />
      <SetupGuide />
      <Footer />
    </main>
  );
}
