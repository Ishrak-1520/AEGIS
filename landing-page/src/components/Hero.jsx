"use client";

import React, { useState } from "react";
import { ArrowUpRight, CheckCircle2 } from "lucide-react";

export default function Hero() {
  const [activeEngine, setActiveEngine] = useState("hids");

  return (
    <section className="relative pt-36 pb-20 md:pt-44 md:pb-28 border-b border-white/10 overflow-hidden">
      {/* Continuous Loop Ambient Background Animation */}
      <div className="absolute inset-0 pointer-events-none z-0 overflow-hidden">
        {/* Soft drifting ambient orb 1 */}
        <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] rounded-full bg-cyan-500/10 blur-[130px] animate-ambient-1" />
        {/* Soft drifting ambient orb 2 */}
        <div className="absolute top-1/3 right-1/4 w-[600px] h-[450px] rounded-full bg-indigo-500/10 blur-[140px] animate-ambient-2" />
        {/* Soft drifting ambient orb 3 */}
        <div className="absolute bottom-10 left-1/3 w-[450px] h-[450px] rounded-full bg-white/5 blur-[120px] animate-ambient-3" />
        {/* Subtle grid mesh overlay */}
        <div
          className="absolute inset-0 opacity-15"
          style={{
            backgroundImage: `radial-gradient(rgba(255, 255, 255, 0.25) 1px, transparent 1px)`,
            backgroundSize: "36px 36px",
          }}
        />
      </div>

      <div className="max-w-7xl mx-auto px-6 sm:px-10 relative z-10">
        {/* Top editorial index header */}
        <div className="flex items-center justify-between pb-6 border-b border-white/10 text-xs font-mono uppercase tracking-widest text-neutral-400">
          <div>Open-Source Windows Protection</div>
          <div>1 — 4</div>
        </div>

        {/* Editorial Headline & Actions Section */}
        <div className="pt-14 pb-8 max-w-5xl">
          <span className="inline-block text-xs sm:text-sm font-mono uppercase tracking-widest px-3 py-1.5 rounded-full border border-white/15 bg-white/5 text-neutral-300 mb-6">
            Lightweight Desktop Suite
          </span>

          <h1 className="text-5xl sm:text-7xl md:text-8xl font-normal tracking-tight leading-[1.02] text-white">
            Smart security made <em className="font-editorial italic text-neutral-300">simple</em>.
          </h1>

          <p className="mt-8 text-lg sm:text-xl text-neutral-400 font-normal leading-relaxed max-w-2xl">
            Hardened endpoint defense, network filtering, and code auditing in a clean Windows app.
          </p>

          <div className="mt-10 flex flex-wrap items-center gap-4">
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="px-8 py-4 rounded-full bg-white text-black font-semibold text-sm sm:text-base hover:bg-neutral-200 transition-all flex items-center gap-2 group shadow-sm"
            >
              Download AEGIS.exe
              <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </a>
            <a
              href="#installation"
              className="px-8 py-4 rounded-full bg-[#18181B] border border-white/15 text-white text-sm sm:text-base font-medium hover:border-white/30 hover:bg-[#202024] transition-all"
            >
              View Setup Guide
            </a>
          </div>
        </div>

        {/* Interactive Desktop Console Preview */}
        <div id="showcase" className="mt-16 border border-white/10 rounded-2xl bg-[#121214]/90 backdrop-blur-xl overflow-hidden shadow-2xl">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 px-6 py-4 border-b border-white/10 bg-[#161619]">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
              </div>
              <span className="text-xs font-mono text-neutral-400">AEGIS Desktop Suite v2.0.0 — Live Status</span>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Runtime Engines Ready
            </div>
          </div>

          <div className="p-6 sm:p-8">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
              {[
                { id: "hids", label: "Volatile Guardian", type: "HIDS PE Scanner" },
                { id: "nids", label: "RT-XNIDS", type: "Scapy Network IPS" },
                { id: "sift", label: "SIFT Auditor", type: "Gemma 4 Code Scan" },
                { id: "nlp", label: "Threat AI", type: "Bilingual Scam NLP" },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveEngine(item.id)}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    activeEngine === item.id
                      ? "bg-white text-black border-white shadow-md"
                      : "bg-[#18181B] text-neutral-400 border-white/10 hover:border-white/20 hover:text-white"
                  }`}
                >
                  <div className="text-xs font-mono uppercase tracking-wider opacity-60">{item.type}</div>
                  <div className="text-sm font-semibold mt-1">{item.label}</div>
                </button>
              ))}
            </div>

            {/* Console Output */}
            <div className="p-6 rounded-xl bg-[#0A0A0C] border border-white/10 font-mono text-xs sm:text-sm text-neutral-300">
              {activeEngine === "hids" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: VOLATILE GUARDIAN (PE IMPORT ADDRESS TABLE INSPECTION)</div>
                  <div className="text-white">Active process monitoring via Portable Executable headers</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Evaluates Windows API call sequences to detect packed or obfuscated malware before it can execute or inject into memory.
                  </p>
                </div>
              )}

              {activeEngine === "nids" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: RT-XNIDS (SCAPY PACKET CAPTURE & WINDOWS FIREWALL)</div>
                  <div className="text-white">Real-time driver interface: Npcap WinPcap mode</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Monitors live network traffic entropy and automatically applies Windows Firewall rules to block malicious incoming or outgoing connections.
                  </p>
                </div>
              )}

              {activeEngine === "sift" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: SIFT AI CODE AUDITOR (STATIC AST + OPENROUTER GEMMA 4)</div>
                  <div className="text-white">Python AST parser + PyPI dependency verification enabled</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Audits Python scripts for vulnerabilities like SQL injection and verifies dependencies against PyPI to catch typosquatting packages.
                  </p>
                </div>
              )}

              {activeEngine === "nlp" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: THREAT AI (BILINGUAL SCAM & PHISHING DEFENSE)</div>
                  <div className="text-white">Supported Languages: English & Bangla (bKash / Nagad / Rocket)</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Analyzes regional scam patterns and highlights suspicious trigger words clearly so you can identify phishing attempts immediately.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
