"use client";

import React, { useState } from "react";
import { ArrowUpRight, CheckCircle2, ShieldAlert } from "lucide-react";

export default function Hero() {
  const [activeEngine, setActiveEngine] = useState("hids");

  return (
    <section className="pt-36 pb-20 md:pt-48 md:pb-32 border-b border-white/10">
      <div className="max-w-7xl mx-auto px-6 sm:px-10">
        {/* Top editorial index header */}
        <div className="flex items-center justify-between pb-8 border-b border-white/10 text-xs font-mono uppercase tracking-widest text-neutral-400">
          <div>Next-Generation Windows Cybersecurity</div>
          <div>1 — 4</div>
        </div>

        {/* Editorial Headline Section */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 pt-12 items-end">
          <div className="lg:col-span-8">
            <h1 className="text-5xl sm:text-7xl md:text-8xl font-light leading-[0.95] tracking-tight">
              <span className="block text-xl sm:text-2xl font-mono uppercase tracking-widest text-neutral-400 mb-4">
                (We build)
              </span>
              <span>
                h<em className="font-editorial italic">a</em>rdened
              </span>
              <br />
              <span>
                W<em className="font-editorial italic">i</em>ndows
              </span>
              <br />
              <span>
                d<em className="font-editorial italic">e</em>fense.
              </span>
            </h1>
          </div>

          <div className="lg:col-span-4 space-y-6">
            <p className="text-base sm:text-lg text-neutral-400 font-normal leading-relaxed">
              An open-source desktop suite combining local Import Address Table inspection, live Scapy packet filtering, bilingual scam analysis, and LLM code auditing.
            </p>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 pt-2">
              <a
                href="https://github.com/Ishrak-1520/AEGIS/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="px-7 py-4 rounded-full bg-white text-black font-semibold text-sm hover:bg-neutral-200 transition-colors flex items-center justify-center gap-2 group"
              >
                Download AEGIS.exe
                <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              </a>
              <a
                href="#installation"
                className="px-7 py-4 rounded-full border border-white/20 text-white text-sm font-medium hover:border-white/40 transition-colors text-center"
              >
                Installation Guide
              </a>
            </div>
          </div>
        </div>

        {/* Interactive Desktop Console Preview */}
        <div id="showcase" className="mt-20 border border-white/10 rounded-2xl bg-[#121214] overflow-hidden">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 px-6 py-4 border-b border-white/10 bg-[#161619]">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
                <span className="w-2.5 h-2.5 rounded-full bg-neutral-600" />
              </div>
              <span className="text-xs font-mono text-neutral-400">AEGIS Desktop Engine v2.0.0 — Live Status</span>
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
                      ? "bg-white text-black border-white"
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
                  <div className="text-white">Active process monitoring via psutil & Portable Executable headers</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Evaluates API sequences (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) using pre-trained Random Forest classifiers to catch packed and evasive Windows malware before memory injection.
                  </p>
                </div>
              )}

              {activeEngine === "nids" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: RT-XNIDS (SCAPY PACKET CAPTURE & WINDOWS FIREWALL)</div>
                  <div className="text-white">Real-time driver interface: Npcap WinPcap mode</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Inspects live packet entropy and automatically applies Windows Firewall drop rules when malicious IP flood thresholds or port scan baselines are exceeded.
                  </p>
                </div>
              )}

              {activeEngine === "sift" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: SIFT AI CODE AUDITOR (STATIC AST + OPENROUTER GEMMA 4)</div>
                  <div className="text-white">Python AST parser + PyPI dependency verification enabled</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Audits Python source code for SQL injections and checks `requirements.txt` against official PyPI registries to catch typosquatting packages.
                  </p>
                </div>
              )}

              {activeEngine === "nlp" && (
                <div className="space-y-2">
                  <div className="text-neutral-500">ENGINE: THREAT AI (BILINGUAL SCAM & PHISHING DEFENSE)</div>
                  <div className="text-white">Supported Languages: English & Bangla (bKash / Nagad / Rocket)</div>
                  <p className="text-neutral-400 font-sans text-sm leading-relaxed pt-2">
                    Provides Explainable AI interpretability by highlighting suspicious trigger words without flagging legitimate personal or financial communication.
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
