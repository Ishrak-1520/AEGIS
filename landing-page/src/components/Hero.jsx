"use client";

import React, { useState } from "react";
import { Shield, Download, ExternalLink, Activity, Terminal, Lock, Network, CheckCircle2 } from "lucide-react";

export default function Hero() {
  const [activeTab, setActiveTab] = useState("hids");

  return (
    <section className="relative pt-32 pb-20 md:pt-40 md:pb-28 overflow-hidden bg-grid-pattern">
      {/* Background glow orb */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-gradient-to-tr from-cyan-500/15 to-blue-600/15 rounded-full blur-[120px] pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center max-w-3xl mx-auto space-y-6">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 text-xs font-medium text-slate-300">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            OPEN SOURCE WINDOWS ENDPOINT PROTECTION
          </div>

          {/* Main Title */}
          <h1 className="text-4xl sm:text-6xl font-extrabold text-white tracking-tight leading-[1.1]">
            Next-Generation Security & Code Intelligence for Windows
          </h1>

          {/* Subtitle */}
          <p className="text-lg sm:text-xl text-slate-400 font-normal leading-relaxed">
            Defend endpoints against packed executables, network intrusion, and regional scams while auditing source code with local machine learning and OpenRouter models.
          </p>

          {/* CTAs */}
          <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-base hover:from-cyan-400 hover:to-blue-500 transition-all shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2.5 group"
            >
              <Download className="w-5 h-5 group-hover:translate-y-0.5 transition-transform" />
              Download AEGIS.exe
            </a>
            <a
              href="https://github.com/Ishrak-1520/AEGIS"
              target="_blank"
              rel="noopener noreferrer"
              className="w-full sm:w-auto px-7 py-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700 text-slate-200 font-medium text-base transition-all flex items-center justify-center gap-2"
            >
              View GitHub Repository
              <ExternalLink className="w-4 h-4 text-slate-400" />
            </a>
          </div>

          {/* Quick stats / Highlights */}
          <div className="pt-6 grid grid-cols-2 sm:grid-cols-4 gap-4 text-left border-t border-white/10 max-w-2xl mx-auto">
            <div>
              <div className="text-xs text-slate-500">PLATFORM</div>
              <div className="text-sm font-semibold text-slate-200">Windows 10 / 11</div>
            </div>
            <div>
              <div className="text-xs text-slate-500">SCAN ARCHITECTURE</div>
              <div className="text-sm font-semibold text-slate-200">PE IAT & Scapy IPS</div>
            </div>
            <div>
              <div className="text-xs text-slate-500">CODE AUDITOR</div>
              <div className="text-sm font-semibold text-slate-200">OpenRouter Gemma 4</div>
            </div>
            <div>
              <div className="text-xs text-slate-500">LICENSE</div>
              <div className="text-sm font-semibold text-slate-200">Open Source</div>
            </div>
          </div>
        </div>

        {/* Interactive Desktop HUD Preview */}
        <div className="mt-14 max-w-5xl mx-auto rounded-2xl border border-slate-800 bg-slate-900/70 backdrop-blur-xl p-4 sm:p-6 shadow-2xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/70" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
              <span className="w-3 h-3 rounded-full bg-green-500/70" />
              <span className="ml-3 text-xs font-mono text-slate-400">AEGIS Desktop Suite — Live Console</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
                <CheckCircle2 className="w-3.5 h-3.5" />
                All Engines Active
              </span>
            </div>
          </div>

          {/* Interactive Preview Tabs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-6">
            <button
              onClick={() => setActiveTab("hids")}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === "hids"
                  ? "bg-cyan-500/15 border-cyan-500/40 text-white"
                  : "bg-slate-800/40 border-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-cyan-400">
                <Activity className="w-3.5 h-3.5" />
                Volatile Guardian
              </div>
              <div className="text-sm font-semibold mt-1">PE IAT Scanner</div>
            </button>

            <button
              onClick={() => setActiveTab("nids")}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === "nids"
                  ? "bg-cyan-500/15 border-cyan-500/40 text-white"
                  : "bg-slate-800/40 border-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-blue-400">
                <Network className="w-3.5 h-3.5" />
                RT-XNIDS
              </div>
              <div className="text-sm font-semibold mt-1">Real-Time Firewall</div>
            </button>

            <button
              onClick={() => setActiveTab("sift")}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === "sift"
                  ? "bg-cyan-500/15 border-cyan-500/40 text-white"
                  : "bg-slate-800/40 border-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-purple-400">
                <Terminal className="w-3.5 h-3.5" />
                SIFT Auditor
              </div>
              <div className="text-sm font-semibold mt-1">Gemma 4 Code Scan</div>
            </button>

            <button
              onClick={() => setActiveTab("nlp")}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === "nlp"
                  ? "bg-cyan-500/15 border-cyan-500/40 text-white"
                  : "bg-slate-800/40 border-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-emerald-400">
                <Lock className="w-3.5 h-3.5" />
                Threat AI
              </div>
              <div className="text-sm font-semibold mt-1">Bilingual Scam Defense</div>
            </button>
          </div>

          {/* Interactive Preview Content */}
          <div className="p-4 sm:p-6 rounded-xl bg-slate-950/80 border border-slate-800/80 font-mono text-sm text-slate-300">
            {activeTab === "hids" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-500">SYSTEM / HOST INTRUSION ENGINE</div>
                <div className="flex items-center justify-between text-white">
                  <span>Target Process Inspection: Windows Portable Executable (PE) headers</span>
                  <span className="text-cyan-400">0 anomalies detected</span>
                </div>
                <p className="text-slate-400 text-xs leading-relaxed font-sans">
                  Monitors 100 Windows Import Address Table API calls (VirtualAlloc, WriteProcessMemory, CreateRemoteThread) using pre-trained Random Forest classifiers to stop packed malware before execution.
                </p>
              </div>
            )}

            {activeTab === "nids" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-500">NETWORK / INTRUSION PREVENTION SYSTEM</div>
                <div className="flex items-center justify-between text-white">
                  <span>Packet Driver: Npcap / Scapy Sniffer Service</span>
                  <span className="text-emerald-400">Active IPS Blocking</span>
                </div>
                <p className="text-slate-400 text-xs leading-relaxed font-sans">
                  Continuous zero-loss packet capture that tracks traffic entropy and automatically applies Windows Firewall drop rules to malicious external IPs.
                </p>
              </div>
            )}

            {activeTab === "sift" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-500">DEVELOPER / CODE AUDIT ENGINE</div>
                <div className="flex items-center justify-between text-white">
                  <span>Model Engine: OpenRouter (Google Gemma 4) + AST Static Verification</span>
                  <span className="text-purple-400">PyPI Verification Enabled</span>
                </div>
                <p className="text-slate-400 text-xs leading-relaxed font-sans">
                  Analyzes Python scripts for SQL injection, buffer overflows, and hallucinated dependency imports.
                </p>
              </div>
            )}

            {activeTab === "nlp" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-500">EXPLAINABLE AI / PHISHING DEFENSE</div>
                <div className="flex items-center justify-between text-white">
                  <span>Languages Supported: English & Bangla (bKash / Nagad / Rocket patterns)</span>
                  <span className="text-emerald-400">Highlighting Active</span>
                </div>
                <p className="text-slate-400 text-xs leading-relaxed font-sans">
                  Contextual NLP engine that detects regional financial scams and highlights contributing keywords without flagging benign personal emails.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
