"use client";

import React, { useState } from "react";
import { ArrowUpRight, Check, Copy } from "lucide-react";

export default function SetupGuide() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText("SIFT_API_KEY=your_openrouter_api_key_here");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="installation" className="py-24 border-b border-white/10">
      <div className="max-w-7xl mx-auto px-6 sm:px-10">
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between pb-12 border-b border-white/10 gap-6">
          <div>
            <div className="text-xs font-mono uppercase tracking-widest text-neutral-400 mb-2">Installation</div>
            <h2 className="text-4xl sm:text-6xl font-light tracking-tight">
              Get started in <em className="font-editorial italic">m</em>inutes.
            </h2>
          </div>
          <div className="text-xs font-mono text-neutral-400">3 — 4</div>
        </div>

        {/* 3 Editorial Installation Columns */}
        <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/10 pt-12 pb-20 border-b border-white/10">
          <div className="md:pr-10 pb-8 md:pb-0">
            <div className="text-xs font-mono text-neutral-500 mb-4">STEP 01</div>
            <h3 className="text-2xl font-normal text-white mb-3">Download Executable</h3>
            <p className="text-sm text-neutral-400 leading-relaxed mb-6">
              Download the standalone `AEGIS.exe` binary directly from GitHub Releases. No local Python runtime or external server required.
            </p>
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-sm font-medium text-white underline underline-offset-4 hover:text-neutral-300"
            >
              Open GitHub Releases
              <ArrowUpRight className="w-4 h-4" />
            </a>
          </div>

          <div className="md:px-10 py-8 md:py-0">
            <div className="text-xs font-mono text-neutral-500 mb-4">STEP 02</div>
            <h3 className="text-2xl font-normal text-white mb-3">Install OS Drivers</h3>
            <p className="text-sm text-neutral-400 leading-relaxed mb-6">
              Install Npcap for low-level packet capture and Tesseract OCR for real-time screen protection and phishing monitoring.
            </p>
            <div className="space-y-2 text-sm font-mono">
              <div>
                <a
                  href="https://npcap.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-white underline underline-offset-4 hover:text-neutral-300 inline-flex items-center gap-1"
                >
                  Download Npcap (WinPcap mode) <ArrowUpRight className="w-3.5 h-3.5" />
                </a>
              </div>
              <div>
                <a
                  href="https://github.com/UB-Mannheim/tesseract/wiki"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-white underline underline-offset-4 hover:text-neutral-300 inline-flex items-center gap-1"
                >
                  Download Tesseract OCR <ArrowUpRight className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          </div>

          <div className="md:pl-10 pt-8 md:pt-0">
            <div className="text-xs font-mono text-neutral-500 mb-4">STEP 03</div>
            <h3 className="text-2xl font-normal text-white mb-3">Launch as Admin</h3>
            <p className="text-sm text-neutral-400 leading-relaxed">
              Right-click `AEGIS.exe` and select Run as administrator so the firewall automation and network sniffer can operate at the kernel level.
            </p>
          </div>
        </div>

        {/* Section 4 - Free OpenRouter API Key Guide */}
        <div id="openrouter" className="pt-20">
          <div className="flex flex-col md:flex-row md:items-end justify-between pb-12 border-b border-white/10 gap-6">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-neutral-400 mb-2">Code Auditor Setup</div>
              <h2 className="text-4xl sm:text-5xl font-light tracking-tight">
                Free OpenRouter <em className="font-editorial italic">A</em>PI key.
              </h2>
            </div>
            <div className="text-xs font-mono text-neutral-400">4 — 4</div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 pt-12">
            <div className="lg:col-span-6 space-y-6">
              <p className="text-base text-neutral-400 leading-relaxed">
                The SIFT AI Code Auditor uses Google Gemma 4 hosted on OpenRouter. All other engines (PE scanner, Scapy firewall, OCR, and bilingual NLP) work 100% offline.
              </p>

              <div className="space-y-4 text-sm text-neutral-300">
                <div className="flex items-start gap-3">
                  <span className="font-mono text-neutral-500">1.</span>
                  <span>
                    Visit{" "}
                    <a
                      href="https://openrouter.ai/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="underline underline-offset-4 text-white"
                    >
                      openrouter.ai
                    </a>{" "}
                    and create a free account.
                  </span>
                </div>
                <div className="flex items-start gap-3">
                  <span className="font-mono text-neutral-500">2.</span>
                  <span>Navigate to Account → Keys and generate a new API key.</span>
                </div>
                <div className="flex items-start gap-3">
                  <span className="font-mono text-neutral-500">3.</span>
                  <span>Save the key inside a `.env` file in your AEGIS directory.</span>
                </div>
              </div>
            </div>

            <div className="lg:col-span-6 flex flex-col justify-center">
              <div className="p-6 rounded-2xl border border-white/10 bg-[#141417]">
                <div className="text-xs font-mono text-neutral-400 mb-2">CONFIGURATION (.env FORMAT)</div>
                <div className="flex items-center justify-between gap-4 p-4 rounded-xl bg-black border border-white/10">
                  <code className="text-sm font-mono text-white">SIFT_API_KEY=your_openrouter_api_key_here</code>
                  <button
                    onClick={handleCopy}
                    className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-mono text-white transition-colors flex items-center gap-1.5"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        Copy
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
