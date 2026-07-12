"use client";

import React, { useState } from "react";
import { Download, CheckCircle, Copy, ExternalLink, Key, Terminal, ShieldAlert } from "lucide-react";

export default function SetupGuide() {
  const [copiedText, setCopiedText] = useState("");

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(""), 2000);
  };

  return (
    <section id="how-it-works" className="py-24 bg-slate-950/60 border-t border-b border-white/10 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Setup & Installation */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-cyan-400">QUICK START GUIDE</h2>
          <h3 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
            How to Download & Launch AEGIS
          </h3>
          <p className="text-slate-400 text-base">
            Get up and running on Windows 10 or Windows 11 in under three minutes.
          </p>
        </div>

        {/* 3 Step Process */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-24">
          <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/50 relative">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 font-bold flex items-center justify-center mb-4">
              01
            </div>
            <h4 className="text-lg font-bold text-white mb-2">Download AEGIS.exe</h4>
            <p className="text-sm text-slate-400 mb-4">
              Download the standalone Windows installer directly from the GitHub Releases page. No Python server required.
            </p>
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
            >
              Go to GitHub Releases
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <div id="prerequisites" className="p-6 rounded-2xl border border-slate-800 bg-slate-900/50 relative">
            <div className="w-10 h-10 rounded-xl bg-blue-500/15 border border-blue-500/30 text-blue-400 font-bold flex items-center justify-center mb-4">
              02
            </div>
            <h4 className="text-lg font-bold text-white mb-2">Install Prerequisites</h4>
            <p className="text-sm text-slate-400 mb-4">
              Install Npcap for real-time network packet sniffing and Tesseract OCR for screen phishing monitoring.
            </p>
            <div className="flex flex-col gap-2">
              <a
                href="https://npcap.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
              >
                Download Npcap (WinPcap mode) <ExternalLink className="w-3 h-3" />
              </a>
              <a
                href="https://github.com/UB-Mannheim/tesseract/wiki"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
              >
                Download Tesseract OCR <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/50 relative">
            <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-400 font-bold flex items-center justify-center mb-4">
              03
            </div>
            <h4 className="text-lg font-bold text-white mb-2">Run as Administrator</h4>
            <p className="text-sm text-slate-400 mb-4">
              Right-click AEGIS.exe and select Run as administrator so the firewall and network inspection drivers can operate properly.
            </p>
            <div className="text-xs text-slate-500">First launch creates your local Master Admin account</div>
          </div>
        </div>

        {/* Free OpenRouter API Key Guide */}
        <div id="openrouter-guide" className="max-w-4xl mx-auto rounded-2xl border border-slate-800 bg-slate-900/70 p-6 sm:p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Key className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">How to Get a Free OpenRouter API Key</h3>
              <p className="text-sm text-slate-400">
                Required only for the SIFT AI Code Auditor. All other security engines work offline without any API key.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <div className="text-xs font-mono text-purple-400 mb-1">STEP 1</div>
              <div className="text-sm font-semibold text-white mb-1">Create Free Account</div>
              <p className="text-xs text-slate-400">
                Visit{" "}
                <a
                  href="https://openrouter.ai/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 underline"
                >
                  openrouter.ai
                </a>{" "}
                and sign in with GitHub or Google.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <div className="text-xs font-mono text-purple-400 mb-1">STEP 2</div>
              <div className="text-sm font-semibold text-white mb-1">Generate API Key</div>
              <p className="text-xs text-slate-400">
                Navigate to your Account Settings → Keys, click Create Key, and copy the generated secret token.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <div className="text-xs font-mono text-purple-400 mb-1">STEP 3</div>
              <div className="text-sm font-semibold text-white mb-1">Save in .env File</div>
              <p className="text-xs text-slate-400">
                Create a file named .env in the AEGIS directory and paste your key inside.
              </p>
            </div>
          </div>

          {/* Copyable code snippet */}
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 flex items-center justify-between">
            <code className="text-sm font-mono text-cyan-400">SIFT_API_KEY=your_openrouter_api_key_here</code>
            <button
              onClick={() => handleCopy("SIFT_API_KEY=your_openrouter_api_key_here")}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors flex items-center gap-1.5"
            >
              {copiedText ? (
                <>
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy .env format
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
