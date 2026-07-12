"use client";

import React from "react";
import { Shield, Network, Terminal, Lock, Eye, Key } from "lucide-react";

const features = [
  {
    icon: Shield,
    title: "Host Intrusion Detection",
    subtitle: "Volatile Guardian PE Analysis",
    description:
      "Inspects Windows Portable Executable headers and Import Address Table sequences to detect packed and obfuscated executables before execution.",
    tag: "Machine Learning",
    color: "from-cyan-500/20 to-blue-500/10 border-cyan-500/30 text-cyan-400",
  },
  {
    icon: Network,
    title: "Network Intrusion Prevention",
    subtitle: "RT-XNIDS Scapy Engine",
    description:
      "Monitors live packet streams via Npcap, calculates network baseline metrics, and automatically blocks malicious IPs using Windows Firewall rules.",
    tag: "Automated IPS",
    color: "from-blue-500/20 to-indigo-500/10 border-blue-500/30 text-blue-400",
  },
  {
    icon: Terminal,
    title: "SIFT AI Code Auditor",
    subtitle: "Gemma 4 + Static Analysis",
    description:
      "Audits Python codebases for security vulnerabilities and checks PyPI packages against live registries to catch typosquatting and malicious imports.",
    tag: "OpenRouter LLM",
    color: "from-purple-500/20 to-pink-500/10 border-purple-500/30 text-purple-400",
  },
  {
    icon: Lock,
    title: "Bilingual Phishing Defense",
    subtitle: "English & Bangla Scam Detection",
    description:
      "Detects regional financial scams targeting bKash, Nagad, and Rocket while highlighting specific threat words with Explainable AI interpretability.",
    tag: "NLP Engine",
    color: "from-emerald-500/20 to-teal-500/10 border-emerald-500/30 text-emerald-400",
  },
  {
    icon: Eye,
    title: "Real-Time Screen Protection",
    subtitle: "Active OCR & Cooldown Timers",
    description:
      "Captures on-screen text to spot live phishing sites or credential harvesting forms with automatic alert deduplication so notifications stay relevant.",
    tag: "Tesseract OCR",
    color: "from-amber-500/20 to-orange-500/10 border-amber-500/30 text-amber-400",
  },
  {
    icon: Key,
    title: "Zero-Knowledge Password Vault",
    subtitle: "AES-256-GCM Storage",
    description:
      "Safely stores credentials locally in SQLite and isolates detected malware files in an encrypted quarantine folder to prevent accidental execution.",
    tag: "Encrypted Storage",
    color: "from-rose-500/20 to-red-500/10 border-rose-500/30 text-rose-400",
  },
];

export default function FeatureShowcase() {
  return (
    <section id="features" className="py-24 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
            COMPREHENSIVE ENDPOINT DEFENSE
          </h2>
          <h3 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
            Why Security Engineers & Developers Use AEGIS
          </h3>
          <p className="text-slate-400 text-base">
            Designed specifically for Windows endpoints, combining low-level OS inspection with modern machine learning.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((item, index) => {
            const Icon = item.icon;
            return (
              <div
                key={index}
                className="group relative rounded-2xl border border-slate-800 bg-slate-900/40 hover:bg-slate-900/80 transition-all duration-300 p-6 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div
                      className={`w-12 h-12 rounded-xl bg-gradient-to-br ${item.color} border flex items-center justify-center`}
                    >
                      <Icon className="w-6 h-6" />
                    </div>
                    <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-300">
                      {item.tag}
                    </span>
                  </div>

                  <h4 className="text-lg font-bold text-white group-hover:text-cyan-400 transition-colors">
                    {item.title}
                  </h4>
                  <div className="text-xs font-mono text-slate-400 mt-0.5 mb-3">{item.subtitle}</div>
                  <p className="text-sm text-slate-400 leading-relaxed">{item.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
