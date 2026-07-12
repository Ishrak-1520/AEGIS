"use client";

import React, { useState } from "react";
import { ArrowUpRight } from "lucide-react";

const capabilities = [
  {
    number: "01",
    title: "Host Intrusion Detection (HIDS)",
    subtitle: "PE Import Address Table Machine Learning",
    details:
      "Inspects Windows Portable Executable headers and Import Address Table sequences to detect packed and obfuscated executables before execution.",
    tech: "Local Random Forest Classifier",
  },
  {
    number: "02",
    title: "Real-Time Network IPS",
    subtitle: "Npcap Driver & Scapy Firewall Automation",
    details:
      "Monitors live packet streams via Npcap, calculates network baseline metrics, and automatically applies Windows Firewall drop rules to malicious IPs.",
    tech: "Windows Firewall API",
  },
  {
    number: "03",
    title: "SIFT Source Code Auditor",
    subtitle: "OpenRouter Gemma 4 + AST Verification",
    details:
      "Audits Python codebases for security vulnerabilities and verifies PyPI dependencies against official registries to catch typosquatting packages.",
    tech: "Gemma 4 LLM & AST Parser",
  },
  {
    number: "04",
    title: "Bilingual Phishing Defense",
    subtitle: "English & Bangla Scam Detection",
    details:
      "Detects regional financial scams targeting bKash, Nagad, and Rocket while highlighting specific threat keywords with Explainable AI interpretability.",
    tech: "Explainable NLP",
  },
  {
    number: "05",
    title: "Real-Time Screen Protection",
    subtitle: "Active OCR & Cooldown Deduplication",
    details:
      "Captures on-screen text to spot live phishing sites or credential harvesting forms with automatic alert deduplication so notifications stay actionable.",
    tech: "Tesseract OCR",
  },
  {
    number: "06",
    title: "Encrypted Password & Quarantine Vault",
    subtitle: "AES-256-GCM Secure Local Storage",
    details:
      "Stores credentials locally in SQLite and isolates suspicious executable files inside an encrypted quarantine directory to prevent accidental execution.",
    tech: "AES-256 Crypto Engine",
  },
];

export default function FeatureShowcase() {
  const [expanded, setExpanded] = useState("01");

  return (
    <section id="architecture" className="py-24 border-b border-white/10">
      <div className="max-w-7xl mx-auto px-6 sm:px-10">
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between pb-12 border-b border-white/10 gap-6">
          <div>
            <div className="text-xs font-mono uppercase tracking-widest text-neutral-400 mb-2">Capabilities</div>
            <h2 className="text-4xl sm:text-6xl font-light tracking-tight">
              Engineered for <em className="font-editorial italic">r</em>esilience.
            </h2>
          </div>
          <div className="text-xs font-mono text-neutral-400">2 — 4</div>
        </div>

        {/* Editorial Accordion List */}
        <div className="divide-y divide-white/10">
          {capabilities.map((item) => {
            const isOpen = expanded === item.number;
            return (
              <div
                key={item.number}
                className="py-8 cursor-pointer group transition-colors"
                onClick={() => setExpanded(isOpen ? null : item.number)}
              >
                <div className="flex items-start justify-between gap-6">
                  <div className="flex items-baseline gap-6 sm:gap-12">
                    <span className="text-sm font-mono text-neutral-500">{item.number}</span>
                    <div>
                      <h3 className="text-2xl sm:text-4xl font-light group-hover:text-white text-neutral-200 transition-colors">
                        {item.title}
                      </h3>
                      <div className="text-sm font-mono text-neutral-400 mt-1">{item.subtitle}</div>
                    </div>
                  </div>

                  <div className="text-right flex flex-col items-end gap-2">
                    <span className="text-xs font-mono px-3 py-1 rounded-full border border-white/10 text-neutral-400 bg-white/5">
                      {item.tech}
                    </span>
                  </div>
                </div>

                {isOpen && (
                  <div className="mt-6 pl-12 sm:pl-18 max-w-3xl text-neutral-400 text-base leading-relaxed">
                    <p>{item.details}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
