"use client";

import React from "react";

export default function Ticker() {
  const items = [
    "WINDOWS 10 & 11 ENDPOINT DEFENSE",
    "LOCAL PE IAT ML INSPECTION",
    "RT-XNIDS SCAPY PACKET FILTERING",
    "SIFT OPENROUTER GEMMA 4 AUDITOR",
    "BILINGUAL BANGLA & ENGLISH SCAM DEFENSE",
    "ZERO CLOUD TELEMETRY STORAGE",
  ];

  return (
    <div className="py-8 border-b border-white/10 overflow-hidden bg-[#0D0D0E]">
      <div className="animate-marquee flex gap-12 text-sm font-mono uppercase tracking-widest text-neutral-400">
        {[...items, ...items, ...items].map((text, idx) => (
          <div key={idx} className="flex items-center gap-12 whitespace-nowrap">
            <span>{text}</span>
            <span className="text-white/20">•</span>
          </div>
        ))}
      </div>
    </div>
  );
}
