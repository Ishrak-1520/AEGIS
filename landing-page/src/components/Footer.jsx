"use client";

import React from "react";
import { ArrowUpRight } from "lucide-react";

export default function Footer() {
  return (
    <footer className="py-20 bg-[#0A0A0C]">
      <div className="max-w-7xl mx-auto px-6 sm:px-10">
        <div className="flex flex-col lg:flex-row items-start lg:items-end justify-between pb-16 border-b border-white/10 gap-8">
          <div>
            <div className="flex items-center gap-3 mb-6">
              <img
                src="/logo.jpg"
                alt="AEGIS Shield Logo"
                className="w-10 h-10 rounded-lg object-cover border border-white/20 shadow-md"
              />
              <span className="text-xs font-mono uppercase tracking-widest text-neutral-400">
                OPEN SOURCE DEFENSIVE SECURITY
              </span>
            </div>
            <h2 className="text-4xl sm:text-7xl font-light tracking-tight leading-none">
              AEGIS <em className="font-editorial italic">S</em>tudio.
            </h2>
          </div>

          <a
            href="https://github.com/Ishrak-1520/AEGIS/releases"
            target="_blank"
            rel="noopener noreferrer"
            className="px-8 py-4 rounded-full bg-white text-black font-semibold text-sm hover:bg-neutral-200 transition-colors flex items-center gap-2"
          >
            Download AEGIS.exe
            <ArrowUpRight className="w-4 h-4" />
          </a>
        </div>

        <div className="pt-10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 text-xs font-mono text-neutral-500">
          <div>AEGIS v2.0.0 — Open Source Windows Desktop Protection</div>

          <div className="flex items-center gap-8">
            <a
              href="https://github.com/Ishrak-1520/AEGIS"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
            >
              GitHub Repository
            </a>
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
            >
              Releases
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
