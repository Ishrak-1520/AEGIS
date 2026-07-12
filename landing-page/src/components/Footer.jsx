"use client";

import React from "react";
import { Shield, ExternalLink, Github } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-[#070B14] py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-sm font-semibold text-slate-200">AEGIS Endpoint Security Suite</span>
          <span className="text-xs text-slate-500">v2.0.0</span>
        </div>

        {/* Links */}
        <div className="flex items-center gap-6 text-sm text-slate-400">
          <a
            href="https://github.com/Ishrak-1520/AEGIS/releases"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white transition-colors"
          >
            Releases
          </a>
          <a
            href="https://github.com/Ishrak-1520/AEGIS"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white transition-colors flex items-center gap-1"
          >
            GitHub Repository
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        {/* Legal */}
        <div className="text-xs text-slate-500 text-center md:text-right">
          Open Source Security Research & Defensive Cybersecurity Project.
        </div>
      </div>
    </footer>
  );
}
