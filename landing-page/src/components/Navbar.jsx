"use client";

import React, { useState } from "react";
import { ArrowUpRight, Menu, X } from "lucide-react";

export default function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-[#0D0D0E]/90 backdrop-blur-md border-b border-white/10">
      <div className="max-w-7xl mx-auto px-6 sm:px-10 h-20 flex items-center justify-between">
        {/* Brand with uploaded Logo */}
        <a href="#" className="flex items-center gap-3 group">
          <img
            src="/logo.jpg"
            alt="AEGIS Shield Logo"
            className="w-9 h-9 rounded-lg object-cover border border-white/20 shadow-md group-hover:scale-105 transition-transform"
          />
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold tracking-tight text-white uppercase">AEGIS</span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border border-white/20 text-neutral-400">
              v2.0.0
            </span>
          </div>
        </a>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-10 text-sm font-normal text-neutral-400">
          <a href="#showcase" className="hover:text-white transition-colors">
            Showcase
          </a>
          <a href="#architecture" className="hover:text-white transition-colors">
            Capabilities
          </a>
          <a href="#installation" className="hover:text-white transition-colors">
            Installation
          </a>
          <a href="#openrouter" className="hover:text-white transition-colors">
            Free API Key
          </a>
        </nav>

        {/* Desktop Actions */}
        <div className="hidden md:flex items-center gap-6">
          <a
            href="https://github.com/Ishrak-1520/AEGIS"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-normal text-neutral-400 hover:text-white transition-colors"
          >
            GitHub
          </a>
          <a
            href="https://github.com/Ishrak-1520/AEGIS/releases"
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-2.5 rounded-full bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors flex items-center gap-1.5"
          >
            Download for Windows
            <ArrowUpRight className="w-4 h-4" />
          </a>
        </div>

        {/* Mobile menu button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-2 text-neutral-400 hover:text-white"
          aria-label="Toggle Menu"
        >
          {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile menu dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-[#0D0D0E] border-b border-white/10 px-6 py-6 space-y-4">
          <a
            href="#showcase"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-neutral-300 hover:text-white"
          >
            Showcase
          </a>
          <a
            href="#architecture"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-neutral-300 hover:text-white"
          >
            Capabilities
          </a>
          <a
            href="#installation"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-neutral-300 hover:text-white"
          >
            Installation
          </a>
          <a
            href="#openrouter"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-neutral-300 hover:text-white"
          >
            Free API Key
          </a>
          <div className="pt-4 border-t border-white/10 flex flex-col gap-3">
            <a
              href="https://github.com/Ishrak-1520/AEGIS/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="w-full py-3 rounded-full bg-white text-black font-medium text-center flex items-center justify-center gap-2"
            >
              Download for Windows
              <ArrowUpRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
