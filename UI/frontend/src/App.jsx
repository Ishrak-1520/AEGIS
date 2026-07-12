import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Activity, Lock, FileSearch, Settings, FileWarning, Menu, Brain, FileText, Wifi, ShieldCheck, Zap, ChevronLeft, ChevronRight } from 'lucide-react'

import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import PasswordManager from './components/PasswordManager';
import Quarantine from './components/Quarantine';
import SettingsView from './components/Settings';
import NLPAnalyzer from './components/NLPAnalyzer';
import Reports from './components/Reports';
import ThreatAlertManager from './components/ThreatAlertManager';

import NetworkMonitor from './components/NetworkMonitor';
import SiftScanner from './components/Sift/SiftScanner';
import HidsLiveDashboard from './components/HidsLiveDashboard';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'hids', label: 'Volatile Guardian', icon: Zap },
    { id: 'network', label: 'Network', icon: Wifi },
    { id: 'scanner', label: 'Scanner', icon: FileSearch },
    { id: 'nlp', label: 'Threat AI', icon: Brain },
    { id: 'sift', label: 'Sift Auditor', icon: ShieldCheck },
    { id: 'passwords', label: 'Passwords', icon: Lock },
    { id: 'quarantine', label: 'Quarantine', icon: FileWarning },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ]

  return (
    <div className="flex h-screen bg-background text-white overflow-hidden font-sans">
      {/* Sidebar */}
      <motion.div
        initial={false}
        animate={{ width: isSidebarOpen ? 260 : 80 }}
        className="bg-surface border-r border-white/5 flex flex-col relative z-20"
      >
        <div className="p-6 flex items-center justify-between">
          {isSidebarOpen ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center gap-3"
            >
              <img
                src="/aegis-logo.png"
                alt="AEGIS Logo"
                className="w-10 h-10 object-contain"
              />
              <div className="flex flex-col">
                <span className="text-xl font-bold tracking-wider text-white">AEGIS</span>
                <span className="text-xs text-primary tracking-[0.2em] font-bold">CYBER DEFENSE</span>
              </div>
            </motion.div>
          ) : (
            <img
              src="/aegis-logo.png"
              alt="AEGIS Logo"
              className="w-8 h-8 object-contain mx-auto"
            />
          )}
        </div>

        <nav className="flex-1 px-4 py-4 space-y-2">
          {menuItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center ${isSidebarOpen ? 'gap-4 px-4' : 'justify-center'} py-3 rounded-lg transition-all duration-200 group relative sidebar-btn ${activeTab === item.id
                ? 'bg-primary/10 text-primary'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
            >
              {activeTab === item.id && (
                <motion.div
                  layoutId="activeTab"
                  className="absolute left-0 top-0 bottom-0 w-[3px] bg-primary rounded-r-full shadow-[0_0_8px_rgba(59,130,246,0.8)]"
                />
              )}
              <item.icon className={`w-5 h-5 shrink-0 transition-colors ${activeTab === item.id ? 'text-primary' : 'group-hover:text-white'}`} />
              {isSidebarOpen && (
                <span className="font-medium tracking-wide text-sm whitespace-nowrap overflow-hidden text-left flex-1">
                  {item.label}
                </span>
              )}
              {!isSidebarOpen && <div className="sidebar-tooltip">{item.label}</div>}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-white/5">
          <div className="flex items-center justify-between">
            {isSidebarOpen && <span className="text-[10px] text-gray-500 font-mono tracking-widest pl-2">v2.0.0</span>}
            <button
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className={`p-2 text-gray-500 hover:text-white transition-colors rounded-lg hover:bg-white/5 ${!isSidebarOpen ? 'w-full flex justify-center' : ''}`}
              title={isSidebarOpen ? "Collapse Sidebar" : "Expand Sidebar"}
            >
              {isSidebarOpen ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col relative overflow-hidden">
        {/* Top Bar */}
        <header className="h-16 border-b border-white/5 bg-surface/50 backdrop-blur-sm flex items-center justify-between px-8">
          <h2 className="text-xl font-bold text-white tracking-wide">
            {menuItems.find(i => i.id === activeTab)?.label.toUpperCase()}
          </h2>
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition-colors duration-300 ${activeTab === 'quarantine' ? 'bg-red-500/10 border-red-500/20' : 'bg-green-500/10 border-green-500/20'}`}>
              <Shield className={`w-4 h-4 ${activeTab === 'quarantine' ? 'text-red-400' : 'text-green-400'}`} />
              <span className={`text-xs font-bold tracking-wide ${activeTab === 'quarantine' ? 'text-red-400' : 'text-green-400'}`}>
                {activeTab === 'quarantine' ? 'ATTENTION' : 'PROTECTED'}
              </span>
            </div>
            <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/50 flex items-center justify-center">
              <span className="font-bold text-primary text-sm">A</span>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-8 custom-scrollbar relative">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              className="h-full"
            >
              {activeTab === 'dashboard' && <Dashboard />}
              {activeTab === 'network' && <NetworkMonitor />}
              {activeTab === 'scanner' && <Scanner />}
              {activeTab === 'nlp' && <NLPAnalyzer />}
              {activeTab === 'hids' && <HidsLiveDashboard />}
              {activeTab === 'sift' && <SiftScanner />}
              {activeTab === 'passwords' && <PasswordManager />}
              {activeTab === 'quarantine' && <Quarantine />}
              {activeTab === 'reports' && <Reports />}
              {activeTab === 'settings' && <SettingsView />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      {/* Global Threat Alert Manager */}
      <ThreatAlertManager />
    </div>
  )
}

export default App
