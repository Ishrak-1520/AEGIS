import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Activity, Lock, FileSearch, Settings, FileWarning, Menu, Brain, FileText } from 'lucide-react'

import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import PasswordManager from './components/PasswordManager';
import Quarantine from './components/Quarantine';
import SettingsView from './components/Settings';
import NLPAnalyzer from './components/NLPAnalyzer';
import Reports from './components/Reports';
import ThreatAlertManager from './components/ThreatAlertManager';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'scanner', label: 'Scanner', icon: FileSearch },
    { id: 'nlp', label: 'Threat AI', icon: Brain },
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
              className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all duration-200 group relative overflow-hidden ${activeTab === item.id
                ? 'bg-primary/10 text-primary'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
            >
              {activeTab === item.id && (
                <motion.div
                  layoutId="activeTab"
                  className="absolute left-0 top-0 bottom-0 w-1 bg-primary"
                />
              )}
              <item.icon className={`w-5 h-5 ${activeTab === item.id ? 'text-primary' : ''}`} />
              {isSidebarOpen && (
                <span className="font-medium tracking-wide text-sm">{item.label}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-white/5">
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="w-full flex items-center justify-center p-2 text-gray-500 hover:text-white transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>
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
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
              <Shield className="w-4 h-4 text-green-400" />
              <span className="text-xs font-bold text-green-400 tracking-wide">PROTECTED</span>
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
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
              className="h-full"
            >
              {activeTab === 'dashboard' && <Dashboard />}
              {activeTab === 'scanner' && <Scanner />}
              {activeTab === 'nlp' && <NLPAnalyzer />}
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
