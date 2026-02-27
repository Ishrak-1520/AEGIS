import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Brain, Activity, Zap, AlertTriangle, CheckCircle, ShieldAlert, Play, Pause } from 'lucide-react';

const BatLogo = ({ size = 48, isThreat = false }) => (
    <div className="flex items-center justify-center">
        <img
            src="/assets/bat4-final.png"
            alt="AEGIS Batman Logo"
            className={`object-contain transition-all duration-300 ${isThreat ? 'animate-[pulse_1.5s_ease-in-out_infinite]' : ''}`}
            style={{
                height: size,
                width: 'auto',
                filter: isThreat
                    ? 'drop-shadow(0 0 5px #EF4444) drop-shadow(0 0 15px rgba(239, 68, 68, 0.8))'
                    : 'drop-shadow(0 0 2px #4F8BF9) drop-shadow(0 0 5px rgba(79, 139, 249, 0.7))',
            }}
        />
    </div>
);

const HidsLiveDashboard = () => {
    const [status, setStatus] = useState({
        telemetry: {
            "svcscan.nservices": 0,
            "svcscan.kernel_drivers": 0,
            "handles.nmutant": 0,
            "dlllist.avg_dlls_per_proc": 0,
            "pslist.nprocs64bit": 0
        },
        inference: {
            "is_threat": false,
            "confidence_score": 0,
            "latency_ms": 0,
            "ai_reasoning": "Waiting for telemetry data..."
        },
        is_active: false
    });

    const fetchData = async () => {
        if (window.pywebview && window.pywebview.api) {
            try {
                const response = await window.pywebview.api.get_volatile_memory_status();
                if (response && response.status === "success") {
                    setStatus(response.data);
                }
            } catch (error) {
                console.error("Failed to fetch HIDS status:", error);
            }
        }
    };

    const [displayedReasoning, setDisplayedReasoning] = useState("");
    const [reasoningHistory, setReasoningHistory] = useState([]);
    const [isPaused, setIsPaused] = useState(false);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 7000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const text = status.inference.ai_reasoning;
        if (!text || text === "Waiting for telemetry data..." || isPaused) return;

        const lastEntry = reasoningHistory[0];
        if (lastEntry !== text) {
            setReasoningHistory(prev => [text, ...prev].slice(0, 20));

            let currentText = "";
            let currentIndex = 0;
            setDisplayedReasoning("");

            const intervalId = setInterval(() => {
                if (currentIndex < text.length) {
                    currentText += text.charAt(currentIndex);
                    setDisplayedReasoning(currentText);
                    currentIndex++;
                } else {
                    clearInterval(intervalId);
                }
            }, 10);
            return () => clearInterval(intervalId);
        }
    }, [status.inference.ai_reasoning, isPaused]);

    const metrics = [
        { label: "Background Programs", value: status.telemetry["svcscan.nservices"] },
        { label: "Hardware Drivers", value: status.telemetry["svcscan.kernel_drivers"] },
        { label: "Resource Locks", value: status.telemetry["handles.nmutant"] },
        { label: "Loaded Components", value: status.telemetry["dlllist.avg_dlls_per_proc"] },
        { label: "Active Processes", value: status.telemetry["pslist.nprocs64bit"] }
    ];

    const isThreat = status.inference.is_threat;
    const confidence = (status.inference.confidence_score * 100).toFixed(1);

    const HighlightText = ({ text }) => {
        if (!text) return null;

        // Define keywords and their associated colors
        const keywords = {
            red: ['THREAT', 'MALWARE', 'DETECTED', 'HIGH-RISK', 'THREAT DETECTED', '🚨', '⚠️'],
            orange: ['CHECKING', 'ELEVATED', 'UNVERIFIED', 'SUSPICIOUS', 'HIGH ACTIVITY', 'RESOURCE LOCKS', 'CODE LIBRARIES', '🔍', '🔒', '💉', '☁️'],
            green: ['ALL CLEAR', 'SAFE', 'VERIFIED', 'NORMAL', 'SYSTEM SAFE', '✅', 'HEALTH', 'DRIVERS VERIFIED', '🛡️', '⚡']
        };

        // Regex to match any of the keywords
        const allKeywords = [...keywords.red, ...keywords.orange, ...keywords.green];
        // Escape special chars like 🚨 or [
        const regex = new RegExp(`(${allKeywords.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');

        const parts = text.split(regex);

        return (
            <span>
                {parts.map((part, i) => {
                    const lowerPart = part.toLowerCase();
                    if (keywords.red.some(k => k.toLowerCase() === lowerPart)) {
                        return <span key={i} className="text-red-500 font-bold">{part}</span>;
                    }
                    if (keywords.orange.some(k => k.toLowerCase() === lowerPart)) {
                        return <span key={i} className="text-orange-400 font-bold">{part}</span>;
                    }
                    if (keywords.green.some(k => k.toLowerCase() === lowerPart)) {
                        return <span key={i} className="text-[#00C853] font-bold">{part}</span>;
                    }
                    return <span key={i}>{part}</span>;
                })}
            </span>
        );
    };

    return (
        <div className="flex-1 overflow-y-auto bg-[#080B10] p-8 custom-scrollbar relative font-mono text-sm uppercase tracking-tight">
            {/* Background effects */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.02] bg-[radial-gradient(#4F8BF9_1px,transparent_1px)] bg-[length:24px_24px] z-0" />
            <div className="absolute inset-0 pointer-events-none opacity-[0.03] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50 animate-[pulse_4s_infinite]" />

            {!status.is_active && (
                <div className="absolute inset-0 bg-[#080B10]/80 backdrop-blur-md flex flex-col items-center justify-center z-50 p-8 text-center">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="bg-surface/50 border border-[#4F8BF9]/20 p-12 rounded-3xl backdrop-blur-xl shadow-[0_0_50px_rgba(79,139,249,0.1)] max-w-lg relative"
                    >
                        <div className="absolute -top-4 -left-4 w-8 h-8 border-t-2 border-l-2 border-[#4F8BF9]/40" />
                        <div className="absolute -bottom-4 -right-4 w-8 h-8 border-b-2 border-r-2 border-[#4F8BF9]/40" />

                        <ShieldAlert size={80} className="text-[#FF5252] mb-8 mx-auto filter drop-shadow-[0_0_15px_rgba(255,82,82,0.5)]" />
                        <h2 className="text-3xl font-black text-white mb-6 tracking-tighter uppercase italic">Guardian Offline</h2>
                        <p className="text-gray-400 mb-10 leading-relaxed font-sans normal-case text-sm">
                            Memory protection is currently turned off.
                            Enable Real-Time Protection from the Dashboard to start monitoring.
                        </p>
                    </motion.div>
                </div>
            )}

            <header className="relative mb-12 flex flex-col md:flex-row items-center justify-between border-b border-white/5 pb-8 z-10">
                <div className="flex items-center gap-6">
                    <motion.div
                        animate={{ y: [0, -4, 0] }}
                        transition={{ repeat: Infinity, duration: 4 }}
                    >
                        <BatLogo size={60} isThreat={status.inference.is_threat} />
                    </motion.div>
                    <div>
                        <h1 className="text-5xl font-black text-white tracking-widest leading-none">
                            AEGIS <span className="text-[#4F8BF9] drop-shadow-[0_0_10px_rgba(79,139,249,0.5)]">BATMAN</span>
                        </h1>
                        <div className="flex items-center gap-3 mt-3">
                            <div className="h-0.5 w-12 bg-[#4F8BF9]" />
                            <span className="text-[12px] font-bold text-[#E6EDF3] tracking-[0.2em]">Memory Protection</span>
                            <div className="h-0.5 w-12 bg-[#4F8BF9]" />
                        </div>
                    </div>
                </div>

                <div className="mt-8 md:mt-0 flex flex-col items-end gap-1">
                    <span className="text-[10px] text-gray-500 font-bold tracking-widest uppercase">Module: Memory Guard</span>
                    <span className="text-[10px] text-[#4F8BF9] font-bold tracking-widest flex items-center gap-2 animate-pulse uppercase">
                        <Activity size={12} />
                        Live Monitoring: Active
                    </span>
                    <div className="flex gap-1 mt-1">
                        {[...Array(8)].map((_, i) => (
                            <div key={i} className={`w-3 h-1 ${i < 5 ? 'bg-[#4F8BF9]' : 'bg-white/10'}`} />
                        ))}
                    </div>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8 z-10 relative">
                {/* Left Columns: Assessment & AI */}
                <div className="lg:col-span-3 space-y-8">
                    {/* Main Assessment Panel */}
                    <motion.div layout className={`rounded-xl overflow-hidden border p-1 backdrop-blur-xl transition-all duration-300 ${isThreat ? 'border-red-500 bg-red-950/20 shadow-[0_0_50px_rgba(239,68,68,0.3)] animate-[pulse_1.5s_ease-in-out_infinite]' : 'border-[#4F8BF9]/30 shadow-[0_0_30px_rgba(79,139,249,0.1)]'}`}>
                        <div className={`p-6 rounded-lg ${isThreat ? 'bg-red-900/10' : 'bg-surface/80'}`}>
                            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                                <div className="space-y-4">
                                    <div className="flex items-center gap-4">
                                        <div className={`p-4 rounded-full ${isThreat ? 'bg-red-500/30 text-red-500 rotate-12 shadow-[0_0_25px_rgba(239,68,68,0.5)] animate-pulse' : 'bg-[#4F8BF9]/20 text-[#4F8BF9] shadow-[0_0_15px_rgba(79,139,249,0.3)]'}`}>
                                            {isThreat ? <AlertTriangle size={36} /> : <CheckCircle size={36} />}
                                        </div>
                                        <div>
                                            <h2 className={`text-4xl font-black italic tracking-tighter ${isThreat ? "text-red-500 drop-shadow-[0_0_10px_rgba(239,68,68,0.8)]" : "text-white"}`}>
                                                {isThreat ? "Threat Detected" : "System Safe"}
                                            </h2>
                                            <p className="text-[11px] text-gray-500 font-bold tracking-[0.3em] uppercase mt-1">Memory Security Status</p>
                                        </div>
                                    </div>
                                    <p className={`text-xs tracking-wider font-mono uppercase leading-relaxed ${isThreat ? "text-red-200" : "text-[#4F8BF9]/80"}`}>
                                        {isThreat
                                            ? "A suspicious pattern was found in your system's memory. AEGIS is actively responding to this threat."
                                            : "Your memory activity is normal. No signs of hidden threats or unauthorized access detected."}
                                    </p>
                                </div>
                                <div className="flex flex-col items-center justify-center p-6 border-l border-white/5 min-w-[160px]">
                                    <div className="text-[12px] text-gray-500 font-bold tracking-widest mb-2 uppercase">Threat Level</div>
                                    <div className={`text-5xl font-black ${isThreat ? 'text-red-500' : 'text-[#4F8BF9]'} drop-shadow-[0_0_8px_currentColor]`}>
                                        {confidence}%
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {/* Hacker CLI Intelligence Log */}
                        <section className={`bg-surface/60 border rounded-xl overflow-hidden backdrop-blur-xl relative group shadow-2xl transition-all duration-300 ${isThreat ? 'border-red-500/50 shadow-[0_0_40px_rgba(239,68,68,0.2)]' : 'border-white/5'}`}>
                            {/* Terminal Window Header */}
                            <div className={`border-b px-4 py-2 flex items-center justify-between transition-colors duration-300 ${isThreat ? 'bg-red-950/40 border-red-500/30 animate-[pulse_1.5s_ease-in-out_infinite]' : 'bg-[#1A1D24] border-white/5'}`}>
                                <div className="flex items-center gap-2">
                                    <div className="flex gap-1.5">
                                        <div className={`w-2.5 h-2.5 rounded-full opacity-80 ${isThreat ? 'bg-red-500 blur-[1px] animate-pulse' : 'bg-[#FF5F56]'}`} />
                                        <div className="w-2.5 h-2.5 rounded-full bg-[#FFBD2E] opacity-80" />
                                        <div className="w-2.5 h-2.5 rounded-full bg-[#27C93F] opacity-80" />
                                    </div>
                                    <span className={`ml-3 text-[10px] font-bold tracking-widest flex items-center gap-2 uppercase ${isThreat ? 'text-red-300' : 'text-gray-400'}`}>
                                        {isThreat ? <ShieldAlert size={12} className="text-red-500" /> : <Shield size={12} className="text-[#4F8BF9]" />}
                                        AI Analysis Log
                                    </span>
                                </div>
                                <div className="flex items-center gap-3">
                                    <button
                                        onClick={() => setIsPaused(!isPaused)}
                                        title={isPaused ? "Resume Live Feed" : "Pause Live Feed"}
                                        className={`p-1.5 rounded-md border transition-all hover:scale-110 active:scale-95 ${isPaused
                                            ? 'bg-orange-500/20 border-orange-500/40 text-orange-400 font-bold'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:text-[#4F8BF9] hover:border-[#4F8BF9]/30'
                                            }`}
                                    >
                                        {isPaused ? <Play size={10} fill="currentColor" /> : <Pause size={10} fill="currentColor" />}
                                    </button>
                                    <div className="text-[9px] text-[#4F8BF9]/60 font-mono animate-pulse uppercase tracking-wider">
                                        Live
                                    </div>
                                </div>
                            </div>

                            <div className={`absolute top-0 left-0 bottom-0 w-1 ${isThreat ? 'bg-red-500' : 'bg-[#4F8BF9]'}`} />

                            <div className="p-4 bg-[#0A0C10]/95 min-h-[300px]">
                                <div className="relative font-mono text-[11px] leading-relaxed max-h-[280px] overflow-y-auto custom-scrollbar pr-2 flex flex-col gap-5">
                                    {/* Current streaming message with CLI prompt */}
                                    <div className="flex items-start gap-4 text-gray-200">
                                        <span className="text-[#4F8BF9] font-bold shrink-0">&gt;&gt;</span>
                                        <div className="whitespace-pre-wrap flex-1 min-w-0">
                                            <HighlightText text={displayedReasoning} />
                                            <span className="inline-block w-1.5 h-3 bg-[#4F8BF9] ml-1 animate-pulse align-middle" />
                                        </div>
                                    </div>

                                    {/* Historical messages */}
                                    {reasoningHistory.slice(1).map((msg, i) => (
                                        <div key={i} className="flex items-start gap-4 text-gray-500 opacity-60">
                                            <span className="text-[#4F8BF9]/40 font-bold shrink-0">&gt;&gt;</span>
                                            <div className="whitespace-pre-wrap flex-1 min-w-0">
                                                <HighlightText text={msg} />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </section>

                        {/* Performance HUD */}
                        <section className="bg-surface/60 border border-white/5 rounded-xl p-8 backdrop-blur-xl relative overflow-hidden">
                            <h3 className="text-md font-black text-white mb-8 flex items-center gap-3 uppercase italic tracking-tighter">
                                <Activity size={20} className="text-[#4F8BF9]" />
                                Performance Monitor
                            </h3>
                            <div className="space-y-6">
                                <div>
                                    <div className="flex justify-between text-[12px] text-gray-500 font-black mb-2 uppercase tracking-widest">
                                        <span>Analysis Speed</span>
                                        <span className={`font-black ${status.inference.latency_ms > 50 ? 'text-red-500 animate-pulse' :
                                            status.inference.latency_ms > 10 ? 'text-orange-400' : 'text-[#00C853]'
                                            }`}>
                                            {status.inference.latency_ms}ms
                                        </span>
                                    </div>
                                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: `${Math.min(status.inference.latency_ms * 2, 100)}%` }}
                                            className={`h-full ${status.inference.latency_ms > 50 ? 'bg-red-500' :
                                                status.inference.latency_ms > 10 ? 'bg-orange-400' : 'bg-[#00C853]'
                                                } shadow-[0_0_10px_rgba(79,139,249,0.5)]`}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <div className="flex justify-between text-[12px] text-gray-500 font-black mb-2 uppercase tracking-widest">
                                        <span>Data Processing</span>
                                        <span className="text-[#4F8BF9]">Active</span>
                                    </div>
                                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden relative">
                                        <motion.div
                                            animate={{ x: ['-100%', '100%'] }}
                                            transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                                            className="absolute top-0 bottom-0 w-full bg-gradient-to-r from-transparent via-[#4F8BF9] to-transparent shadow-[0_0_15px_rgba(79,139,249,0.5)]"
                                        />
                                    </div>
                                </div>
                            </div>
                        </section>
                    </div>
                </div>

                {/* Right Column: Tactical Telemetry HUD */}
                <aside className="space-y-4">
                    <h3 className="text-[11px] font-black text-[#4F8BF9] mb-4 tracking-[0.4em] flex items-center gap-2 uppercase">
                        <Zap size={14} />
                        System Metrics
                    </h3>
                    <div className="flex flex-col gap-3">
                        {metrics.map((metric, index) => (
                            <motion.div
                                key={index}
                                initial={{ x: 20, opacity: 0 }}
                                animate={{ x: 0, opacity: 1 }}
                                transition={{ delay: index * 0.1 }}
                                className="bg-surface/40 border border-white/5 rounded-lg p-5 flex justify-between items-center group hover:bg-[#4F8BF9]/5 transition-all"
                            >
                                <div className="space-y-1">
                                    <div className="text-[11px] text-gray-500 font-black uppercase tracking-widest leading-none">
                                        {metric.label.replace(' (Root Access)', '').replace(' per Process', '')}
                                    </div>
                                    <div className="text-xl font-black text-white group-hover:text-[#4F8BF9] transition-colors leading-none">
                                        {metric.value}
                                    </div>
                                </div>
                                <div className="h-10 w-[2px] bg-white/5 group-hover:bg-[#4F8BF9]/30 transition-colors" />
                            </motion.div>
                        ))}
                    </div>

                    <div className="mt-8 p-6 bg-[#4F8BF9]/5 border border-[#4F8BF9]/20 rounded-xl">
                        <div className="text-[10px] text-[#4F8BF9] font-black mb-4 tracking-[0.2em] uppercase">Protection Status</div>
                        <div className="space-y-3 font-mono text-[11px] normal-case text-gray-500 italic">
                            <p>• Memory sections verified.</p>
                            <p>• Protected against new and unknown threats.</p>
                            <p>• Core system components isolated safely.</p>
                        </div>
                    </div>
                </aside>
            </div>
        </div>
    );
};

export default HidsLiveDashboard;
