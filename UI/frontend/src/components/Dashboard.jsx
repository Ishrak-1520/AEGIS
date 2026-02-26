import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, FileText, AlertTriangle, Activity, Zap, CheckCircle, ShieldCheck, ShieldAlert, Brain } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
    { name: 'Mon', threats: 2 },
    { name: 'Tue', threats: 5 },
    { name: 'Wed', threats: 1 },
    { name: 'Thu', threats: 8 },
    { name: 'Fri', threats: 3 },
    { name: 'Sat', threats: 0 },
    { name: 'Sun', threats: 1 },
];

const StatCard = ({ title, value, icon: Icon, color, trend }) => (
    <motion.div
        whileHover={{ scale: 1.02 }}
        className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group"
    >
        <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity ${color}`}>
            <Icon size={64} />
        </div>
        <div className="relative z-10">
            <div className="flex items-center gap-3 mb-2">
                <div className={`p-2 rounded-lg bg-white/5 ${color}`}>
                    <Icon size={20} />
                </div>
                <span className="text-gray-400 text-sm font-medium">{title}</span>
            </div>
            <div className="flex items-end gap-3">
                <span className="text-3xl font-bold text-white">{value}</span>
                {trend && (
                    <span className="text-xs font-medium text-green-500 mb-1 bg-green-500/10 px-2 py-0.5 rounded-full">
                        {trend}
                    </span>
                )}
            </div>
        </div>
    </motion.div>
);

const Dashboard = () => {
    const [rtpStatus, setRtpStatus] = useState(null);
    const [systemStats, setSystemStats] = useState({ cpu: 0, memory: 0, disk: 0 });
    const [volatileStatus, setVolatileStatus] = useState({
        is_active: false,
        telemetry: {
            "svcscan.nservices": 0,
            "svcscan.kernel_drivers": 0,
            "handles.nmutant": 0,
            "dlllist.avg_dlls_per_proc": 0,
            "pslist.nprocs64bit": 0
        },
        inference: {
            is_threat: false,
            confidence_score: 0,
            latency_ms: 0,
            ai_reasoning: ""
        }
    });

    useEffect(() => {
        const fetchData = async () => {
            if (window.pywebview?.api) {
                try {
                    const rtp = await window.pywebview.api.get_rtp_status();
                    setRtpStatus(rtp);

                    const stats = await window.pywebview.api.get_system_stats();
                    setSystemStats(stats);

                    const volatile = await window.pywebview.api.get_volatile_memory_status();
                    if (volatile && volatile.status === "success") setVolatileStatus(volatile.data);
                } catch (error) {
                    console.error("Failed to fetch dashboard data:", error);
                }
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const isProtected = rtpStatus?.is_running || false;
    const filesMonitored = rtpStatus?.files_monitored || 0;
    const threatsBlocked = rtpStatus?.threats_blocked || 0;

    const handleToggleProtection = async () => {
        console.log("Toggle button clicked! Current state:", isProtected);
        if (window.pywebview?.api) {
            try {
                console.log("Calling toggle_rtp with:", !isProtected);
                const result = await window.pywebview.api.toggle_rtp(!isProtected);
                console.log("Toggle result:", result);

                setTimeout(async () => {
                    const rtp = await window.pywebview.api.get_rtp_status();
                    console.log("New RTP status:", rtp);
                    setRtpStatus(rtp);
                }, 500);
            } catch (error) {
                console.error("Failed to toggle RTP:", error);
                alert("Failed to toggle protection: " + error.message);
            }
        } else {
            console.error("PyWebView API not available!");
            alert("Cannot connect to backend API");
        }
    };

    return (
        <div className="space-y-6">
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className={`border rounded-xl p-6 ${isProtected
                    ? 'bg-green-500/10 border-green-500/30'
                    : 'bg-red-500/10 border-red-500/30'
                    }`}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        {isProtected ? (
                            <ShieldCheck className="text-green-400" size={48} />
                        ) : (
                            <ShieldAlert className="text-red-400" size={48} />
                        )}
                        <div>
                            <h2 className={`text-2xl font-bold ${isProtected ? 'text-green-400' : 'text-red-400'}`}>
                                {isProtected ? 'Real-Time Protection Active' : 'Real-Time Protection Disabled'}
                            </h2>
                            <p className="text-gray-400 text-sm mt-1">
                                {isProtected
                                    ? 'Your system is actively protected against threats'
                                    : 'Click the button to enable protection'}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-6">
                        {isProtected && (
                            <div className="flex gap-6 text-center">
                                <div>
                                    <div className="text-2xl font-bold text-white">{filesMonitored.toLocaleString()}</div>
                                    <div className="text-xs text-gray-400 mt-1">Files Monitored</div>
                                </div>
                                <div className="w-px bg-white/10"></div>
                                <div>
                                    <div className="text-2xl font-bold text-green-400">{threatsBlocked}</div>
                                    <div className="text-xs text-gray-400 mt-1">Threats Blocked</div>
                                </div>
                            </div>
                        )}
                        <button
                            onClick={handleToggleProtection}
                            className={`px-6 py-3 rounded-lg font-bold transition-all ${isProtected
                                ? 'bg-red-500/20 text-red-400 border-2 border-red-500/50 hover:bg-red-500/30'
                                : 'bg-green-500/20 text-green-400 border-2 border-green-500/50 hover:bg-green-500/30'
                                }`}
                        >
                            {isProtected ? 'Disable Protection' : 'Enable Protection'}
                        </button>
                    </div>
                </div>
            </motion.div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title="Threats Blocked"
                    value={threatsBlocked.toString()}
                    icon={Shield}
                    color="text-primary"
                    trend={threatsBlocked > 0 ? `+${threatsBlocked} today` : 'Secure'}
                />
                <StatCard
                    title="Files Scanned"
                    value={filesMonitored.toLocaleString()}
                    icon={FileText}
                    color="text-blue-400"
                    trend={isProtected ? 'Active' : 'Inactive'}
                />
                <StatCard
                    title="Vulnerabilities"
                    value="0"
                    icon={AlertTriangle}
                    color="text-green-400"
                    trend="Secure"
                />
                <StatCard
                    title="System Load"
                    value={`${Math.round(systemStats.cpu)}%`}
                    icon={Activity}
                    color="text-secondary"
                    trend="Stable"
                />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-surface border border-white/5 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                            <Activity className="text-primary" size={20} />
                            Threat Activity
                        </h3>
                        <select className="bg-background border border-white/10 rounded-lg px-3 py-1 text-sm text-gray-400 outline-none focus:border-primary/50">
                            <option>Last 7 Days</option>
                            <option>Last 30 Days</option>
                        </select>
                    </div>
                    <div className="h-[300px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data}>
                                <defs>
                                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#00F3FF" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#00F3FF" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                                <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0F1926', border: '1px solid #334155', borderRadius: '8px' }}
                                    itemStyle={{ color: '#00F3FF' }}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="threats"
                                    stroke="#00F3FF"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#colorThreats)"
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="space-y-6">
                    <div className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-4 opacity-10 text-primary group-hover:scale-110 transition-transform duration-500">
                            <Zap size={48} />
                        </div>
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2 relative z-10">
                            <Zap className="text-primary" size={20} />
                            Tactical Actions
                        </h3>
                        <div className="space-y-3 relative z-10">
                            <button className="w-full bg-primary/5 hover:bg-primary/20 text-primary border border-primary/20 hover:border-primary/50 rounded-lg p-3 flex items-center justify-between transition-all group/btn shadow-[0_0_10px_rgba(0,0,0,0.2)]">
                                <span className="font-bold tracking-tight text-sm">INITIATE QUICK SCAN</span>
                                <Zap size={16} className="group-hover/btn:animate-pulse" />
                            </button>
                            <button className="w-full bg-white/5 hover:bg-white/10 text-white border border-white/10 hover:border-white/20 rounded-lg p-3 flex items-center justify-between transition-all group/btn">
                                <span className="font-bold tracking-tight text-sm text-gray-400 group-hover/btn:text-white">RECALIBRATE SENSORS</span>
                                <CheckCircle size={16} className="text-green-500/50 group-hover/btn:text-green-500" />
                            </button>
                        </div>
                    </div>

                    {/* Volatile Guardian (HIDS) Widget */}
                    <motion.div
                        animate={volatileStatus.is_active && volatileStatus.inference.is_threat ? {
                            backgroundColor: ['rgba(30, 41, 59, 1)', 'rgba(239, 68, 68, 0.2)', 'rgba(30, 41, 59, 1)'],
                            borderColor: ['rgba(255, 255, 255, 0.1)', 'rgba(239, 68, 68, 0.5)', 'rgba(255, 255, 255, 0.1)'],
                            boxShadow: ['0 0 0px rgba(79, 139, 249, 0)', '0 0 20px rgba(239, 68, 68, 0.2)', '0 0 0px rgba(79, 139, 249, 0)']
                        } : volatileStatus.is_active ? {
                            boxShadow: ['0 0 5px rgba(79, 139, 249, 0.1)', '0 0 15px rgba(79, 139, 249, 0.2)', '0 0 5px rgba(79, 139, 249, 0.1)']
                        } : {}}
                        transition={{ repeat: Infinity, duration: 2 }}
                        className={`bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden ${!volatileStatus.is_active ? 'opacity-70' : ''}`}
                    >
                        {/* Scanline Effect */}
                        {volatileStatus.is_active && (
                            <div className="absolute inset-0 pointer-events-none opacity-[0.03] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] animate-[pulse_2s_infinite]" />
                        )}

                        {!volatileStatus.is_active && (
                            <div className="absolute inset-0 bg-background/40 backdrop-blur-[1px] flex items-center justify-center z-10 rounded-xl overflow-hidden">
                                <div className="bg-surface/90 border border-white/10 px-4 py-2 rounded-lg text-[10px] font-bold text-gray-400 flex items-center gap-2 tracking-widest uppercase">
                                    <ShieldAlert size={14} />
                                    Engine Offline
                                </div>
                            </div>
                        )}

                        <div className="flex items-center justify-between mb-4 relative z-10">
                            <div className="flex items-center gap-2">
                                <div className="relative">
                                    <img
                                        src="/assets/bat4-final.png"
                                        className={`w-6 h-auto ${volatileStatus.is_active && volatileStatus.inference.is_threat ? 'invert-[20%] sepia-[100%] saturate-[500%] hue-rotate-[320deg]' : 'invert-[30%] sepia-[100%] saturate-[1000%] hue-rotate-[190deg] brightness-[1.2]'}`}
                                        alt="icon"
                                        style={{ filter: `drop-shadow(0 0 4px ${volatileStatus.is_active && volatileStatus.inference.is_threat ? '#FF5252' : '#4F8BF9'})` }}
                                    />
                                </div>
                                <h3 className="text-lg font-bold text-white tracking-tight">
                                    Volatile Guardian
                                </h3>
                            </div>
                            {volatileStatus.is_active && volatileStatus.inference.is_threat && (
                                <span className="text-[10px] font-black bg-red-500 text-white px-2 py-0.5 rounded shadow-[0_0_10px_rgba(239,68,68,0.5)]">INTRUSION</span>
                            )}
                        </div>

                        <div className="flex flex-col items-center justify-center py-2 relative z-10">
                            <div className="relative w-32 h-32 flex items-center justify-center">
                                <svg className="w-full h-full transform -rotate-90">
                                    <defs>
                                        <linearGradient id="neonGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                            <stop offset="0%" stopColor="#4F8BF9" />
                                            <stop offset="100%" stopColor="#00F3FF" />
                                        </linearGradient>
                                        <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                            <stop offset="0%" stopColor="#FF5252" />
                                            <stop offset="100%" stopColor="#FF8A80" />
                                        </linearGradient>
                                    </defs>
                                    <circle
                                        cx="64" cy="64" r="58"
                                        stroke="currentColor" strokeWidth="6"
                                        fill="transparent"
                                        className="text-white/5"
                                    />
                                    <motion.circle
                                        cx="64" cy="64" r="58"
                                        stroke={volatileStatus.is_active && volatileStatus.inference.is_threat ? "url(#threatGradient)" : "url(#neonGradient)"}
                                        strokeWidth="8"
                                        fill="transparent"
                                        strokeDasharray={364.4}
                                        initial={{ strokeDashoffset: 364.4 }}
                                        animate={{ strokeDashoffset: 364.4 * (1 - (volatileStatus.is_active ? volatileStatus.inference.confidence_score : 0)) }}
                                        transition={{ duration: 1.5, ease: "easeOut" }}
                                        className="drop-shadow-[0_0_8px_rgba(79,139,249,0.5)]"
                                    />
                                </svg>
                                <div className="absolute flex flex-col items-center">
                                    <span className={`text-2xl font-black ${volatileStatus.is_active && volatileStatus.inference.is_threat ? 'text-red-400' : 'text-white'}`}>
                                        {(volatileStatus.is_active ? (volatileStatus.inference.confidence_score * 100).toFixed(1) : "0.0")}%
                                    </span>
                                    <span className="text-[9px] text-gray-500 uppercase font-black tracking-widest">Threat Prob</span>
                                </div>
                            </div>
                        </div>

                        <div className="mt-4 space-y-2 relative z-10">
                            {[
                                { label: "Active Threads", key: "svcscan.nservices" },
                                { label: "Kernel Stack", key: "svcscan.kernel_drivers" },
                                { label: "Atomic Mutex", key: "handles.nmutant" },
                                { label: "Injection Surface", key: "dlllist.avg_dlls_per_proc" }
                            ].map((item, idx) => (
                                <div key={idx} className="flex justify-between text-[11px] group/item">
                                    <span className="text-gray-500 group-hover/item:text-gray-300 transition-colors uppercase text-[8px] font-bold tracking-[0.1em]">{item.label}:</span>
                                    <span className="text-white font-mono font-bold bg-white/5 px-1.5 rounded text-[10px]">{volatileStatus.telemetry[item.key]}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
