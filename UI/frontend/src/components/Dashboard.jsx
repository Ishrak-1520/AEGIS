import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, FileText, AlertTriangle, Activity, Zap, CheckCircle, ShieldCheck, ShieldAlert } from 'lucide-react';
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

    useEffect(() => {
        const fetchData = async () => {
            if (window.pywebview?.api) {
                try {
                    const rtp = await window.pywebview.api.get_rtp_status();
                    setRtpStatus(rtp);

                    const stats = await window.pywebview.api.get_system_stats();
                    setSystemStats(stats);
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
                    <div className="bg-surface border border-white/5 rounded-xl p-6">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Zap className="text-yellow-400" size={20} />
                            Quick Actions
                        </h3>
                        <div className="space-y-3">
                            <button className="w-full bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 hover:border-primary/50 rounded-lg p-3 flex items-center justify-between transition-all group">
                                <span className="font-medium">Quick Scan</span>
                                <Zap size={18} className="group-hover:scale-110 transition-transform" />
                            </button>
                            <button className="w-full bg-white/5 hover:bg-white/10 text-white border border-white/10 hover:border-white/20 rounded-lg p-3 flex items-center justify-between transition-all group">
                                <span className="font-medium">Update Database</span>
                                <CheckCircle size={18} className="text-green-400 group-hover:scale-110 transition-transform" />
                            </button>
                        </div>
                    </div>

                    <div className="bg-surface border border-white/5 rounded-xl p-6">
                        <h3 className="text-lg font-bold text-white mb-4">System Status</h3>
                        <div className="space-y-4">
                            <div>
                                <div className="flex justify-between text-sm mb-1">
                                    <span className="text-gray-400">CPU Usage</span>
                                    <span className="text-white font-medium">{Math.round(systemStats.cpu)}%</span>
                                </div>
                                <div className="h-2 bg-background rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-blue-500 rounded-full transition-all duration-500"
                                        style={{ width: `${Math.min(systemStats.cpu, 100)}%` }}
                                    />
                                </div>
                            </div>
                            <div>
                                <div className="flex justify-between text-sm mb-1">
                                    <span className="text-gray-400">Memory</span>
                                    <span className="text-white font-medium">{Math.round(systemStats.memory)}%</span>
                                </div>
                                <div className="h-2 bg-background rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-purple-500 rounded-full transition-all duration-500"
                                        style={{ width: `${Math.min(systemStats.memory, 100)}%` }}
                                    />
                                </div>
                            </div>
                            <div>
                                <div className="flex justify-between text-sm mb-1">
                                    <span className="text-gray-400">Disk</span>
                                    <span className="text-white font-medium">{Math.round(systemStats.disk)}%</span>
                                </div>
                                <div className="h-2 bg-background rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-green-500 rounded-full transition-all duration-500"
                                        style={{ width: `${Math.min(systemStats.disk, 100)}%` }}
                                    />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
