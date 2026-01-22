import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
    Wifi,
    WifiOff,
    AlertTriangle,
    Activity,
    ShieldAlert,
    Clock,
    ArrowRight,
    RefreshCw
} from 'lucide-react';
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer
} from 'recharts';

const NetworkMonitor = () => {
    // State
    const [nidsStatus, setNidsStatus] = useState({
        is_active: false,
        total_packets: 0,
        total_flows: 0,
        threats_detected: 0,
        error: null
    });
    const [networkAlerts, setNetworkAlerts] = useState([]);
    const [trafficData, setTrafficData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    // Ref for tracking previous packet count
    const prevPacketsRef = useRef(0);

    // Fetch NIDS data every second
    useEffect(() => {
        const fetchData = async () => {
            if (window.pywebview?.api) {
                try {
                    // Get NIDS status
                    const status = await window.pywebview.api.get_nids_status();
                    setNidsStatus(status);

                    // Calculate packets per second
                    const currentPackets = status.total_packets || 0;
                    const pps = currentPackets - prevPacketsRef.current;
                    prevPacketsRef.current = currentPackets;

                    // Update traffic chart data
                    const now = new Date();
                    const timeLabel = now.toLocaleTimeString('en-US', {
                        hour12: false,
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });

                    setTrafficData(prev => {
                        const newData = [...prev, { time: timeLabel, pps: Math.max(0, pps) }];
                        // Keep only last 30 data points
                        return newData.slice(-30);
                    });

                    // Get network alerts
                    const alerts = await window.pywebview.api.get_network_alerts();
                    if (alerts && alerts.length > 0) {
                        setNetworkAlerts(prev => {
                            const combined = [...alerts, ...prev];
                            // Keep only last 50 alerts
                            return combined.slice(0, 50);
                        });
                    }

                    setIsLoading(false);
                } catch (error) {
                    console.error("Failed to fetch NIDS data:", error);
                }
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 1000);
        return () => clearInterval(interval);
    }, []);

    const isActive = nidsStatus.is_active;
    const hasError = nidsStatus.error !== null;

    return (
        <div className="space-y-6">
            {/* Error Banner */}
            {hasError && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-red-500/10 border border-red-500/30 rounded-xl p-4"
                >
                    <div className="flex items-center gap-4">
                        <div className="p-2 bg-red-500/20 rounded-lg">
                            <AlertTriangle className="text-red-400" size={24} />
                        </div>
                        <div className="flex-1">
                            <h3 className="text-red-400 font-bold">NIDS Error</h3>
                            <p className="text-gray-400 text-sm mt-1">{nidsStatus.error}</p>
                        </div>
                        <div className="px-4 py-2 bg-red-500/20 rounded-lg">
                            <span className="text-red-400 text-sm font-medium">Run as Administrator</span>
                        </div>
                    </div>
                </motion.div>
            )}

            {/* Status Card */}
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className={`border rounded-xl p-6 ${isActive && !hasError
                        ? 'bg-cyan-500/10 border-cyan-500/30'
                        : 'bg-gray-500/10 border-gray-500/30'
                    }`}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        {isActive && !hasError ? (
                            <motion.div
                                animate={{ scale: [1, 1.1, 1] }}
                                transition={{ repeat: Infinity, duration: 2 }}
                            >
                                <Wifi className="text-cyan-400" size={48} />
                            </motion.div>
                        ) : (
                            <WifiOff className="text-gray-400" size={48} />
                        )}
                        <div>
                            <h2 className={`text-2xl font-bold ${isActive && !hasError ? 'text-cyan-400' : 'text-gray-400'
                                }`}>
                                {isActive && !hasError
                                    ? 'Network Sniffer Active'
                                    : hasError
                                        ? 'Sniffer Error'
                                        : 'Network Sniffer Inactive'}
                            </h2>
                            <p className="text-gray-400 text-sm mt-1">
                                {isActive && !hasError
                                    ? 'Monitoring network traffic for intrusions'
                                    : hasError
                                        ? 'Unable to capture packets - see error above'
                                        : 'Waiting for sniffer to start...'}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-6">
                        {isActive && !hasError && (
                            <div className="flex gap-6 text-center">
                                <div>
                                    <div className="text-2xl font-bold text-white">
                                        {nidsStatus.total_packets.toLocaleString()}
                                    </div>
                                    <div className="text-xs text-gray-400 mt-1">Packets Captured</div>
                                </div>
                                <div className="w-px bg-white/10"></div>
                                <div>
                                    <div className="text-2xl font-bold text-cyan-400">
                                        {nidsStatus.total_flows.toLocaleString()}
                                    </div>
                                    <div className="text-xs text-gray-400 mt-1">Flows Analyzed</div>
                                </div>
                            </div>
                        )}
                        <div className={`px-4 py-2 rounded-lg font-bold ${isActive && !hasError
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50'
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                            }`}>
                            {isActive && !hasError ? 'ONLINE' : 'OFFLINE'}
                        </div>
                    </div>
                </div>
            </motion.div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <motion.div
                    whileHover={{ scale: 1.02 }}
                    className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group"
                >
                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-cyan-400">
                        <Activity size={64} />
                    </div>
                    <div className="relative z-10">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 rounded-lg bg-white/5 text-cyan-400">
                                <Activity size={20} />
                            </div>
                            <span className="text-gray-400 text-sm font-medium">Total Packets</span>
                        </div>
                        <div className="flex items-end gap-3">
                            <span className="text-3xl font-bold text-white">
                                {nidsStatus.total_packets.toLocaleString()}
                            </span>
                            {isActive && !hasError && (
                                <span className="text-xs font-medium text-cyan-500 mb-1 bg-cyan-500/10 px-2 py-0.5 rounded-full">
                                    Live
                                </span>
                            )}
                        </div>
                    </div>
                </motion.div>

                <motion.div
                    whileHover={{ scale: 1.02 }}
                    className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group"
                >
                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-purple-400">
                        <RefreshCw size={64} />
                    </div>
                    <div className="relative z-10">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 rounded-lg bg-white/5 text-purple-400">
                                <RefreshCw size={20} />
                            </div>
                            <span className="text-gray-400 text-sm font-medium">Active Flows</span>
                        </div>
                        <div className="flex items-end gap-3">
                            <span className="text-3xl font-bold text-white">
                                {nidsStatus.total_flows.toLocaleString()}
                            </span>
                        </div>
                    </div>
                </motion.div>

                <motion.div
                    whileHover={{ scale: 1.02 }}
                    className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group"
                >
                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-red-400">
                        <ShieldAlert size={64} />
                    </div>
                    <div className="relative z-10">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 rounded-lg bg-white/5 text-red-400">
                                <ShieldAlert size={20} />
                            </div>
                            <span className="text-gray-400 text-sm font-medium">Threats Detected</span>
                        </div>
                        <div className="flex items-end gap-3">
                            <span className="text-3xl font-bold text-white">
                                {nidsStatus.threats_detected}
                            </span>
                            {nidsStatus.threats_detected > 0 && (
                                <span className="text-xs font-medium text-red-500 mb-1 bg-red-500/10 px-2 py-0.5 rounded-full">
                                    Alert
                                </span>
                            )}
                        </div>
                    </div>
                </motion.div>
            </div>

            {/* Traffic Graph & Threat Feed */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Traffic Graph */}
                <div className="lg:col-span-2 bg-surface border border-white/5 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                            <Activity className="text-cyan-400" size={20} />
                            Network Traffic (Packets/sec)
                        </h3>
                        <span className="text-xs text-gray-400 bg-white/5 px-3 py-1 rounded-full">
                            Real-time
                        </span>
                    </div>
                    <div className="h-[250px] w-full">
                        {trafficData.length > 1 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={trafficData}>
                                    <defs>
                                        <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#00F3FF" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#00F3FF" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                                    <XAxis
                                        dataKey="time"
                                        stroke="#94a3b8"
                                        fontSize={10}
                                        tickLine={false}
                                        axisLine={false}
                                        interval="preserveStartEnd"
                                    />
                                    <YAxis
                                        stroke="#94a3b8"
                                        fontSize={12}
                                        tickLine={false}
                                        axisLine={false}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#0F1926',
                                            border: '1px solid #334155',
                                            borderRadius: '8px'
                                        }}
                                        itemStyle={{ color: '#00F3FF' }}
                                        labelStyle={{ color: '#94a3b8' }}
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="pps"
                                        name="Packets/sec"
                                        stroke="#00F3FF"
                                        strokeWidth={2}
                                        fillOpacity={1}
                                        fill="url(#colorPps)"
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="h-full flex items-center justify-center text-gray-500">
                                <div className="text-center">
                                    <Activity size={48} className="mx-auto mb-3 opacity-30" />
                                    <p>Waiting for traffic data...</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Live Threat Feed */}
                <div className="bg-surface border border-white/5 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <ShieldAlert className="text-red-400" size={20} />
                        Live Threat Feed
                    </h3>
                    <div className="space-y-3 max-h-[250px] overflow-y-auto custom-scrollbar">
                        {networkAlerts.length > 0 ? (
                            networkAlerts.map((alert, index) => (
                                <motion.div
                                    key={`${alert.timestamp}-${index}`}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.05 }}
                                    className={`p-3 rounded-lg border ${alert.type === 'system_error'
                                            ? 'bg-yellow-500/10 border-yellow-500/20'
                                            : 'bg-red-500/10 border-red-500/20'
                                        }`}
                                >
                                    {alert.type === 'system_error' ? (
                                        <div className="flex items-start gap-2">
                                            <AlertTriangle size={16} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                                            <div className="text-sm">
                                                <span className="text-yellow-400 font-medium">System: </span>
                                                <span className="text-gray-300">{alert.msg}</span>
                                            </div>
                                        </div>
                                    ) : (
                                        <>
                                            <div className="flex items-center justify-between mb-1">
                                                <span className="text-red-400 font-medium text-sm">
                                                    {alert.threat_type || 'Unknown Threat'}
                                                </span>
                                                <span className="text-xs text-gray-500">
                                                    {alert.confidence ? `${(alert.confidence * 100).toFixed(0)}%` : ''}
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-1 text-xs text-gray-400">
                                                <span className="font-mono">{alert.source_ip}</span>
                                                <ArrowRight size={12} />
                                                <span className="font-mono">{alert.dest_ip}</span>
                                            </div>
                                            <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                                                <Clock size={10} />
                                                <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                            </div>
                                        </>
                                    )}
                                </motion.div>
                            ))
                        ) : (
                            <div className="text-center py-8 text-gray-500">
                                <ShieldAlert size={32} className="mx-auto mb-2 opacity-30" />
                                <p className="text-sm">No threats detected</p>
                                <p className="text-xs mt-1">The network appears safe</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkMonitor;
