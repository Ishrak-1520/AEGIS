import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Wifi,
    WifiOff,
    AlertTriangle,
    Activity,
    ShieldAlert,
    Clock,
    ArrowRight,
    RefreshCw,
    Shield,
    Ban,
    Unlock,
    Plus,
    Loader2,
    Power,
    Info,
    ChevronDown,
    ChevronUp,
    AlertCircle,
    Zap,
    Eye
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
    
    // IPS / Blocked IPs State
    const [blockedIps, setBlockedIps] = useState([]);
    const [ipsStatus, setIpsStatus] = useState({
        ips_available: false,
        auto_block_enabled: false,
        blocked_count: 0
    });
    const [newBlockIp, setNewBlockIp] = useState('');
    const [blockingIp, setBlockingIp] = useState(null);
    const [unblockingIp, setUnblockingIp] = useState(null);
    
    // Toggle state
    const [isToggling, setIsToggling] = useState(false);
    const [expandedAlert, setExpandedAlert] = useState(null);

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

    // Fetch blocked IPs every 5 seconds
    useEffect(() => {
        const fetchBlockedIps = async () => {
            if (window.pywebview?.api) {
                try {
                    // Get blocked IPs
                    const result = await window.pywebview.api.get_blocked_ips();
                    if (result.success) {
                        setBlockedIps(result.blocked_ips || []);
                    }
                    
                    // Get IPS status
                    const status = await window.pywebview.api.get_ips_status();
                    if (status.success) {
                        setIpsStatus(status);
                    }
                } catch (error) {
                    console.error("Failed to fetch blocked IPs:", error);
                }
            }
        };

        fetchBlockedIps();
        const interval = setInterval(fetchBlockedIps, 5000);
        return () => clearInterval(interval);
    }, []);

    // Handle manual IP block
    const handleBlockIp = async () => {
        if (!newBlockIp.trim()) return;
        
        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(newBlockIp.trim())) {
            alert('Invalid IP address format');
            return;
        }
        
        setBlockingIp(newBlockIp);
        try {
            const result = await window.pywebview.api.block_ip(newBlockIp.trim());
            if (result.success) {
                setBlockedIps(prev => [...prev, newBlockIp.trim()]);
                setNewBlockIp('');
            } else {
                alert(result.error || 'Failed to block IP');
            }
        } catch (error) {
            console.error("Failed to block IP:", error);
            alert('Failed to block IP: ' + error.message);
        }
        setBlockingIp(null);
    };

    // Handle IP unblock
    const handleUnblockIp = async (ip) => {
        setUnblockingIp(ip);
        try {
            const result = await window.pywebview.api.unblock_ip(ip);
            if (result.success) {
                setBlockedIps(prev => prev.filter(blocked => blocked !== ip));
            } else {
                alert(result.error || 'Failed to unblock IP');
            }
        } catch (error) {
            console.error("Failed to unblock IP:", error);
            alert('Failed to unblock IP: ' + error.message);
        }
        setUnblockingIp(null);
    };

    // Handle auto-block toggle
    const handleToggleAutoBlock = async () => {
        try {
            const newValue = !ipsStatus.auto_block_enabled;
            const result = await window.pywebview.api.toggle_auto_block(newValue);
            if (result.success) {
                setIpsStatus(prev => ({ ...prev, auto_block_enabled: newValue }));
            }
        } catch (error) {
            console.error("Failed to toggle auto-block:", error);
        }
    };

    // Handle NIDS toggle (Online/Offline button)
    const handleToggleNids = async () => {
        if (isToggling) return;
        
        setIsToggling(true);
        try {
            const newState = !isActive;
            const result = await window.pywebview.api.toggle_nids(newState);
            console.log("NIDS toggle result:", result);
            
            // Fetch updated status
            setTimeout(async () => {
                const status = await window.pywebview.api.get_nids_status();
                setNidsStatus(status);
                setIsToggling(false);
            }, 500);
        } catch (error) {
            console.error("Failed to toggle NIDS:", error);
            setIsToggling(false);
        }
    };

    // Get risk level color
    const getRiskColor = (level) => {
        switch (level) {
            case 'CRITICAL': return 'text-red-500 bg-red-500/20 border-red-500/50';
            case 'HIGH': return 'text-orange-500 bg-orange-500/20 border-orange-500/50';
            case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/20 border-yellow-500/50';
            case 'LOW': return 'text-blue-400 bg-blue-500/20 border-blue-500/50';
            default: return 'text-gray-400 bg-gray-500/20 border-gray-500/50';
        }
    };

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
                        <button
                            onClick={handleToggleNids}
                            disabled={isToggling || hasError}
                            className={`px-4 py-2 rounded-lg font-bold cursor-pointer transition-all hover:scale-105 active:scale-95 flex items-center gap-2 ${isActive && !hasError
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 hover:bg-cyan-500/30'
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/50 hover:bg-gray-500/30'
                            } ${isToggling ? 'opacity-50 cursor-wait' : ''} ${hasError ? 'cursor-not-allowed' : ''}`}
                        >
                            {isToggling ? (
                                <Loader2 size={16} className="animate-spin" />
                            ) : (
                                <Power size={16} />
                            )}
                            {isActive && !hasError ? 'ONLINE' : 'OFFLINE'}
                        </button>
                    </div>
                </div>
            </motion.div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
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

                <motion.div
                    whileHover={{ scale: 1.02 }}
                    className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden group"
                >
                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-orange-400">
                        <Ban size={64} />
                    </div>
                    <div className="relative z-10">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 rounded-lg bg-white/5 text-orange-400">
                                <Ban size={20} />
                            </div>
                            <span className="text-gray-400 text-sm font-medium">IPs Blocked</span>
                        </div>
                        <div className="flex items-end gap-3">
                            <span className="text-3xl font-bold text-white">
                                {blockedIps.length}
                            </span>
                            {ipsStatus.auto_block_enabled && (
                                <span className="text-xs font-medium text-orange-500 mb-1 bg-orange-500/10 px-2 py-0.5 rounded-full">
                                    Auto
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
                        {networkAlerts.length > 0 && (
                            <span className="ml-auto text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                                {networkAlerts.length} alerts
                            </span>
                        )}
                    </h3>
                    <div className="space-y-3 max-h-[350px] overflow-y-auto custom-scrollbar">
                        {networkAlerts.length > 0 ? (
                            networkAlerts.map((alert, index) => (
                                <motion.div
                                    key={`${alert.timestamp}-${index}`}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.05 }}
                                    className={`rounded-lg border overflow-hidden ${alert.type === 'system_error'
                                            ? 'bg-yellow-500/10 border-yellow-500/20'
                                            : 'bg-red-500/10 border-red-500/20'
                                        }`}
                                >
                                    {alert.type === 'system_error' ? (
                                        <div className="flex items-start gap-2 p-3">
                                            <AlertTriangle size={16} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                                            <div className="text-sm">
                                                <span className="text-yellow-400 font-medium">System: </span>
                                                <span className="text-gray-300">{alert.msg}</span>
                                            </div>
                                        </div>
                                    ) : (
                                        <>
                                            {/* Alert Header */}
                                            <div 
                                                className="p-3 cursor-pointer hover:bg-white/5 transition-colors"
                                                onClick={() => setExpandedAlert(expandedAlert === index ? null : index)}
                                            >
                                                <div className="flex items-center justify-between mb-1">
                                                    <div className="flex items-center gap-2">
                                                        {alert.xai?.risk_level && (
                                                            <span className={`text-xs px-2 py-0.5 rounded border ${getRiskColor(alert.xai.risk_level)}`}>
                                                                {alert.xai.risk_level}
                                                            </span>
                                                        )}
                                                        <span className="text-red-400 font-medium text-sm">
                                                            {alert.xai?.title || alert.threat_type || 'Unknown Threat'}
                                                        </span>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-xs text-gray-500">
                                                            {alert.confidence ? `${(alert.confidence * 100).toFixed(0)}%` : ''}
                                                        </span>
                                                        {expandedAlert === index ? (
                                                            <ChevronUp size={14} className="text-gray-400" />
                                                        ) : (
                                                            <ChevronDown size={14} className="text-gray-400" />
                                                        )}
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-1 text-xs text-gray-400">
                                                    <span className="font-mono">{alert.source_ip}</span>
                                                    <ArrowRight size={12} />
                                                    <span className="font-mono">{alert.dest_ip}</span>
                                                </div>
                                                <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                                                    <Clock size={10} />
                                                    <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                                    {alert.blocked && (
                                                        <span className="ml-2 px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded text-[10px]">
                                                            BLOCKED
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                            
                                            {/* XAI Explanation Panel */}
                                            <AnimatePresence>
                                                {expandedAlert === index && alert.xai && (
                                                    <motion.div
                                                        initial={{ height: 0, opacity: 0 }}
                                                        animate={{ height: 'auto', opacity: 1 }}
                                                        exit={{ height: 0, opacity: 0 }}
                                                        className="border-t border-red-500/20 bg-dark/50"
                                                    >
                                                        <div className="p-4 space-y-3">
                                                            {/* Simple Explanation */}
                                                            <div className="flex items-start gap-2">
                                                                <Info size={16} className="text-cyan-400 mt-0.5 flex-shrink-0" />
                                                                <div>
                                                                    <p className="text-xs text-gray-500 mb-1">What's happening:</p>
                                                                    <p className="text-sm text-white">
                                                                        {alert.xai.simple_explanation}
                                                                    </p>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* Recommended Action */}
                                                            <div className="flex items-start gap-2">
                                                                <Shield size={16} className="text-orange-400 mt-0.5 flex-shrink-0" />
                                                                <div>
                                                                    <p className="text-xs text-gray-500 mb-1">What you should know:</p>
                                                                    <p className="text-sm text-gray-300">
                                                                        {alert.xai.recommended_action}
                                                                    </p>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* Confidence */}
                                                            <div className="flex items-start gap-2">
                                                                <Eye size={16} className="text-purple-400 mt-0.5 flex-shrink-0" />
                                                                <div>
                                                                    <p className="text-xs text-gray-500 mb-1">AI Confidence:</p>
                                                                    <p className="text-sm text-gray-300">
                                                                        {alert.xai.confidence_interpretation}
                                                                    </p>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* Technical Details (collapsible) */}
                                                            <div className="pt-2 border-t border-white/5">
                                                                <p className="text-xs text-gray-500 mb-1">Technical details:</p>
                                                                <p className="text-xs text-gray-400 font-mono">
                                                                    {alert.xai.technical_details}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    </motion.div>
                                                )}
                                            </AnimatePresence>
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

            {/* IPS / Blocked IPs Section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* IPS Status & Controls */}
                <div className="bg-surface border border-white/5 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                            <Shield className="text-orange-400" size={20} />
                            IPS Controls
                        </h3>
                        <div className={`px-3 py-1 rounded-full text-xs font-bold ${
                            ipsStatus.ips_available 
                                ? 'bg-green-500/20 text-green-400 border border-green-500/50'
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                        }`}>
                            {ipsStatus.ips_available ? 'IPS ACTIVE' : 'IPS UNAVAILABLE'}
                        </div>
                    </div>
                    
                    {/* Auto-Block Toggle */}
                    <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg mb-4">
                        <div>
                            <p className="text-white font-medium">Auto-Block Threats</p>
                            <p className="text-xs text-gray-400 mt-1">Automatically block HIGH/CRITICAL threat IPs</p>
                        </div>
                        <button
                            onClick={handleToggleAutoBlock}
                            className={`relative w-12 h-6 rounded-full transition-colors ${
                                ipsStatus.auto_block_enabled ? 'bg-cyan-500' : 'bg-gray-600'
                            }`}
                        >
                            <div className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                                ipsStatus.auto_block_enabled ? 'translate-x-6' : 'translate-x-0.5'
                            }`} />
                        </button>
                    </div>

                    {/* Manual IP Block Input */}
                    <div className="flex gap-2">
                        <input
                            type="text"
                            value={newBlockIp}
                            onChange={(e) => setNewBlockIp(e.target.value)}
                            placeholder="Enter IP to block (e.g., 192.168.1.100)"
                            className="flex-1 px-4 py-2 bg-dark border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                            onKeyPress={(e) => e.key === 'Enter' && handleBlockIp()}
                        />
                        <button
                            onClick={handleBlockIp}
                            disabled={blockingIp || !newBlockIp.trim()}
                            className="px-4 py-2 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                        >
                            {blockingIp ? (
                                <Loader2 size={16} className="animate-spin" />
                            ) : (
                                <Ban size={16} />
                            )}
                            Block
                        </button>
                    </div>

                    {/* Stats */}
                    <div className="mt-4 flex items-center gap-4 text-sm text-gray-400">
                        <span className="flex items-center gap-1">
                            <Ban size={14} className="text-red-400" />
                            {blockedIps.length} IPs blocked
                        </span>
                    </div>
                </div>

                {/* Blocked IPs List */}
                <div className="bg-surface border border-white/5 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Ban className="text-red-400" size={20} />
                        Blocked IPs
                    </h3>
                    <div className="space-y-2 max-h-[250px] overflow-y-auto custom-scrollbar">
                        {blockedIps.length > 0 ? (
                            blockedIps.map((ip, index) => (
                                <motion.div
                                    key={`blocked-${ip}-${index}`}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    className="flex items-center justify-between p-3 bg-red-500/10 border border-red-500/20 rounded-lg"
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="p-1.5 bg-red-500/20 rounded">
                                            <Ban size={14} className="text-red-400" />
                                        </div>
                                        <span className="font-mono text-white">{ip}</span>
                                    </div>
                                    <button
                                        onClick={() => handleUnblockIp(ip)}
                                        disabled={unblockingIp === ip}
                                        className="px-3 py-1.5 bg-green-500/20 border border-green-500/50 rounded text-green-400 text-sm hover:bg-green-500/30 transition-colors disabled:opacity-50 flex items-center gap-1"
                                    >
                                        {unblockingIp === ip ? (
                                            <Loader2 size={14} className="animate-spin" />
                                        ) : (
                                            <Unlock size={14} />
                                        )}
                                        Unblock
                                    </button>
                                </motion.div>
                            ))
                        ) : (
                            <div className="text-center py-8 text-gray-500">
                                <Shield size={32} className="mx-auto mb-2 opacity-30" />
                                <p className="text-sm">No IPs currently blocked</p>
                                <p className="text-xs mt-1">Threats will be auto-blocked when detected</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkMonitor;
