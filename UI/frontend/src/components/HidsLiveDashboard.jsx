import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Brain, Activity, Zap, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';

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

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    const metrics = [
        { label: "Hidden Background Services", value: status.telemetry["svcscan.nservices"] },
        { label: "Kernel Drivers (Root Access)", value: status.telemetry["svcscan.kernel_drivers"] },
        { label: "System Locks (Mutexes)", value: status.telemetry["handles.nmutant"] },
        { label: "Code Libraries per Process", value: status.telemetry["dlllist.avg_dlls_per_proc"] },
        { label: "Active 64-bit Processes", value: status.telemetry["pslist.nprocs64bit"] }
    ];

    const isThreat = status.inference.is_threat;
    const confidence = (status.inference.confidence_score * 100).toFixed(1);

    return (
        <div className="flex-1 overflow-y-auto bg-[#0E1117] p-8 custom-scrollbar relative">
            {!status.is_active && (
                <div className="absolute inset-0 bg-[#0E1117]/60 backdrop-blur-sm flex flex-col items-center justify-center z-50 p-8 text-center">
                    <div className="bg-[#262730] border border-[#FF5252]/30 p-10 rounded-2xl shadow-2xl max-w-md">
                        <ShieldAlert size={64} className="text-[#FF5252] mb-6 mx-auto animate-pulse" />
                        <h2 className="text-2xl font-bold text-white mb-4">HIDS Engine Deactivated</h2>
                        <p className="text-[#8B949E] mb-8">
                            The Dynamic Volatile Memory HIDS is integrated into the Real-Time Protection system.
                            Please enable **Real-Time Protection** from the main dashboard to begin monitoring.
                        </p>
                        <div className="text-[10px] text-[#4F8BF9] uppercase tracking-widest font-bold border border-[#4F8BF9]/20 px-4 py-2 rounded-full inline-block">
                            Waiting for RTP Activation...
                        </div>
                    </div>
                </div>
            )}

            {/* Header */}
            <header className="mb-8">
                <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                    <Shield className="text-[#4F8BF9]" size={32} />
                    HIDS Enterprise Dashboard
                </h1>
                <p className="text-[#8B949E] mt-2">
                    Real-time Host-Based Intrusion Detection System powered by Random Forest
                </p>
            </header>

            {/* Live Telemetry Section */}
            <section className="mb-8">
                <h3 className="text-xl font-semibold text-[#E6EDF3] mb-4 flex items-center gap-2">
                    <Activity size={20} className="text-[#4F8BF9]" />
                    Live Telemetry
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    {metrics.map((metric, index) => (
                        <motion.div
                            key={index}
                            whileHover={{ translateY: -2 }}
                            className="bg-[#262730] border border-[#30363D] rounded-lg p-4 text-center shadow-lg hover:border-[#4F8BF9] transition-colors"
                        >
                            <div className="text-[12px] text-[#8B949E] uppercase tracking-wider font-semibold mb-2">
                                {metric.label}
                            </div>
                            <div className="text-2xl font-bold text-[#4F8BF9]">
                                {metric.value}
                            </div>
                        </motion.div>
                    ))}
                </div>
            </section>

            {/* Diagnostic Results Section */}
            <section className="mb-8">
                <h3 className="text-xl font-semibold text-[#E6EDF3] mb-4 flex items-center gap-2">
                    <Zap size={20} className="text-[#4F8BF9]" />
                    Diagnostic Results
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    {/* Threat Banner */}
                    <motion.div
                        initial={false}
                        animate={{ scale: 1 }}
                        className={`rounded-lg p-6 flex flex-col justify-center border ${isThreat
                            ? "bg-[rgba(255,82,82,0.1)] border-[#FF5252]"
                            : "bg-[rgba(0,200,83,0.1)] border-[#00C853]"
                            }`}
                    >
                        <h2 className={`text-2xl font-bold flex items-center gap-2 ${isThreat ? "text-[#FF5252]" : "text-[#00C853]"}`}>
                            {isThreat ? <AlertTriangle /> : <CheckCircle />}
                            {isThreat ? "THREAT DETECTED" : "SYSTEM SECURE"}
                        </h2>
                        <p className={`mt-2 ${isThreat ? "text-[#FFEBEE]" : "text-[#E8F5E9]"}`}>
                            {isThreat ? "Malware signatures matched." : "Integrity verified."}
                        </p>
                    </motion.div>

                    {/* Quick Metrics */}
                    <div className="grid grid-cols-2 gap-4">
                        <div className="bg-[#262730] rounded-lg p-6 border border-[#30363D]">
                            <div className="text-[#8B949E] text-sm uppercase mb-1">Confidence Score</div>
                            <div className="text-3xl font-bold text-white">{confidence}%</div>
                        </div>
                        <div className="bg-[#262730] rounded-lg p-6 border border-[#30363D]">
                            <div className="text-[#8B949E] text-sm uppercase mb-1">Inference Time</div>
                            <div className="text-3xl font-bold text-white mb-1">
                                {(status.inference.latency_ms / 1000).toFixed(4)}s
                            </div>
                            <div className={`text-sm ${status.inference.latency_ms < 10 ? 'text-[#00C853]' : 'text-[#FF5252]'}`}>
                                {status.inference.latency_ms} ms
                            </div>
                        </div>
                    </div>
                </div>

                {/* AI Reasoning Narrative */}
                <motion.div
                    layout
                    className={`bg-[#262730] p-6 rounded-lg border-l-4 shadow-xl ${isThreat ? "border-[#FF5252]" : "border-[#00C853]"
                        }`}
                >
                    <h4 className="text-lg font-bold text-[#FAFAFA] mb-3 flex items-center gap-2">
                        <Brain size={20} />
                        AI Reasoning
                    </h4>
                    <p className="text-[#D1D5DB] text-md leading-relaxed">
                        {status.inference.ai_reasoning}
                    </p>
                </motion.div>
            </section>
        </div>
    );
};

export default HidsLiveDashboard;
