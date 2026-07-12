import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, ShieldAlert, X, Search, Activity } from 'lucide-react';

const ThreatNotification = ({ threat, onDismiss, onViewDetails }) => {
    useEffect(() => {
        const timer = setTimeout(() => {
            onDismiss();
        }, 30000); // Auto dismiss after 30 seconds

        return () => clearTimeout(timer);
    }, [onDismiss]);

    if (!threat) return null;

    const getLevelColor = (level) => {
        switch (level) {
            case 'CRITICAL': return 'text-red-500';
            case 'HIGH': return 'text-orange-500';
            case 'MEDIUM': return 'text-yellow-500';
            case 'LOW': return 'text-green-400';
            default: return 'text-blue-400';
        }
    };

    const getLevelShadow = (level) => {
        switch (level) {
            case 'CRITICAL': return 'shadow-[0_0_30px_rgba(239,68,68,0.4)]';
            case 'HIGH': return 'shadow-[0_0_30px_rgba(249,115,22,0.4)]';
            case 'MEDIUM': return 'shadow-[0_0_30px_rgba(234,179,8,0.4)]';
            case 'LOW': return 'shadow-[0_0_30px_rgba(74,222,128,0.4)]';
            default: return 'shadow-[0_0_30px_rgba(96,165,250,0.4)]';
        }
    };

    const getLevelBg = (level) => {
        switch (level) {
            case 'CRITICAL': return 'bg-red-500/10 border-red-500/30';
            case 'HIGH': return 'bg-orange-500/10 border-orange-500/30';
            case 'MEDIUM': return 'bg-yellow-500/10 border-yellow-500/30';
            case 'LOW': return 'bg-green-500/10 border-green-500/30';
            default: return 'bg-blue-500/10 border-blue-500/30';
        }
    };

    const getExcerpt = () => {
        if (threat.screen_text_sample) {
            return threat.screen_text_sample.split(' ').slice(0, 12).join(' ') + '...';
        }
        if (threat.patterns && threat.patterns.length > 0) {
            return `Detected: ${threat.patterns.join(', ')}`;
        }
        return 'Suspicious activity detected on screen.';
    };

    return (
        <motion.div
            initial={{ x: 400, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 400, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className={`fixed bottom-6 right-6 w-96 rounded-xl border backdrop-blur-2xl z-50 overflow-hidden ${getLevelBg(threat.level)} bg-[#0C0E14]/95 ${getLevelShadow(threat.level)}`}
        >
            {/* Progress bar for auto-dismiss */}
            <motion.div
                initial={{ width: "100%" }}
                animate={{ width: "0%" }}
                transition={{ duration: 30, ease: "linear" }}
                className={`h-1.5 ${getLevelColor(threat.level).replace('text-', 'bg-')} shadow-[0_0_10px_currentColor]`}
            />

            <div className="p-4">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                        <div className={`p-2.5 rounded-lg bg-white/5 ${getLevelColor(threat.level)} shadow-[0_0_15px_currentColor]`}>
                            <AlertTriangle size={24} className="filter drop-shadow-[0_0_8px_currentColor] animate-pulse" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h3 className={`font-bold ${getLevelColor(threat.level)}`}>
                                    {threat.level} THREAT
                                </h3>
                                <span className="text-xs text-gray-400 bg-white/5 px-2 py-0.5 rounded">
                                    {Math.round(threat.confidence)}% Conf.
                                </span>
                            </div>
                            <p className="text-xs text-gray-400 mt-0.5">
                                Source: {threat.source || 'Real-Time Protection'}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={onDismiss}
                        className="text-gray-400 hover:text-white transition-colors p-1 hover:bg-white/10 rounded"
                    >
                        <X size={16} />
                    </button>
                </div>

                {/* Content */}
                <div className="bg-black/20 rounded-lg p-3 mb-3 border border-white/5">
                    <p className="text-sm text-gray-300 italic">
                        "{getExcerpt()}"
                    </p>
                </div>

                {/* Footer / Action */}
                <button
                    onClick={onViewDetails}
                    className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 transition-all duration-300 group hover:shadow-[0_0_15px_rgba(59,130,246,0.3)] hover:scale-[1.02]"
                >
                    <Search size={16} className="group-hover:scale-110 transition-transform" />
                    <span className="font-medium text-sm">View Full Details</span>
                </button>
            </div>
        </motion.div>
    );
};

export default ThreatNotification;
