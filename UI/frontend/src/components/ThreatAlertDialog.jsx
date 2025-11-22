import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Shield, X, Activity, Lock, Globe, CreditCard, AlertOctagon, CheckCircle } from 'lucide-react';

const ThreatAlertDialog = ({ threat, onClose, onAction }) => {
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

    const getLevelBg = (level) => {
        switch (level) {
            case 'CRITICAL': return 'bg-red-500/10 border-red-500/30';
            case 'HIGH': return 'bg-orange-500/10 border-orange-500/30';
            case 'MEDIUM': return 'bg-yellow-500/10 border-yellow-500/30';
            case 'LOW': return 'bg-green-500/10 border-green-500/30';
            default: return 'bg-blue-500/10 border-blue-500/30';
        }
    };

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                {/* Backdrop */}
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    onClick={onClose}
                    className="absolute inset-0 bg-black/80 backdrop-blur-sm"
                />

                {/* Modal */}
                <motion.div
                    initial={{ scale: 0.9, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.9, opacity: 0, y: 20 }}
                    className="relative w-full max-w-2xl bg-[#111a22] border border-white/10 rounded-2xl shadow-2xl overflow-hidden"
                >
                    {/* Header */}
                    <div className={`p-6 border-b ${getLevelBg(threat.level)} flex items-center justify-between`}>
                        <div className="flex items-center gap-4">
                            <div className={`p-3 rounded-xl bg-black/20 ${getLevelColor(threat.level)}`}>
                                <AlertTriangle size={32} />
                            </div>
                            <div>
                                <h2 className={`text-2xl font-bold ${getLevelColor(threat.level)}`}>
                                    THREAT DETECTED
                                </h2>
                                <div className="flex items-center gap-3 mt-1">
                                    <span className="text-gray-300 font-medium">
                                        Level: {threat.level}
                                    </span>
                                    <span className="text-gray-500">•</span>
                                    <span className="text-gray-300">
                                        Confidence: {Math.round(threat.confidence)}%
                                    </span>
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="text-gray-400 hover:text-white transition-colors p-2 hover:bg-white/10 rounded-lg"
                        >
                            <X size={24} />
                        </button>
                    </div>

                    {/* Body */}
                    <div className="p-6 space-y-6 max-h-[60vh] overflow-y-auto custom-scrollbar">

                        {/* Description */}
                        <div>
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">
                                Threat Description
                            </h3>
                            <div className="bg-surface border border-white/5 rounded-xl p-4 text-gray-300">
                                {threat.description || "Suspicious activity detected on your screen matching known threat patterns."}
                            </div>
                        </div>

                        {/* Patterns & Keywords */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">
                                    Detected Patterns
                                </h3>
                                <div className="space-y-2">
                                    {threat.patterns && threat.patterns.length > 0 ? (
                                        threat.patterns.map((pattern, i) => (
                                            <div key={i} className="flex items-center gap-2 text-orange-400 bg-orange-500/10 px-3 py-2 rounded-lg border border-orange-500/20">
                                                <Activity size={16} />
                                                <span className="text-sm font-medium">{pattern}</span>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="text-gray-500 italic">No specific patterns listed</div>
                                    )}
                                </div>
                            </div>
                            <div>
                                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">
                                    Suspicious Keywords
                                </h3>
                                <div className="flex flex-wrap gap-2">
                                    {threat.keywords && threat.keywords.length > 0 ? (
                                        threat.keywords.slice(0, 8).map((keyword, i) => (
                                            <span key={i} className="text-xs font-mono text-gray-300 bg-white/5 px-2 py-1 rounded border border-white/10">
                                                {keyword}
                                            </span>
                                        ))
                                    ) : (
                                        <div className="text-gray-500 italic">No keywords listed</div>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Screen Text Sample */}
                        {threat.screen_text_sample && (
                            <div>
                                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">
                                    Captured Text Sample
                                </h3>
                                <div className="bg-black/30 border border-white/5 rounded-xl p-4 font-mono text-sm text-gray-400 max-h-32 overflow-y-auto">
                                    "{threat.screen_text_sample}"
                                </div>
                            </div>
                        )}

                        {/* Recommended Actions */}
                        <div>
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">
                                Recommended Actions
                            </h3>
                            <div className="space-y-2">
                                {threat.recommended_actions && threat.recommended_actions.length > 0 ? (
                                    threat.recommended_actions.map((action, i) => (
                                        <div key={i} className="flex items-start gap-3 text-gray-300 bg-white/5 px-4 py-3 rounded-lg border border-white/5">
                                            <CheckCircle size={18} className="text-green-400 mt-0.5 shrink-0" />
                                            <span className="text-sm">{action}</span>
                                        </div>
                                    ))
                                ) : (
                                    <div className="text-gray-500 italic">No specific actions recommended</div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Footer / Actions */}
                    <div className="p-6 border-t border-white/10 bg-surface/50 flex justify-end gap-4">
                        <button
                            onClick={() => onAction('DISMISS')}
                            className="px-6 py-3 rounded-lg font-medium text-gray-300 hover:text-white hover:bg-white/5 transition-colors"
                        >
                            Dismiss Alert
                        </button>

                        {(threat.level === 'HIGH' || threat.level === 'CRITICAL') && (
                            <button
                                onClick={() => onAction('BLOCK')}
                                className="px-6 py-3 rounded-lg font-bold bg-red-500 hover:bg-red-600 text-white shadow-lg shadow-red-500/20 transition-all flex items-center gap-2"
                            >
                                <AlertOctagon size={18} />
                                Block & Close
                            </button>
                        )}
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

export default ThreatAlertDialog;
