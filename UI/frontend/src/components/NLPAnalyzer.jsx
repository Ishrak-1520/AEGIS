import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Brain, Send, AlertTriangle, CheckCircle, Shield } from 'lucide-react';

const NLPAnalyzer = () => {
    const [text, setText] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleAnalyze = async () => {
        if (!text.trim()) return;

        setLoading(true);
        setResult(null);

        if (window.pywebview?.api) {
            try {
                const analysis = await window.pywebview.api.analyze_text(text);
                setResult(analysis);
            } catch (error) {
                console.error("Analysis failed:", error);
                setResult({ error: "Analysis failed. Please try again." });
            }
        } else {
            // Mock for dev
            setTimeout(() => {
                setResult({
                    is_threat: text.toLowerCase().includes('hack') || text.toLowerCase().includes('password'),
                    threat_type: text.toLowerCase().includes('password') ? 'Phishing' : 'Social Engineering',
                    confidence: 0.85,
                    flagged_keywords: ['password', 'urgent']
                });
            }, 1000);
        }
        setLoading(false);
    };

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div className="bg-primary/10 border border-primary/20 rounded-xl p-6 flex items-start gap-4">
                <Brain className="text-primary shrink-0" size={32} />
                <div>
                    <h3 className="text-lg font-bold text-white mb-1">AI Threat Detector</h3>
                    <p className="text-gray-400 text-sm">
                        Use our advanced NLP model to analyze emails, messages, or any text for potential security threats like phishing, social engineering, or malicious intent.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-surface border border-white/5 rounded-xl p-6 flex flex-col h-[500px]">
                    <h3 className="font-bold text-white mb-4">Input Text</h3>
                    <textarea
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        placeholder="Paste suspicious text here..."
                        className="flex-1 bg-black/20 border border-white/10 rounded-lg p-4 text-white resize-none focus:border-primary/50 outline-none transition-colors mb-4"
                    />
                    <button
                        onClick={handleAnalyze}
                        disabled={loading || !text}
                        className="bg-primary text-black font-bold px-6 py-3 rounded-lg flex items-center justify-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? (
                            <motion.div
                                animate={{ rotate: 360 }}
                                transition={{ repeat: Infinity, duration: 1 }}
                                className="w-5 h-5 border-2 border-black border-t-transparent rounded-full"
                            />
                        ) : (
                            <>
                                <Send size={20} />
                                Analyze Text
                            </>
                        )}
                    </button>
                </div>

                <div className="bg-surface border border-white/5 rounded-xl p-6 h-[500px] overflow-y-auto">
                    <h3 className="font-bold text-white mb-4">Analysis Result</h3>

                    {!result && !loading && (
                        <div className="h-full flex flex-col items-center justify-center text-gray-500 opacity-50">
                            <Shield size={64} className="mb-4" />
                            <p>Ready to analyze</p>
                        </div>
                    )}

                    {loading && (
                        <div className="h-full flex flex-col items-center justify-center text-primary">
                            <motion.div
                                animate={{ scale: [1, 1.2, 1] }}
                                transition={{ repeat: Infinity, duration: 1.5 }}
                            >
                                <Brain size={64} className="mb-4" />
                            </motion.div>
                            <p className="animate-pulse">Analyzing content...</p>
                        </div>
                    )}

                    {result && (
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="space-y-6"
                        >
                            <div className={`p-4 rounded-lg border ${result.is_threat ? 'bg-red-500/10 border-red-500/20' : 'bg-green-500/10 border-green-500/20'}`}>
                                <div className="flex items-center gap-3 mb-2">
                                    {result.is_threat ? (
                                        <AlertTriangle className="text-red-500" size={24} />
                                    ) : (
                                        <CheckCircle className="text-green-500" size={24} />
                                    )}
                                    <h4 className={`text-lg font-bold ${result.is_threat ? 'text-red-500' : 'text-green-500'}`}>
                                        {result.is_threat ? 'Threat Detected' : 'Safe Content'}
                                    </h4>
                                </div>
                                <p className="text-gray-300 text-sm">
                                    {result.is_threat
                                        ? `This content appears to contain elements of ${result.threat_type || 'malicious intent'}.`
                                        : "No significant threats were detected in this content."}
                                </p>
                            </div>

                            {result.is_threat && (
                                <>
                                    <div>
                                        <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Threat Type</h4>
                                        <div className="bg-white/5 rounded-lg p-3 text-white font-mono">
                                            {result.threat_type}
                                        </div>
                                    </div>

                                    <div>
                                        <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Confidence Score</h4>
                                        <div className="bg-white/5 rounded-lg p-3">
                                            <div className="flex justify-between text-sm mb-1">
                                                <span className="text-white">AI Confidence</span>
                                                <span className="text-primary">{Math.round((result.confidence || 0) * 100)}%</span>
                                            </div>
                                            <div className="h-2 bg-black/50 rounded-full overflow-hidden">
                                                <motion.div
                                                    initial={{ width: 0 }}
                                                    animate={{ width: `${(result.confidence || 0) * 100}%` }}
                                                    className="h-full bg-primary"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    {result.flagged_keywords && result.flagged_keywords.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Flagged Keywords</h4>
                                            <div className="flex flex-wrap gap-2">
                                                {result.flagged_keywords.map((keyword, i) => (
                                                    <span key={i} className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded text-xs font-mono">
                                                        {keyword}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </>
                            )}
                        </motion.div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default NLPAnalyzer;
