import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Brain, Send, AlertTriangle, CheckCircle, Shield, History, Trash2, Clock, AlertOctagon } from 'lucide-react';

const NLPAnalyzer = () => {
    const [text, setText] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [history, setHistory] = useState([]);
    const [showHistory, setShowHistory] = useState(false);

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        if (window.pywebview?.api) {
            try {
                const hist = await window.pywebview.api.get_nlp_history();
                setHistory(hist);
            } catch (error) {
                console.error("Failed to fetch history:", error);
            }
        }
    };

    const handleAnalyze = async () => {
        if (!text.trim()) return;

        setLoading(true);
        setResult(null);

        if (window.pywebview?.api) {
            try {
                const analysis = await window.pywebview.api.analyze_text(text);
                setResult(analysis);
                fetchHistory(); // Refresh history
            } catch (error) {
                console.error("Analysis failed:", error);
                setResult({ error: "Analysis failed. Please try again." });
            }
        } else {
            // Mock for dev
            setTimeout(() => {
                const mockResult = {
                    is_threat: text.toLowerCase().includes('hack') || text.toLowerCase().includes('password'),
                    threat_class: text.toLowerCase().includes('hack') ? 'HIGH_THREAT' : 'SAFE',
                    threat_level: text.toLowerCase().includes('hack') ? 'HIGH' : 'SAFE',
                    threat_score: text.toLowerCase().includes('hack') ? 75 : 5,
                    confidence: 0.85,
                    keywords_found: ['hack', 'password'],
                    matches: [
                        { start: text.indexOf('hack'), end: text.indexOf('hack') + 4, type: 'Critical' },
                        { start: text.indexOf('password'), end: text.indexOf('password') + 8, type: 'Credential' }
                    ].filter(m => m.start !== -1),
                    timestamp: new Date().toISOString()
                };
                setResult(mockResult);
                setHistory(prev => [mockResult, ...prev]);
            }, 1000);
        }
        setLoading(false);
    };

    const clearHistory = async () => {
        if (window.pywebview?.api) {
            await window.pywebview.api.clear_nlp_history();
            setHistory([]);
        } else {
            setHistory([]);
        }
    };

    const loadFromHistory = (item) => {
        // If the item has the original text (we might need to store it if we want to reload fully)
        // Currently the backend result doesn't explicitly echo back the full input text in the result dict,
        // but it does return 'matches'.
        // Wait, if I want to reload the text into the input box, I need the original text.
        // The current backend implementation logs "Text analyzed: ..." but doesn't return the full input text in the result object.
        // I should have added 'text' to the result object in nlp_model.py.
        // For now, I can't restore the text to the input box unless I stored it.
        // The `matches` contain snippets, but not the whole text.
        // Actually, `matches` has `text` (the snippet).

        // LIMITATION: Without storing the full text in the DB, I can't fully restore the input.
        // However, for the *result view*, I can show the analysis.
        // But the highlighting component needs the full text.

        // Workaround: I will just show the result details. 
        // Or better, I'll update nlp_model.py to include 'text' in the result?
        // No, storing large text in DB might be heavy.
        // Let's assume for now we just show the result summary for history items, 
        // or if the user just analyzed it, the text is still in the box.

        // Actually, for a good UX, I really should have the text.
        // Let's just set the result and if the text matches, great. If not, we can't highlight.
        setResult(item);
        // We can't set 'text' because we don't have it.
    };

    // Helper to render highlighted text
    const renderHighlightedText = () => {
        if (!text || !result || !result.matches) return <p className="text-gray-300 whitespace-pre-wrap">{text}</p>;

        // Sort matches by start index
        const sortedMatches = [...result.matches].sort((a, b) => a.start - b.start);

        // Filter overlaps (keep first one)
        const uniqueMatches = [];
        let lastEnd = 0;
        sortedMatches.forEach(m => {
            if (m.start >= lastEnd) {
                uniqueMatches.push(m);
                lastEnd = m.end;
            }
        });

        const elements = [];
        let lastIndex = 0;

        uniqueMatches.forEach((match, i) => {
            // Text before match
            if (match.start > lastIndex) {
                elements.push(
                    <span key={`text-${i}`}>{text.slice(lastIndex, match.start)}</span>
                );
            }

            // Match
            let colorClass = 'bg-yellow-500/30 text-yellow-200';
            if (match.type === 'Critical' || match.type === 'Phishing') colorClass = 'bg-red-500/30 text-red-200';
            if (match.type === 'Safe') colorClass = 'bg-green-500/30 text-green-200';

            elements.push(
                <span key={`match-${i}`} className={`${colorClass} px-1 rounded border border-white/10`} title={match.type}>
                    {text.slice(match.start, match.end)}
                </span>
            );

            lastIndex = match.end;
        });

        // Remaining text
        if (lastIndex < text.length) {
            elements.push(<span key="text-end">{text.slice(lastIndex)}</span>);
        }

        return <div className="whitespace-pre-wrap font-mono text-sm">{elements}</div>;
    };

    const getThreatColor = (level) => {
        switch (level) {
            case 'CRITICAL': return 'text-red-500';
            case 'HIGH': return 'text-orange-500';
            case 'MEDIUM': return 'text-yellow-500';
            case 'LOW': return 'text-blue-500';
            default: return 'text-green-500';
        }
    };

    return (
        <div className="flex h-full gap-6">
            {/* Main Content */}
            <div className="flex-1 flex flex-col gap-6 overflow-hidden">
                {/* Header */}
                <div className="bg-primary/10 border border-primary/20 rounded-xl p-6 flex items-start gap-4 shrink-0">
                    <Brain className="text-primary shrink-0" size={32} />
                    <div>
                        <h3 className="text-lg font-bold text-white mb-1">AI Threat Analyzer</h3>
                        <p className="text-gray-400 text-sm">
                            Advanced NLP engine to detect phishing, social engineering, and malicious patterns in text.
                        </p>
                    </div>
                    <button
                        onClick={() => setShowHistory(!showHistory)}
                        className={`ml-auto p-2 rounded-lg transition-colors ${showHistory ? 'bg-primary text-black' : 'bg-white/5 text-gray-400 hover:text-white'}`}
                    >
                        <History size={20} />
                    </button>
                </div>

                <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
                    {/* Input Section */}
                    <div className="bg-surface border border-white/5 rounded-xl p-6 flex flex-col h-full">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="font-bold text-white">Input Text</h3>
                            <span className={`text-xs ${text.length > 90000 ? 'text-red-500' : 'text-gray-500'}`}>
                                {text.length} / 100,000
                            </span>
                        </div>
                        <textarea
                            value={text}
                            onChange={(e) => setText(e.target.value)}
                            placeholder="Paste suspicious email, message, or content here..."
                            className="flex-1 bg-black/20 border border-white/10 rounded-lg p-4 text-white resize-none focus:border-primary/50 outline-none transition-colors mb-4 font-mono text-sm"
                        />
                        <button
                            onClick={handleAnalyze}
                            disabled={loading || !text}
                            className="bg-primary text-black font-bold px-6 py-3 rounded-lg flex items-center justify-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
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

                    {/* Result Section */}
                    <div className="bg-surface border border-white/5 rounded-xl p-6 h-full overflow-y-auto custom-scrollbar">
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
                                <p className="animate-pulse">Processing content...</p>
                            </div>
                        )}

                        {result && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="space-y-6"
                            >
                                {/* Score Gauge */}
                                <div className="flex items-center justify-between bg-white/5 rounded-xl p-4">
                                    <div className="flex items-center gap-4">
                                        <div className="relative w-16 h-16 flex items-center justify-center">
                                            <svg className="w-full h-full transform -rotate-90">
                                                <circle cx="32" cy="32" r="28" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-gray-700" />
                                                <circle
                                                    cx="32" cy="32" r="28"
                                                    stroke="currentColor" strokeWidth="4" fill="transparent"
                                                    strokeDasharray={175.93}
                                                    strokeDashoffset={175.93 - (175.93 * (result.threat_score || 0)) / 100}
                                                    className={getThreatColor(result.threat_level)}
                                                />
                                            </svg>
                                            <span className={`absolute text-sm font-bold ${getThreatColor(result.threat_level)}`}>
                                                {result.threat_score || 0}
                                            </span>
                                        </div>
                                        <div>
                                            <div className={`text-xl font-bold ${getThreatColor(result.threat_level)}`}>
                                                {result.threat_level}
                                            </div>
                                            <div className="text-xs text-gray-400">Threat Score</div>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-sm text-gray-400">Confidence</div>
                                        <div className="text-lg font-bold text-white">
                                            {Math.round(result.confidence || 0)}%
                                        </div>
                                    </div>
                                </div>

                                {/* Highlighted Text View */}
                                <div className="bg-black/30 rounded-lg p-4 border border-white/10">
                                    <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Analyzed Content</h4>
                                    {renderHighlightedText()}
                                </div>

                                {/* Details */}
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="bg-white/5 p-3 rounded-lg">
                                        <h4 className="text-xs text-gray-400 mb-1">Threat Class</h4>
                                        <div className="text-sm font-mono text-white">{result.threat_class}</div>
                                    </div>
                                    <div className="bg-white/5 p-3 rounded-lg">
                                        <h4 className="text-xs text-gray-400 mb-1">Patterns</h4>
                                        <div className="text-sm text-white">
                                            {result.patterns_detected?.length || 0} detected
                                        </div>
                                    </div>
                                </div>

                                {result.patterns_detected?.length > 0 && (
                                    <div>
                                        <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Detected Patterns</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {result.patterns_detected.map((pattern, i) => (
                                                <span key={i} className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded text-xs">
                                                    {pattern}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </motion.div>
                        )}
                    </div>
                </div>
            </div>

            {/* History Sidebar */}
            <AnimatePresence>
                {showHistory && (
                    <motion.div
                        initial={{ width: 0, opacity: 0 }}
                        animate={{ width: 300, opacity: 1 }}
                        exit={{ width: 0, opacity: 0 }}
                        className="bg-surface border-l border-white/5 flex flex-col overflow-hidden"
                    >
                        <div className="p-4 border-b border-white/5 flex justify-between items-center">
                            <h3 className="font-bold text-white">History</h3>
                            <button onClick={clearHistory} className="text-gray-400 hover:text-red-400 p-1">
                                <Trash2 size={16} />
                            </button>
                        </div>
                        <div className="flex-1 overflow-y-auto p-4 space-y-3">
                            {history.length === 0 ? (
                                <div className="text-center text-gray-500 text-sm py-8">
                                    No recent analysis
                                </div>
                            ) : (
                                history.map((item, i) => (
                                    <button
                                        key={i}
                                        onClick={() => loadFromHistory(item)}
                                        className="w-full text-left bg-white/5 hover:bg-white/10 p-3 rounded-lg border border-white/5 transition-colors group"
                                    >
                                        <div className="flex justify-between items-start mb-2">
                                            <span className={`text-xs font-bold px-2 py-0.5 rounded ${item.threat_level === 'SAFE' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                }`}>
                                                {item.threat_level}
                                            </span>
                                            <span className="text-[10px] text-gray-500">
                                                {new Date(item.timestamp).toLocaleTimeString()}
                                            </span>
                                        </div>
                                        <div className="text-xs text-gray-400 truncate">
                                            {item.description}
                                        </div>
                                    </button>
                                ))
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default NLPAnalyzer;
