import React, { useState, useRef, useEffect } from 'react';
import { Upload, Code, Play, AlertCircle, CheckCircle, ChevronDown, FileCode, Copy, ClipboardCheck, Search, ShieldCheck, Info, Package, FileSearch } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const LANGUAGES = [
    "Python", "JavaScript", "TypeScript", "HTML", "CSS", "Java", "C++", "C#", "Go", "Rust", "PHP", "Ruby", "Swift", "Kotlin", "SQL", "Shell", "Unknown"
];

// Maps step keywords to appropriate icons
const getStepIcon = (text) => {
    const lower = text.toLowerCase();
    if (lower.includes('import') || lower.includes('dependenc') || lower.includes('package') || lower.includes('registry'))
        return Package;
    if (lower.includes('vulnerabilit') || lower.includes('injection') || lower.includes('security') || lower.includes('safe'))
        return ShieldCheck;
    if (lower.includes('scan') || lower.includes('check') || lower.includes('analyz') || lower.includes('inspect'))
        return Search;
    if (lower.includes('file') || lower.includes('code') || lower.includes('function') || lower.includes('logic'))
        return FileSearch;
    return Info;
};

// Parses the AI's analysis_steps string into structured items
const parseSummarySteps = (summary) => {
    if (!summary || typeof summary !== 'string') return [];

    // Try to split on "Step N:", "N)", or "N." patterns
    const stepRegex = /(?:step\s*\d+[:.\-\)]|\d+[).]\s)/gi;
    const parts = summary.split(stepRegex).filter(s => s.trim());

    if (parts.length > 1) {
        return parts.map((text, i) => ({
            number: i + 1,
            text: text.trim().replace(/^\s*[-–]\s*/, ''),
        }));
    }

    // Fallback: split on sentence boundaries
    const sentences = summary.split(/(?<=[.!])\s+/).filter(s => s.trim().length > 10);
    if (sentences.length > 1) {
        return sentences.map((text, i) => ({
            number: i + 1,
            text: text.trim(),
        }));
    }

    // If nothing worked, return a single item
    return [{ number: 1, text: summary.trim() }];
};

const SiftScanner = () => {
    const [code, setCode] = useState('');
    const [language, setLanguage] = useState('Unknown');
    const [isDetecting, setIsDetecting] = useState(false);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [analysisResult, setAnalysisResult] = useState(null);
    const [error, setError] = useState(null);
    const [copiedIndex, setCopiedIndex] = useState(null);

    const fileInputRef = useRef(null);

    const copyToClipboard = (text, index) => {
        navigator.clipboard.writeText(text).then(() => {
            setCopiedIndex(index);
            setTimeout(() => setCopiedIndex(null), 2000);
        });
    };

    // Debounce logic for language detection
    useEffect(() => {
        const detectTimer = setTimeout(() => {
            if (code.trim().length > 10) {
                detectLanguage(code);
            }
        }, 1000); // Wait 1 second after typing stops

        return () => clearTimeout(detectTimer);
    }, [code]);

    const detectLanguage = async (content) => {
        setIsDetecting(true);
        try {
            if (window.pywebview && window.pywebview.api) {
                const detected = await window.pywebview.api.sift_detect_language(content);
                setLanguage(detected);
            } else {
                console.warn("API Bridge not available. Mocking detection.");
                // Mock fallback for UI development without backend
                if (content.includes("def ")) setLanguage("Python");
                else if (content.includes("function") || content.includes("const ")) setLanguage("JavaScript");
                else setLanguage("Unknown");
            }
        } catch (err) {
            console.error("Language detection failed:", err);
            // specific error handling if needed
        } finally {
            setIsDetecting(false);
        }
    };

    const handleFileUpload = (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            setCode(content);
            // Immediate detection for file upload
            detectLanguage(content);
        };
        reader.readAsText(file);
    };

    const handleAnalyze = async () => {
        if (!code.trim()) return;

        setIsAnalyzing(true);
        setError(null);
        setAnalysisResult(null);

        try {
            if (window.pywebview && window.pywebview.api) {
                const result = await window.pywebview.api.sift_analyze_code(code, language);
                if (result.error) {
                    setError(result.error);
                } else {
                    // Map backend keys (vulnerabilities, analysis_steps) to UI keys (issues, summary)
                    const mapped = {
                        score: result.score ?? 0,
                        summary: result.analysis_steps ?? 'No summary available.',
                        issues: (result.vulnerabilities ?? []).map(v => ({
                            type: v.name || v.type,
                            severity: v.type === 'Hallucination' ? 'CRITICAL' : 'WARNING',
                            line: v.line,
                            message: v.description,
                            suggested_fix: v.suggested_fix || null,
                        })),
                    };
                    setAnalysisResult(mapped);
                    console.log("Analysis Result (mapped):", mapped);
                }
            } else {
                console.warn("API Bridge not available. Mocking analysis.");
                setTimeout(() => {
                    setAnalysisResult({ score: 85, summary: "Mock analysis complete.", issues: [] });
                }, 1000);
            }
        } catch (err) {
            setError(err.message || "An unexpected error occurred during analysis.");
        } finally {
            setIsAnalyzing(false);
        }
    };

    const getScoreColor = (score) => {
        if (score >= 80) return 'text-green-500 border-green-500/50 bg-green-500/10';
        if (score >= 50) return 'text-yellow-500 border-yellow-500/50 bg-yellow-500/10';
        return 'text-red-500 border-red-500/50 bg-red-500/10';
    };

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            {/* Header Card */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-surface border border-white/10 rounded-xl p-6"
            >
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                        <div className="p-3 bg-primary/20 rounded-lg">
                            <Code className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white">Sift Code Auditor</h2>
                            <p className="text-gray-400 text-sm">AI-powered security analysis for your source code</p>
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        {/* Language Badge & Selector */}
                        <div className="relative group">
                            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors duration-300 ${language === 'Unknown' ? 'bg-white/5 border-white/10' : 'bg-blue-500/10 border-blue-500/20 text-blue-400'
                                }`}>
                                {isDetecting ? (
                                    <span className="text-xs animate-pulse">Detecting...</span>
                                ) : (
                                    <>
                                        <FileCode className="w-4 h-4" />
                                        <span className="text-sm font-medium">{language || "Unknown"}</span>
                                        <ChevronDown className="w-3 h-3 opacity-50 ml-1" />
                                    </>
                                )}
                            </div>

                            {/* Dropdown */}
                            <select
                                className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                                value={language}
                                onChange={(e) => setLanguage(e.target.value)}
                                disabled={isDetecting}
                            >
                                {LANGUAGES.map(lang => (
                                    <option key={lang} value={lang}>{lang}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                {/* Input Area */}
                <div className="space-y-4">
                    <div className="relative group">
                        <textarea
                            value={code}
                            onChange={(e) => setCode(e.target.value)}
                            placeholder="Paste your code here to begin analysis..."
                            className="w-full h-80 bg-black/40 border border-white/10 rounded-lg p-4 font-mono text-sm text-gray-300 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 resize-none transition-all custom-scrollbar"
                        />

                        {/* File Upload Overlay/Button */}
                        <div className="absolute bottom-4 right-4 flex items-center gap-2">
                            <button
                                onClick={() => fileInputRef.current?.click()}
                                className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-gray-400 transition-colors backdrop-blur-sm"
                            >
                                <Upload className="w-3 h-3" />
                                Load File
                            </button>
                            <input
                                type="file"
                                ref={fileInputRef}
                                className="hidden"
                                onChange={handleFileUpload}
                                accept=".py,.js,.ts,.tsx,.jsx,.html,.css,.java,.c,.cpp,.cs,.go,.rs,.php,.rb,.swift,.kt,.sql,.sh"
                            />
                        </div>
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="text-xs text-gray-500 font-mono">
                            {code.length} chars
                        </div>
                        <button
                            onClick={handleAnalyze}
                            disabled={!code.trim() || isAnalyzing}
                            className={`flex items-center gap-2 px-6 py-2 rounded-lg font-bold transition-all transform active:scale-95 ${!code.trim() || isAnalyzing
                                ? 'bg-white/5 text-gray-500 cursor-not-allowed'
                                : 'bg-primary text-background hover:bg-primary-hover shadow-lg shadow-primary/20'
                                }`}
                        >
                            {isAnalyzing ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-background/30 border-t-background rounded-full animate-spin" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <Play className="w-4 h-4 fill-current" />
                                    Analyze Code
                                </>
                            )}
                        </button>
                    </div>

                    {error && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-3 overflow-hidden"
                        >
                            <AlertCircle className="w-5 h-5 flex-shrink-0" />
                            <span>{error}</span>
                        </motion.div>
                    )}
                </div>
            </motion.div>

            {/* Analysis Results */}
            {analysisResult && (
                <motion.div
                    initial={{ opacity: 0, y: 40 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, type: "spring" }}
                    className="grid grid-cols-1 md:grid-cols-3 gap-6"
                >
                    {/* Score Card */}
                    <div className="md:col-span-1 space-y-6">
                        <div className="bg-surface border border-white/10 rounded-xl p-6 flex flex-col items-center justify-center text-center h-full relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/30 to-transparent" />

                            <h3 className="text-lg font-semibold text-white mb-6">Security Score</h3>

                            <div className={`relative w-40 h-40 rounded-full flex items-center justify-center border-4 ${getScoreColor(analysisResult.score).split(' ')[1]} mb-6`}>
                                <div className={`absolute inset-0 rounded-full opacity-20 ${getScoreColor(analysisResult.score).split(' ')[2]}`} />
                                <span className={`text-5xl font-bold ${getScoreColor(analysisResult.score).split(' ')[0]}`}>
                                    {analysisResult.score}
                                </span>
                            </div>

                            {/* Score label */}
                            <p className={`text-sm font-medium mt-2 ${analysisResult.score >= 80 ? 'text-green-400' :
                                    analysisResult.score >= 50 ? 'text-yellow-400' : 'text-red-400'
                                }`}>
                                {analysisResult.score >= 80 ? 'Secure' :
                                    analysisResult.score >= 50 ? 'Needs Attention' : 'Critical Risk'}
                            </p>
                        </div>
                    </div>

                    {/* Issues List */}
                    <div className="md:col-span-2 space-y-4">
                        <div className="flex items-center justify-between mb-2 px-2">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <AlertCircle className="w-5 h-5 text-primary" />
                                Vulnerabilities Found
                                <span className="bg-white/10 text-xs px-2 py-1 rounded-full text-gray-300">
                                    {analysisResult.issues.length}
                                </span>
                            </h3>
                        </div>

                        {analysisResult.issues.length === 0 ? (
                            <div className="bg-surface border border-white/10 rounded-xl p-12 text-center text-gray-500">
                                <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4 opacity-50" />
                                <h4 className="text-xl font-medium text-white mb-2">Clean Code!</h4>
                                <p>No evident security issues found in this snippet.</p>
                            </div>
                        ) : (
                            analysisResult.issues.map((issue, index) => (
                                <motion.div
                                    key={index}
                                    initial={{ opacity: 0, x: 20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.1 }}
                                    className="bg-surface border border-white/10 rounded-xl overflow-hidden hover:border-white/20 transition-colors"
                                >
                                    <div className="p-4 border-b border-white/5 flex items-start gap-4">
                                        <div className={`p-2 rounded-lg mt-1 flex-shrink-0 ${issue.severity === 'CRITICAL'
                                            ? 'bg-red-500/20 text-red-500'
                                            : 'bg-yellow-500/20 text-yellow-500'
                                            }`}>
                                            <AlertCircle className="w-5 h-5" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center justify-between mb-1">
                                                <h4 className={`font-bold truncate ${issue.severity === 'CRITICAL' ? 'text-red-400' : 'text-yellow-400'
                                                    }`}>
                                                    {issue.type}
                                                </h4>
                                                <span className="text-xs text-gray-500 font-mono bg-black/30 px-2 py-1 rounded">
                                                    Line {issue.line}
                                                </span>
                                            </div>
                                            <p className="text-gray-300 text-sm">{issue.message}</p>
                                        </div>
                                    </div>

                                    {issue.suggested_fix && (
                                        <div className="bg-black/30 p-4 font-mono text-sm border-t border-white/5">
                                            <div className="flex items-center justify-between mb-2">
                                                <div className="flex items-center gap-2 text-xs text-green-400 uppercase tracking-wide font-bold">
                                                    <CheckCircle className="w-3 h-3" />
                                                    Suggested Fix
                                                </div>
                                                <button
                                                    onClick={() => copyToClipboard(issue.suggested_fix, index)}
                                                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-all duration-200 ${copiedIndex === index
                                                        ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                                                        : 'bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10 hover:text-white'
                                                        }`}
                                                >
                                                    {copiedIndex === index ? (
                                                        <><ClipboardCheck className="w-3.5 h-3.5" /> Copied!</>
                                                    ) : (
                                                        <><Copy className="w-3.5 h-3.5" /> Copy</>
                                                    )}
                                                </button>
                                            </div>
                                            <div className="bg-black/50 rounded-lg p-3 border border-white/5 overflow-x-auto">
                                                <pre className="text-gray-300">
                                                    <code>{issue.suggested_fix}</code>
                                                </pre>
                                            </div>
                                        </div>
                                    )}
                                </motion.div>
                            ))
                        )}
                    </div>
                </motion.div>
            )}

            {/* Audit Summary Section — Full Width Below */}
            {analysisResult && analysisResult.summary && (
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.2 }}
                    className="bg-surface border border-white/10 rounded-xl overflow-hidden"
                >
                    {/* Header */}
                    <div className="px-6 py-4 border-b border-white/5 flex items-center gap-3">
                        <div className="p-2 bg-primary/10 rounded-lg">
                            <FileSearch className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                            <h3 className="text-base font-bold text-white">Audit Summary</h3>
                            <p className="text-xs text-gray-500">Step-by-step analysis breakdown</p>
                        </div>
                        <span className="ml-auto bg-white/5 text-xs px-2.5 py-1 rounded-full text-gray-400 border border-white/5">
                            {parseSummarySteps(analysisResult.summary).length} steps
                        </span>
                    </div>

                    {/* Steps */}
                    <div className="p-4 space-y-2">
                        {parseSummarySteps(analysisResult.summary).map((step, index) => {
                            const IconComponent = getStepIcon(step.text);
                            return (
                                <motion.div
                                    key={index}
                                    initial={{ opacity: 0, x: -15 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: 0.3 + index * 0.08 }}
                                    className="group flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] hover:bg-white/[0.06] border border-transparent hover:border-white/10 transition-all duration-200 cursor-default"
                                >
                                    {/* Step number badge */}
                                    <div className="flex-shrink-0 w-7 h-7 rounded-full bg-primary/15 border border-primary/20 flex items-center justify-center text-xs font-bold text-primary group-hover:bg-primary/25 transition-colors">
                                        {step.number}
                                    </div>

                                    {/* Icon */}
                                    <div className="flex-shrink-0 mt-0.5">
                                        <IconComponent className="w-4 h-4 text-gray-500 group-hover:text-gray-300 transition-colors" />
                                    </div>

                                    {/* Step text */}
                                    <p className="text-sm text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">
                                        {step.text}
                                    </p>
                                </motion.div>
                            );
                        })}
                    </div>
                </motion.div>
            )}
        </div>
    );
};

export default SiftScanner;
