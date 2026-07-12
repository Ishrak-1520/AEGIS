import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileSearch, Play, FolderOpen, AlertCircle, CheckCircle, X } from 'lucide-react';

const Scanner = () => {
    const [scanning, setScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [currentFile, setCurrentFile] = useState('');
    const [results, setResults] = useState([]);
    const [scanStats, setScanStats] = useState(null);
    const [isDragging, setIsDragging] = useState(false);

    const stopScan = async () => {
        try {
            await window.pywebview.api.stop_scan();
            setScanning(false);
            setCurrentFile('Scan Stopped');
        } catch (err) {
            console.error("Error stopping scan:", err);
        }
    };

    const handleCustomScan = async () => {
        try {
            const path = await window.pywebview.api.browse_directory();
            if (path) {
                startScan('custom', path);
            }
        } catch (err) {
            console.error("Error selecting directory:", err);
        }
    };

    const startScan = async (type, path = null) => {
        if (scanning) return;

        try {
            // Call backend to start scan
            const response = await window.pywebview.api.start_scan(type, path);
            if (response.status === 'started') {
                setScanning(true);
                setProgress(0);
                setResults([]);
                setScanStats(null);

                // Poll for progress
                const interval = setInterval(async () => {
                    try {
                        const status = await window.pywebview.api.get_scan_progress();

                        setProgress(status.progress);
                        setCurrentFile(status.file);

                        if (status.results) {
                            setResults(status.results);
                        }

                        if (status.status === 'completed' || status.status === 'error' || status.status === 'stopped') {
                            clearInterval(interval);
                            setScanning(false);
                            setCurrentFile(status.status === 'completed' ? 'Scan Complete' : `Scan ${status.status}`);

                            // Set stats for analytics display
                            if (status.status === 'completed') {
                                setScanStats({
                                    filesScanned: status.progress * 10, // Placeholder
                                    threatsFound: status.results.length,
                                    status: status.status
                                });
                            }
                        }
                    } catch (err) {
                        console.error("Error polling progress:", err);
                        clearInterval(interval);
                        setScanning(false);
                    }
                }, 500); // Poll every 500ms
            } else {
                console.error("Failed to start scan:", response.message);
            }
        } catch (err) {
            console.error("Error calling start_scan:", err);
        }
    };

    const handleFileSelect = async () => {
        try {
            const path = await window.pywebview.api.browse_file();
            if (path) {
                startScan('custom', path);
            }
        } catch (err) {
            console.error("Error selecting file:", err);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
    };

    const handleDrop = async (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);

        // Note: Getting full path from drag & drop in webview is restricted.
        // We encourage using the click-to-browse for now.
        // However, if pywebview supports it in future or via specific config, this would work.
        // For now, we'll just show a message or try to handle if possible.
        console.log("Files dropped:", e.dataTransfer.files);

        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            // In standard webview, we can't get the full path.
            // We will trigger the file picker as a fallback for now to ensure user can select the file they wanted.
            handleFileSelect();
        }
    };

    return (
        <div className="space-y-6">
            {/* Scan Options */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => startScan('quick')}
                    disabled={scanning}
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-primary/50 hover:shadow-[0_0_20px_rgba(59,130,246,0.15)] transition-all duration-300 group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                    <div className="bg-primary/10 w-12 h-12 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                        <ZapIcon className="text-primary" size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">Quick Scan</h3>
                    <p className="text-sm text-gray-400">Scans critical system areas and common malware locations.</p>
                </motion.button>

                <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => startScan('full')}
                    disabled={scanning}
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-violet-500/50 hover:shadow-[0_0_20px_rgba(139,92,246,0.15)] transition-all duration-300 group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                    <div className="bg-violet-500/10 w-12 h-12 rounded-lg flex items-center justify-center mb-4 group-hover:bg-violet-500/20 transition-colors">
                        <FileSearch className="text-violet-500" size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">Full Scan</h3>
                    <p className="text-sm text-gray-400">Deep scan of the entire system. This may take a while.</p>
                </motion.button>

                <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={handleCustomScan}
                    disabled={scanning}
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-green-500/50 hover:shadow-[0_0_20px_rgba(34,197,94,0.15)] transition-all duration-300 group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                    <div className="bg-green-500/10 w-12 h-12 rounded-lg flex items-center justify-center mb-4 group-hover:bg-green-500/20 transition-colors">
                        <FolderOpen className="text-green-500" size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">Custom Scan</h3>
                    <p className="text-sm text-gray-400">Select specific files or folders to scan for threats.</p>
                </motion.button>
            </div>

            {/* Drag & Drop Zone */}
            <div
                className={`border-2 border-dashed rounded-xl p-16 flex flex-col items-center justify-center text-center transition-all duration-300 cursor-pointer ${
                    isDragging 
                        ? 'border-primary bg-primary/5 shadow-[0_0_30px_rgba(59,130,246,0.1)] scale-[1.02]' 
                        : 'border-white/10 hover:border-primary/50 hover:bg-white/5 hover:shadow-[0_0_20px_rgba(59,130,246,0.05)]'
                }`}
                onClick={handleFileSelect}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
            >
                <div className={`p-4 rounded-full mb-4 transition-all duration-300 ${isDragging ? 'bg-primary/20 scale-110' : 'bg-white/5'}`}>
                    <Upload className={isDragging ? 'text-primary animate-bounce' : 'text-gray-400'} size={48} />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">
                    {isDragging ? 'Drop Files Here' : 'Drag & Drop Files Here'}
                </h3>
                <p className="text-gray-400">or click to browse your computer</p>
            </div>

            {/* Scan Progress */}
            <AnimatePresence>
                {scanning && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-surface border border-white/5 rounded-xl p-6"
                    >
                        <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-4">
                                <div className="relative">
                                    <div className="absolute inset-0 bg-primary/20 blur-md rounded-full animate-pulse"></div>
                                    <div className="animate-spin text-primary relative z-10">
                                        <Play size={24} />
                                    </div>
                                </div>
                                <div>
                                    <h4 className="font-bold text-white">Scanning...</h4>
                                    <p className="text-sm text-gray-400">{currentFile}</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <span className="text-2xl font-bold text-primary">{progress}%</span>
                                <button
                                    onClick={stopScan}
                                    className="px-4 py-2 bg-red-500/10 text-red-500 rounded-lg hover:bg-red-500/20 transition-colors font-medium"
                                >
                                    Stop Scan
                                </button>
                            </div>
                        </div>
                        <div className="h-3 bg-dark/50 border border-white/5 rounded-full overflow-hidden relative">
                            <motion.div
                                className="h-full bg-gradient-to-r from-primary to-blue-400 relative"
                                initial={{ width: 0 }}
                                animate={{ width: `${progress}%` }}
                            >
                                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent -translate-x-full animate-[shimmer_2s_infinite]"></div>
                            </motion.div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Scan Analytics */}
            {!scanning && scanStats && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-surface border border-white/5 rounded-xl p-6 relative overflow-hidden"
                >
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/50 to-transparent"></div>
                    <h3 className="font-bold text-lg text-white mb-6">Scan Summary</h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="bg-white/5 border border-white/10 rounded-xl p-6 text-center hover:bg-white/10 transition-colors">
                            <p className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Status</p>
                            <p className="text-2xl font-bold text-white capitalize">{scanStats.status}</p>
                        </div>
                        <div className={`border rounded-xl p-6 text-center transition-colors ${
                            scanStats.threatsFound > 0 
                                ? 'bg-red-500/10 border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.1)] hover:bg-red-500/20' 
                                : 'bg-green-500/10 border-green-500/30 shadow-[0_0_20px_rgba(34,197,94,0.1)] hover:bg-green-500/20'
                        }`}>
                            <p className={`text-sm font-medium uppercase tracking-wider mb-2 ${scanStats.threatsFound > 0 ? 'text-red-400' : 'text-green-400'}`}>Threats Found</p>
                            <p className={`text-4xl font-black ${scanStats.threatsFound > 0 ? 'text-red-500 drop-shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 'text-green-500 drop-shadow-[0_0_10px_rgba(34,197,94,0.5)]'}`}>
                                {scanStats.threatsFound}
                            </p>
                        </div>
                        <div className="bg-white/5 border border-white/10 rounded-xl p-6 text-center hover:bg-white/10 transition-colors">
                            <p className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Files Scanned</p>
                            <p className="text-2xl font-bold text-white">Check Logs</p>
                        </div>
                    </div>
                </motion.div>
            )}

            {/* Results */}
            {results.length > 0 && (
                <div className="bg-surface border border-white/5 rounded-xl overflow-hidden">
                    <div className="p-4 border-b border-white/5 flex items-center justify-between">
                        <h3 className="font-bold text-white">Scan Results</h3>
                        <span className="text-sm text-gray-400">{results.length} items found</span>
                    </div>
                    <div className="divide-y divide-white/5">
                        {results.map((result, index) => (
                            <div key={index} className="p-4 flex items-center justify-between hover:bg-white/5 transition-colors">
                                <div className="flex items-center gap-3">
                                    {result.status === 'threat' ? (
                                        <AlertCircle className="text-red-500" size={20} />
                                    ) : result.status === 'suspicious' ? (
                                        <AlertCircle className="text-yellow-500" size={20} />
                                    ) : (
                                        <CheckCircle className="text-green-500" size={20} />
                                    )}
                                    <div>
                                        <p className="text-white font-medium">{result.file}</p>
                                        <p className="text-xs text-gray-500">{result.path}</p>
                                        {result.threat && (
                                            <p className="text-xs text-gray-400">
                                                {result.threat.name || result.threat}
                                                {result.threat.description ? ` - ${result.threat.description}` : ''}
                                            </p>
                                        )}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    {(result.status === 'threat' || result.status === 'suspicious') && (
                                        <button className={`px-3 py-1 ${result.status === 'threat' ? 'bg-red-500/10 text-red-500 hover:bg-red-500/20' : 'bg-yellow-500/10 text-yellow-500 hover:bg-yellow-500/20'} text-sm font-bold rounded transition-colors`}>
                                            Quarantine
                                        </button>
                                    )}
                                    <button className="p-2 text-gray-400 hover:text-white">
                                        <X size={16} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

const ZapIcon = ({ className, size }) => (
    <svg
        xmlns="http://www.w3.org/2000/svg"
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
    >
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
    </svg>
);

export default Scanner;
