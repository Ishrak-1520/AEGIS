import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileSearch, Play, FolderOpen, AlertCircle, CheckCircle, X } from 'lucide-react';

const Scanner = () => {
    const [scanning, setScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [currentFile, setCurrentFile] = useState('');
    const [results, setResults] = useState([]);
    const [scanStats, setScanStats] = useState(null);

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
    };

    const handleDrop = async (e) => {
        e.preventDefault();
        e.stopPropagation();

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
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-primary/50 transition-colors group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
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
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-purple-500/50 transition-colors group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                    <div className="bg-purple-500/10 w-12 h-12 rounded-lg flex items-center justify-center mb-4 group-hover:bg-purple-500/20 transition-colors">
                        <FileSearch className="text-purple-500" size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">Full Scan</h3>
                    <p className="text-sm text-gray-400">Deep scan of the entire system. This may take a while.</p>
                </motion.button>

                <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={handleCustomScan}
                    disabled={scanning}
                    className={`bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-green-500/50 transition-colors group ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
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
                className="border-2 border-dashed border-white/10 rounded-xl p-12 flex flex-col items-center justify-center text-center hover:border-primary/30 hover:bg-white/5 transition-all cursor-pointer"
                onClick={handleFileSelect}
                onDragOver={handleDragOver}
                onDrop={handleDrop}
            >
                <Upload className="text-gray-500 mb-4" size={48} />
                <h3 className="text-xl font-bold text-white mb-2">Drag & Drop Files Here</h3>
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
                            <div className="flex items-center gap-3">
                                <div className="animate-spin text-primary">
                                    <Play size={20} />
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
                        <div className="h-2 bg-background rounded-full overflow-hidden">
                            <motion.div
                                className="h-full bg-primary"
                                initial={{ width: 0 }}
                                animate={{ width: `${progress}%` }}
                            />
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Scan Analytics */}
            {!scanning && scanStats && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-surface border border-white/5 rounded-xl p-6"
                >
                    <h3 className="font-bold text-white mb-4">Scan Summary</h3>
                    <div className="grid grid-cols-3 gap-4">
                        <div className="bg-white/5 rounded-lg p-4 text-center">
                            <p className="text-gray-400 text-sm mb-1">Status</p>
                            <p className="text-xl font-bold text-white capitalize">{scanStats.status}</p>
                        </div>
                        <div className="bg-white/5 rounded-lg p-4 text-center">
                            <p className="text-gray-400 text-sm mb-1">Threats Found</p>
                            <p className={`text-xl font-bold ${scanStats.threatsFound > 0 ? 'text-red-500' : 'text-green-500'}`}>
                                {scanStats.threatsFound}
                            </p>
                        </div>
                        <div className="bg-white/5 rounded-lg p-4 text-center">
                            <p className="text-gray-400 text-sm mb-1">Files Scanned</p>
                            <p className="text-xl font-bold text-white">Check Logs</p>
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
