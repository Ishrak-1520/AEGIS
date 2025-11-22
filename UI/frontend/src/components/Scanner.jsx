import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileSearch, Play, FolderOpen, AlertCircle, CheckCircle, X } from 'lucide-react';

const Scanner = () => {
    const [scanning, setScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [currentFile, setCurrentFile] = useState('');
    const [results, setResults] = useState([]);

    const startScan = (type) => {
        setScanning(true);
        setProgress(0);
        setResults([]);

        // Simulation
        let p = 0;
        const interval = setInterval(() => {
            p += 1;
            setProgress(p);
            setCurrentFile(`file_${Math.floor(Math.random() * 1000)}.exe`);

            if (p % 20 === 0) {
                setResults(prev => [...prev, {
                    file: `suspicious_file_${p}.dll`,
                    status: Math.random() > 0.7 ? 'threat' : 'clean',
                    path: `C:/Windows/System32/suspicious_file_${p}.dll`
                }]);
            }

            if (p >= 100) {
                clearInterval(interval);
                setScanning(false);
                setCurrentFile('Scan Complete');
            }
        }, 50);
    };

    return (
        <div className="space-y-6">
            {/* Scan Options */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => startScan('quick')}
                    className="bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-primary/50 transition-colors group"
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
                    className="bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-purple-500/50 transition-colors group"
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
                    className="bg-surface border border-white/5 rounded-xl p-6 text-left hover:border-green-500/50 transition-colors group"
                >
                    <div className="bg-green-500/10 w-12 h-12 rounded-lg flex items-center justify-center mb-4 group-hover:bg-green-500/20 transition-colors">
                        <FolderOpen className="text-green-500" size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">Custom Scan</h3>
                    <p className="text-sm text-gray-400">Select specific files or folders to scan for threats.</p>
                </motion.button>
            </div>

            {/* Drag & Drop Zone */}
            <div className="border-2 border-dashed border-white/10 rounded-xl p-12 flex flex-col items-center justify-center text-center hover:border-primary/30 hover:bg-white/5 transition-all cursor-pointer">
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
                            <span className="text-2xl font-bold text-primary">{progress}%</span>
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
                                    ) : (
                                        <CheckCircle className="text-green-500" size={20} />
                                    )}
                                    <div>
                                        <p className="text-white font-medium">{result.file}</p>
                                        <p className="text-xs text-gray-500">{result.path}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    {result.status === 'threat' && (
                                        <button className="px-3 py-1 bg-red-500/10 text-red-500 text-sm font-bold rounded hover:bg-red-500/20 transition-colors">
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
