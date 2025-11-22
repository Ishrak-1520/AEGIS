import React, { useState, useEffect } from 'react';
import { FileText, Clock, AlertCircle, Info, CheckCircle, RefreshCw } from 'lucide-react';

const Reports = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetchLogs();
    }, []);

    const fetchLogs = async () => {
        setLoading(true);
        if (window.pywebview?.api) {
            try {
                const data = await window.pywebview.api.get_recent_logs(50);
                setLogs(data);
            } catch (error) {
                console.error("Failed to fetch logs:", error);
            }
        } else {
            // Mock data
            setTimeout(() => {
                setLogs([
                    { id: 1, timestamp: '2023-10-26 10:30:00', level: 'INFO', event: 'System scan started', details: 'Quick scan initiated by user' },
                    { id: 2, timestamp: '2023-10-26 10:35:12', level: 'WARNING', event: 'Threat detected', details: 'EICAR test file found in Downloads' },
                    { id: 3, timestamp: '2023-10-26 10:35:15', level: 'INFO', event: 'Threat quarantined', details: 'File moved to quarantine successfully' },
                    { id: 4, timestamp: '2023-10-26 12:00:00', level: 'INFO', event: 'Database updated', details: 'Virus definitions updated to version 2023.10.26' },
                ]);
            }, 500);
        }
        setLoading(false);
    };

    const getIcon = (level) => {
        switch (level?.toUpperCase()) {
            case 'WARNING': return <AlertCircle className="text-yellow-500" size={18} />;
            case 'ERROR': return <AlertCircle className="text-red-500" size={18} />;
            case 'SUCCESS': return <CheckCircle className="text-green-500" size={18} />;
            default: return <Info className="text-blue-500" size={18} />;
        }
    };

    const getColor = (level) => {
        switch (level?.toUpperCase()) {
            case 'WARNING': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
            case 'ERROR': return 'text-red-500 bg-red-500/10 border-red-500/20';
            case 'SUCCESS': return 'text-green-500 bg-green-500/10 border-green-500/20';
            default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
        }
    };

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-white/5 rounded-xl">
                        <FileText className="text-white" size={24} />
                    </div>
                    <div>
                        <h3 className="text-xl font-bold text-white">System Logs</h3>
                        <p className="text-gray-400 text-sm">View recent system activity and security events</p>
                    </div>
                </div>
                <button
                    onClick={fetchLogs}
                    disabled={loading}
                    className="p-2 bg-white/5 hover:bg-white/10 rounded-lg text-gray-400 hover:text-white transition-colors"
                >
                    <RefreshCw size={20} className={loading ? "animate-spin" : ""} />
                </button>
            </div>

            <div className="bg-surface border border-white/5 rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-white/5 text-gray-400 text-sm uppercase tracking-wider">
                            <tr>
                                <th className="p-4 font-medium w-48">Timestamp</th>
                                <th className="p-4 font-medium w-32">Level</th>
                                <th className="p-4 font-medium w-64">Event</th>
                                <th className="p-4 font-medium">Details</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {logs.map((log, index) => (
                                <tr key={log.id || index} className="hover:bg-white/5 transition-colors">
                                    <td className="p-4 text-gray-400 font-mono text-sm whitespace-nowrap">
                                        <div className="flex items-center gap-2">
                                            <Clock size={14} />
                                            {log.timestamp}
                                        </div>
                                    </td>
                                    <td className="p-4">
                                        <span className={`px-2 py-1 rounded text-xs font-bold border ${getColor(log.level)}`}>
                                            {log.level}
                                        </span>
                                    </td>
                                    <td className="p-4 font-medium text-white">
                                        <div className="flex items-center gap-2">
                                            {getIcon(log.level)}
                                            {log.event}
                                        </div>
                                    </td>
                                    <td className="p-4 text-gray-400 text-sm">
                                        {log.details}
                                    </td>
                                </tr>
                            ))}
                            {logs.length === 0 && !loading && (
                                <tr>
                                    <td colSpan="4" className="p-8 text-center text-gray-500">
                                        No logs found.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default Reports;
