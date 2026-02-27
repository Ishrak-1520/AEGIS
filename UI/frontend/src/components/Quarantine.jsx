import React, { useState, useEffect } from 'react';
import { AlertTriangle, Trash2, RotateCcw, ShieldAlert } from 'lucide-react';

const Quarantine = () => {
    const [quarantinedItems, setQuarantinedItems] = useState([]);

    useEffect(() => {
        fetchQuarantine();
    }, []);

    const fetchQuarantine = async () => {
        if (window.pywebview?.api) {
            try {
                const data = await window.pywebview.api.get_quarantined_items();
                setQuarantinedItems(data);
            } catch (error) {
                console.error("Failed to fetch quarantine:", error);
            }
        } else {
            // Mock data for dev
            console.log("PyWebView API not found, using mock data");
        }
    };

    const handleRestore = async (id) => {
        if (window.pywebview?.api) {
            try {
                await window.pywebview.api.restore_quarantine_item(id);
                fetchQuarantine();
            } catch (error) {
                console.error("Failed to restore item:", error);
            }
        }
    };

    const handleDelete = async (id) => {
        if (window.pywebview?.api) {
            try {
                await window.pywebview.api.delete_quarantine_item(id);
                fetchQuarantine();
            } catch (error) {
                console.error("Failed to delete item:", error);
            }
        }
    };

    const handleSimulateQuarantine = async () => {
        if (window.pywebview?.api) {
            try {
                const result = await window.pywebview.api.simulate_quarantine();
                if (result?.status === 'success') {
                    fetchQuarantine();
                } else {
                    alert("Failed to simulate: " + (result?.message || "Unknown error"));
                }
            } catch (error) {
                console.error("Failed to simulate quarantine:", error);
            }
        }
    };

    return (
        <div className="space-y-6">
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 flex items-start gap-4">
                <ShieldAlert className="text-red-500 shrink-0" size={32} />
                <div className="flex-1">
                    <h3 className="text-lg font-bold text-white mb-1">Quarantined Items</h3>
                    <p className="text-gray-400 text-sm">
                        These items have been isolated to prevent harm to your system. You can choose to restore them if you believe they are safe, or delete them permanently.
                    </p>
                </div>
                <button
                    onClick={handleSimulateQuarantine}
                    className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg transition-colors border border-red-500/30 text-sm font-medium whitespace-nowrap"
                >
                    Test: Simulate Threat
                </button>
            </div>

            <div className="bg-surface border border-white/5 rounded-xl overflow-hidden min-h-[400px]">
                <div className="p-4 border-b border-white/5 flex items-center justify-between">
                    <h3 className="font-bold text-white">Isolated Threats</h3>
                    <div className="text-sm text-gray-500">
                        {quarantinedItems.length} items
                    </div>
                </div>
                <div className="divide-y divide-white/5">
                    {quarantinedItems.map((item) => (
                        <div key={item.id} className="p-4 flex items-center justify-between hover:bg-white/5 transition-colors">
                            <div className="flex items-center gap-4">
                                <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center text-red-500">
                                    <AlertTriangle size={20} />
                                </div>
                                <div>
                                    <h4 className="font-bold text-white">{item.original_path ? item.original_path.split(/[/\\]/).pop() : 'Unknown File'}</h4>
                                    <p className="text-xs text-gray-500">{item.original_path}</p>
                                    <div className="flex items-center gap-2 mt-1">
                                        <span className="text-xs text-gray-400">
                                            {item.quarantined_at ? new Date(item.quarantined_at).toLocaleString() : 'Unknown Date'}
                                        </span>
                                        <span className="text-xs font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
                                            {item.threat_type || 'Unknown Threat'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={() => handleRestore(item.id)}
                                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white transition-colors text-sm font-medium"
                                >
                                    <RotateCcw size={16} />
                                    Restore
                                </button>
                                <button
                                    onClick={() => handleDelete(item.id)}
                                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-500 transition-colors text-sm font-medium"
                                >
                                    <Trash2 size={16} />
                                    Delete
                                </button>
                            </div>
                        </div>
                    ))}
                    {quarantinedItems.length === 0 && (
                        <div className="p-8 text-center text-gray-500">
                            No quarantined items found. Your system is clean.
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Quarantine;
