import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Bell, Shield, Lock, Eye, Moon, Monitor, RefreshCw, Save } from 'lucide-react';

const Toggle = ({ enabled, onChange }) => (
    <button
        onClick={() => onChange(!enabled)}
        className={`w-12 h-6 rounded-full p-1 transition-colors ${enabled ? 'bg-primary' : 'bg-white/10'}`}
    >
        <motion.div
            layout
            className="w-4 h-4 bg-white rounded-full"
            animate={{ x: enabled ? 24 : 0 }}
        />
    </button>
);

const Section = ({ title, icon: Icon, children }) => (
    <div className="bg-surface border border-white/5 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-primary/10 rounded-lg">
                <Icon className="text-primary" size={20} />
            </div>
            <h3 className="text-lg font-bold text-white">{title}</h3>
        </div>
        <div className="space-y-6">
            {children}
        </div>
    </div>
);

const Settings = () => {
    const [settings, setSettings] = useState({
        realTimeProtection: true,
        autoScan: true,
        notifications: true,
        darkMode: true,
        autoUpdate: false,
    });

    useEffect(() => {
        // Fetch initial RTP status
        if (window.pywebview?.api) {
            window.pywebview.api.get_rtp_status().then(stats => {
                // Assuming stats has an 'active' or similar field, but for now we just trust the state
                // In a real app, we'd sync this.
            }).catch(console.error);
        }
    }, []);

    const updateSetting = async (key, value) => {
        setSettings(prev => ({ ...prev, [key]: value }));

        if (key === 'realTimeProtection') {
            if (window.pywebview?.api) {
                try {
                    await window.pywebview.api.toggle_rtp(value);
                } catch (error) {
                    console.error("Failed to toggle RTP:", error);
                    // Revert state on error
                    setSettings(prev => ({ ...prev, [key]: !value }));
                }
            }
        }
    };

    return (
        <div className="max-w-4xl mx-auto">
            <Section title="General Security" icon={Shield}>
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="font-medium text-white">Real-Time Protection</h4>
                        <p className="text-sm text-gray-400">Continuously monitor system for threats</p>
                    </div>
                    <Toggle
                        enabled={settings.realTimeProtection}
                        onChange={(v) => updateSetting('realTimeProtection', v)}
                    />
                </div>
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="font-medium text-white">Automatic Scanning</h4>
                        <p className="text-sm text-gray-400">Perform background scans when system is idle</p>
                    </div>
                    <Toggle
                        enabled={settings.autoScan}
                        onChange={(v) => updateSetting('autoScan', v)}
                    />
                </div>
            </Section>

            <Section title="Notifications & Privacy" icon={Bell}>
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="font-medium text-white">Desktop Notifications</h4>
                        <p className="text-sm text-gray-400">Show alerts for detected threats and updates</p>
                    </div>
                    <Toggle
                        enabled={settings.notifications}
                        onChange={(v) => updateSetting('notifications', v)}
                    />
                </div>
            </Section>

            <Section title="Appearance" icon={Monitor}>
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="font-medium text-white">Dark Mode</h4>
                        <p className="text-sm text-gray-400">Use dark theme for the interface</p>
                    </div>
                    <Toggle
                        enabled={settings.darkMode}
                        onChange={(v) => updateSetting('darkMode', v)}
                    />
                </div>
            </Section>

            <Section title="Updates" icon={RefreshCw}>
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="font-medium text-white">Auto-Update Database</h4>
                        <p className="text-sm text-gray-400">Keep virus definitions up to date automatically</p>
                    </div>
                    <Toggle
                        enabled={settings.autoUpdate}
                        onChange={(v) => updateSetting('autoUpdate', v)}
                    />
                </div>
                <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
                    <span className="text-sm text-gray-400">Current Version: 2.0.0 (AEGIS)</span>
                    <button className="text-primary text-sm font-bold hover:underline">Check for Updates</button>
                </div>
            </Section>

            <div className="flex justify-end">
                <button className="bg-primary text-black font-bold px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-primary/90 transition-colors">
                    <Save size={20} />
                    Save Changes
                </button>
            </div>
        </div>
    );
};

export default Settings;
