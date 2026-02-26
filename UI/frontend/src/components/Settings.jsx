import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
    Bell, Shield, Lock, Eye, Moon, Monitor, RefreshCw, Save, 
    Check, X, Loader2, Wifi, AlertTriangle, Zap, Clock,
    ShieldCheck, ShieldOff, Volume2, VolumeX
} from 'lucide-react';

const Toggle = ({ enabled, onChange, disabled, loading }) => (
    <button
        onClick={() => !disabled && !loading && onChange(!enabled)}
        disabled={disabled || loading}
        className={`w-12 h-6 rounded-full p-1 transition-colors relative ${
            enabled ? 'bg-primary' : 'bg-white/10'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
    >
        {loading ? (
            <div className="absolute inset-0 flex items-center justify-center">
                <Loader2 size={14} className="animate-spin text-white" />
            </div>
        ) : (
            <motion.div
                layout
                className="w-4 h-4 bg-white rounded-full"
                animate={{ x: enabled ? 24 : 0 }}
            />
        )}
    </button>
);

const Section = ({ title, icon: Icon, children, description }) => (
    <div className="bg-surface border border-white/5 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-primary/10 rounded-lg">
                <Icon className="text-primary" size={20} />
            </div>
            <div>
                <h3 className="text-lg font-bold text-white">{title}</h3>
                {description && <p className="text-xs text-gray-500">{description}</p>}
            </div>
        </div>
        <div className="space-y-4 mt-4">
            {children}
        </div>
    </div>
);

const SettingRow = ({ title, description, children }) => (
    <div className="flex items-center justify-between py-2">
        <div className="flex-1">
            <h4 className="font-medium text-white">{title}</h4>
            <p className="text-sm text-gray-400">{description}</p>
        </div>
        <div className="ml-4">
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
        autoBlockThreats: true,
        threatSensitivity: 'MEDIUM',
    });
    
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [savingKey, setSavingKey] = useState(null);
    const [saveStatus, setSaveStatus] = useState(null); // 'success' | 'error' | null
    const [rtpActive, setRtpActive] = useState(false);
    const [nidsActive, setNidsActive] = useState(false);

    // Load settings on mount
    useEffect(() => {
        loadSettings();
    }, []);

    const loadSettings = async () => {
        if (window.pywebview?.api) {
            try {
                const result = await window.pywebview.api.get_all_settings();
                if (result.success) {
                    setSettings(prev => ({
                        ...prev,
                        ...result.settings
                    }));
                    setRtpActive(result.settings.rtpActive || false);
                    setNidsActive(result.settings.nidsActive || false);
                }
            } catch (error) {
                console.error("Failed to load settings:", error);
            }
        }
        setLoading(false);
    };

    const updateSetting = async (key, value) => {
        setSavingKey(key);
        setSettings(prev => ({ ...prev, [key]: value }));

        if (window.pywebview?.api) {
            try {
                const result = await window.pywebview.api.save_setting(key, value);
                
                if (result.success) {
                    // Update runtime states if applicable
                    if (key === 'realTimeProtection') {
                        setRtpActive(value);
                        setNidsActive(value);
                    }
                    showSaveStatus('success');
                } else {
                    // Revert on failure
                    setSettings(prev => ({ ...prev, [key]: !value }));
                    showSaveStatus('error');
                }
            } catch (error) {
                console.error(`Failed to save ${key}:`, error);
                setSettings(prev => ({ ...prev, [key]: !value }));
                showSaveStatus('error');
            }
        }
        setSavingKey(null);
    };

    const showSaveStatus = (status) => {
        setSaveStatus(status);
        setTimeout(() => setSaveStatus(null), 2000);
    };

    const handleSaveAll = async () => {
        setSaving(true);
        if (window.pywebview?.api) {
            try {
                const result = await window.pywebview.api.save_all_settings(settings);
                if (result.success) {
                    showSaveStatus('success');
                } else {
                    showSaveStatus('error');
                }
            } catch (error) {
                console.error("Failed to save settings:", error);
                showSaveStatus('error');
            }
        }
        setSaving(false);
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 size={48} className="animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto">
            {/* Save Status Toast */}
            <AnimatePresence>
                {saveStatus && (
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        className={`fixed top-4 right-4 px-4 py-3 rounded-lg flex items-center gap-2 z-50 ${
                            saveStatus === 'success' 
                                ? 'bg-green-500/20 border border-green-500/50 text-green-400'
                                : 'bg-red-500/20 border border-red-500/50 text-red-400'
                        }`}
                    >
                        {saveStatus === 'success' ? (
                            <>
                                <Check size={18} />
                                <span>Setting saved</span>
                            </>
                        ) : (
                            <>
                                <X size={18} />
                                <span>Failed to save</span>
                            </>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Protection Status Banner */}
            <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`mb-6 p-4 rounded-xl border flex items-center justify-between ${
                    rtpActive 
                        ? 'bg-green-500/10 border-green-500/30'
                        : 'bg-red-500/10 border-red-500/30'
                }`}
            >
                <div className="flex items-center gap-3">
                    {rtpActive ? (
                        <ShieldCheck className="text-green-400" size={32} />
                    ) : (
                        <ShieldOff className="text-red-400" size={32} />
                    )}
                    <div>
                        <h3 className={`font-bold ${rtpActive ? 'text-green-400' : 'text-red-400'}`}>
                            {rtpActive ? 'Protection Active' : 'Protection Disabled'}
                        </h3>
                        <p className="text-sm text-gray-400">
                            {rtpActive 
                                ? 'Real-time monitoring and network protection are running'
                                : 'Enable protection to secure your system'
                            }
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-4">
                    {rtpActive && (
                        <div className="flex items-center gap-2 text-sm">
                            <Wifi size={16} className={nidsActive ? 'text-cyan-400' : 'text-gray-500'} />
                            <span className={nidsActive ? 'text-cyan-400' : 'text-gray-500'}>
                                NIDS {nidsActive ? 'Online' : 'Offline'}
                            </span>
                        </div>
                    )}
                </div>
            </motion.div>

            {/* General Security */}
            <Section title="General Security" icon={Shield} description="Core protection settings">
                <SettingRow 
                    title="Real-Time Protection" 
                    description="Continuously monitor system for threats (also controls Network IDS)"
                >
                    <Toggle
                        enabled={settings.realTimeProtection}
                        onChange={(v) => updateSetting('realTimeProtection', v)}
                        loading={savingKey === 'realTimeProtection'}
                    />
                </SettingRow>
                
                <SettingRow 
                    title="Auto-Block Threats" 
                    description="Automatically block malicious IPs detected by Network IDS"
                >
                    <Toggle
                        enabled={settings.autoBlockThreats}
                        onChange={(v) => updateSetting('autoBlockThreats', v)}
                        loading={savingKey === 'autoBlockThreats'}
                        disabled={!settings.realTimeProtection}
                    />
                </SettingRow>

                <SettingRow 
                    title="Automatic Scanning" 
                    description="Perform background scans when system is idle"
                >
                    <Toggle
                        enabled={settings.autoScan}
                        onChange={(v) => updateSetting('autoScan', v)}
                        loading={savingKey === 'autoScan'}
                    />
                </SettingRow>

                <div className="flex items-center justify-between py-2">
                    <div className="flex-1">
                        <h4 className="font-medium text-white">Threat Sensitivity</h4>
                        <p className="text-sm text-gray-400">Adjust detection sensitivity level</p>
                    </div>
                    <div className="flex gap-2">
                        {['LOW', 'MEDIUM', 'HIGH'].map((level) => (
                            <button
                                key={level}
                                onClick={() => updateSetting('threatSensitivity', level)}
                                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                                    settings.threatSensitivity === level
                                        ? level === 'LOW' 
                                            ? 'bg-blue-500/20 text-blue-400 border border-blue-500/50'
                                            : level === 'MEDIUM'
                                                ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/50'
                                                : 'bg-red-500/20 text-red-400 border border-red-500/50'
                                        : 'bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10'
                                }`}
                            >
                                {level}
                            </button>
                        ))}
                    </div>
                </div>
            </Section>

            {/* Notifications & Alerts */}
            <Section title="Notifications & Alerts" icon={Bell} description="Configure how you receive alerts">
                <SettingRow 
                    title="Desktop Notifications" 
                    description="Show popup alerts for detected threats"
                >
                    <Toggle
                        enabled={settings.notifications}
                        onChange={(v) => updateSetting('notifications', v)}
                        loading={savingKey === 'notifications'}
                    />
                </SettingRow>

                <div className="flex items-center justify-between py-2 opacity-50">
                    <div className="flex-1">
                        <h4 className="font-medium text-white">Sound Alerts</h4>
                        <p className="text-sm text-gray-400">Play sound when threat is detected (coming soon)</p>
                    </div>
                    <div className="flex items-center gap-2 text-gray-500">
                        <VolumeX size={18} />
                        <span className="text-xs">Coming Soon</span>
                    </div>
                </div>
            </Section>

            {/* Appearance */}
            <Section title="Appearance" icon={Monitor} description="Customize the look and feel">
                <SettingRow 
                    title="Dark Mode" 
                    description="Use dark theme for the interface"
                >
                    <Toggle
                        enabled={settings.darkMode}
                        onChange={(v) => updateSetting('darkMode', v)}
                        loading={savingKey === 'darkMode'}
                    />
                </SettingRow>
            </Section>

            {/* Updates */}
            <Section title="Updates" icon={RefreshCw} description="Manage updates and versions">
                <SettingRow 
                    title="Auto-Update Database" 
                    description="Keep threat signatures up to date automatically"
                >
                    <Toggle
                        enabled={settings.autoUpdate}
                        onChange={(v) => updateSetting('autoUpdate', v)}
                        loading={savingKey === 'autoUpdate'}
                    />
                </SettingRow>

                <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
                    <div>
                        <span className="text-sm text-gray-400">Current Version: </span>
                        <span className="text-sm text-white font-medium">2.0.0 (AEGIS)</span>
                    </div>
                    <button 
                        className="text-primary text-sm font-bold hover:underline flex items-center gap-1"
                        onClick={() => alert('You are using the latest version!')}
                    >
                        <RefreshCw size={14} />
                        Check for Updates
                    </button>
                </div>
            </Section>

            {/* Save Button */}
            <div className="flex justify-between items-center">
                <p className="text-sm text-gray-500">
                    Settings are saved automatically when changed
                </p>
                <button 
                    onClick={handleSaveAll}
                    disabled={saving}
                    className="bg-primary text-black font-bold px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                    {saving ? (
                        <Loader2 size={20} className="animate-spin" />
                    ) : (
                        <Save size={20} />
                    )}
                    Save All Settings
                </button>
            </div>
        </div>
    );
};

export default Settings;
