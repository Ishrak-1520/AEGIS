import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Plus, Copy, Eye, EyeOff, Trash2, X, Save, Lock, KeyRound } from 'lucide-react';

const PasswordManager = () => {
    // Auth State
    const [authStatus, setAuthStatus] = useState({ isChecking: true, hasMaster: false, isAuth: false });
    const [masterPassword, setMasterPassword] = useState('');
    const [authError, setAuthError] = useState('');

    // Vault State
    const [passwords, setPasswords] = useState([]);
    const [decryptedPasswords, setDecryptedPasswords] = useState({});
    const [showPassword, setShowPassword] = useState({});
    const [searchTerm, setSearchTerm] = useState('');

    // Modal State
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [newPassword, setNewPassword] = useState({ site: '', username: '', password: '', category: 'General' });

    useEffect(() => {
        checkAuth();
    }, []);

    const checkAuth = async () => {
        if (window.pywebview?.api) {
            try {
                const status = await window.pywebview.api.check_auth_status();
                setAuthStatus({
                    isChecking: false,
                    hasMaster: status.has_master_password,
                    isAuth: status.is_authenticated
                });

                if (status.is_authenticated) {
                    fetchPasswords();
                }
            } catch (error) {
                console.error("Auth check failed:", error);
                setAuthStatus(prev => ({ ...prev, isChecking: false }));
            }
        }
    };

    const handleAuthSubmit = async (e) => {
        e.preventDefault();
        setAuthError('');

        if (!masterPassword) return;

        if (window.pywebview?.api) {
            try {
                let result;
                if (!authStatus.hasMaster) {
                    result = await window.pywebview.api.register_master_password(masterPassword);
                } else {
                    result = await window.pywebview.api.login_master_password(masterPassword);
                }

                if (result.status === 'success') {
                    setAuthStatus(prev => ({ ...prev, hasMaster: true, isAuth: true }));
                    setMasterPassword('');
                    fetchPasswords();
                } else {
                    setAuthError(result.message || "Authentication failed");
                }
            } catch (error) {
                setAuthError("Failed to communicate with secure vault");
            }
        }
    };

    const fetchPasswords = async () => {
        if (window.pywebview?.api) {
            try {
                const data = await window.pywebview.api.get_passwords();
                if (data.error === 'unauthenticated') {
                    setAuthStatus(prev => ({ ...prev, isAuth: false }));
                    return;
                }
                setPasswords(data || []);
            } catch (error) {
                console.error("Failed to fetch passwords:", error);
            }
        }
    };

    const handleAddPassword = async () => {
        if (window.pywebview?.api) {
            try {
                const result = await window.pywebview.api.add_password(
                    newPassword.site,
                    newPassword.username,
                    newPassword.password,
                    newPassword.category
                );

                if (result.status === 'success') {
                    fetchPasswords();
                    setIsAddModalOpen(false);
                    setNewPassword({ site: '', username: '', password: '', category: 'General' });
                } else {
                    alert(result.message || "Failed to add password");
                }
            } catch (error) {
                console.error("Failed to add password:", error);
            }
        }
    };

    const handleDeletePassword = async (id) => {
        if (window.pywebview?.api) {
            try {
                await window.pywebview.api.delete_password(id);
                fetchPasswords();

                // Cleanup decrypted cache
                const newDecrypted = { ...decryptedPasswords };
                delete newDecrypted[id];
                setDecryptedPasswords(newDecrypted);

            } catch (error) {
                console.error("Failed to delete password:", error);
            }
        }
    };

    const togglePassword = async (id) => {
        const isCurrentlyShown = showPassword[id];

        if (!isCurrentlyShown && !decryptedPasswords[id]) {
            // Need to fetch decrypted version
            if (window.pywebview?.api) {
                try {
                    const result = await window.pywebview.api.get_decrypted_password(id);
                    if (result.status === 'success') {
                        setDecryptedPasswords(prev => ({ ...prev, [id]: result.password }));
                        setShowPassword(prev => ({ ...prev, [id]: true }));
                    } else {
                        console.error(result.message);
                    }
                } catch (e) {
                    console.error("Error decrypting:", e);
                }
            }
        } else {
            // Already have it or hiding it
            setShowPassword(prev => ({ ...prev, [id]: !prev[id] }));
        }
    };

    const copyToClipboard = async (id) => {
        let textToCopy = decryptedPasswords[id];

        if (!textToCopy && window.pywebview?.api) {
            // Fetch it just to copy if we don't have it cached
            try {
                const result = await window.pywebview.api.get_decrypted_password(id);
                if (result.status === 'success') {
                    textToCopy = result.password;
                    setDecryptedPasswords(prev => ({ ...prev, [id]: textToCopy }));
                }
            } catch (e) {
                console.error("Error decrypting for copy:", e);
                return;
            }
        }

        if (textToCopy) {
            navigator.clipboard.writeText(textToCopy);
            // Could add a toast here
        }
    };

    const filteredPasswords = passwords.filter(p =>
        (p.website || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (p.username || '').toLowerCase().includes(searchTerm.toLowerCase())
    );

    // --- RENDER MODES ---

    if (authStatus.isChecking) {
        return <div className="flex justify-center items-center h-64 text-gray-400">Checking secure vault status...</div>;
    }

    if (!authStatus.isAuth) {
        return (
            <div className="flex items-center justify-center min-h-[500px]">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="bg-surface border border-white/10 rounded-xl p-8 max-w-md w-full text-center relative overflow-hidden"
                >
                    <div className="absolute top-0 right-0 p-8 opacity-5 text-primary">
                        <Lock size={120} />
                    </div>

                    <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6 text-primary relative z-10 border border-primary/20">
                        <KeyRound size={28} />
                    </div>

                    <h2 className="text-2xl font-bold text-white mb-2 relative z-10">Secure Password Vault</h2>
                    <p className="text-gray-400 text-sm mb-8 relative z-10">
                        {authStatus.hasMaster
                            ? "Enter your master password to unlock your vault."
                            : "Set up a master password to encrypt your vault. Use at least 12 characters with mixed case, digits, and symbols."}
                    </p>

                    <form onSubmit={handleAuthSubmit} className="relative z-10">
                        <input
                            type="password"
                            value={masterPassword}
                            onChange={(e) => setMasterPassword(e.target.value)}
                            placeholder="Master Password"
                            className="w-full bg-black/20 border border-white/10 rounded-lg p-3 text-white focus:border-primary outline-none text-center tracking-widest mb-4"
                            autoFocus
                        />

                        {authError && (
                            <p className="text-red-400 text-sm mb-4 bg-red-500/10 py-2 rounded border border-red-500/20">{authError}</p>
                        )}

                        <button
                            type="submit"
                            className="w-full bg-primary hover:bg-primary/90 text-black font-bold py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                        >
                            <Lock size={18} />
                            {authStatus.hasMaster ? "Unlock Vault" : "Create Vault"}
                        </button>
                    </form>
                </motion.div>
            </div>
        );
    }

    return (
        <div className="space-y-6 relative">
            {/* Header Actions */}
            <div className="flex items-center justify-between">
                <div className="relative w-96">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
                    <input
                        type="text"
                        placeholder="Search passwords..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-surface border border-white/10 rounded-lg pl-10 pr-4 py-2 text-white focus:border-primary/50 outline-none transition-colors"
                    />
                </div>
                <div className="flex items-center gap-3">
                    <div className="px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400 text-sm flex items-center gap-2">
                        <Lock size={14} /> Vault Unlocked
                    </div>
                    <button
                        onClick={() => setIsAddModalOpen(true)}
                        className="bg-primary text-black font-bold px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-primary/90 transition-colors"
                    >
                        <Plus size={20} />
                        Add Password
                    </button>
                </div>
            </div>

            {/* Password Table */}
            <div className="bg-surface border border-white/5 rounded-xl overflow-hidden min-h-[400px]">
                <table className="w-full text-left">
                    <thead className="bg-white/5 text-gray-400 text-sm uppercase tracking-wider">
                        <tr>
                            <th className="p-4 font-medium">Site</th>
                            <th className="p-4 font-medium">Username</th>
                            <th className="p-4 font-medium">Password</th>
                            <th className="p-4 font-medium">Category</th>
                            <th className="p-4 font-medium text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                        {filteredPasswords.map((item) => (
                            <tr key={item.id} className="hover:bg-white/5 transition-colors group">
                                <td className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="w-8 h-8 rounded bg-white/10 flex items-center justify-center text-white font-bold">
                                            {(item.website || '?')[0].toUpperCase()}
                                        </div>
                                        <span className="font-medium text-white">{item.website}</span>
                                    </div>
                                </td>
                                <td className="p-4 text-gray-300">{item.username}</td>
                                <td className="p-4">
                                    <div className="flex items-center gap-2">
                                        <span className="font-mono text-gray-300 tracking-wider">
                                            {showPassword[item.id] ? decryptedPasswords[item.id] || '******' : '••••••••••••'}
                                        </span>
                                        <button
                                            onClick={() => togglePassword(item.id)}
                                            className="text-gray-500 hover:text-white transition-colors ml-2"
                                        >
                                            {showPassword[item.id] ? <EyeOff size={16} /> : <Eye size={16} />}
                                        </button>
                                    </div>
                                </td>
                                <td className="p-4">
                                    <span className="px-2 py-1 rounded text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                        {item.category || 'General'}
                                    </span>
                                </td>
                                <td className="p-4 text-right">
                                    <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <button
                                            onClick={() => copyToClipboard(item.id)}
                                            className="p-2 text-gray-400 hover:text-primary transition-colors hover:bg-white/5 rounded"
                                            title="Copy Password"
                                        >
                                            <Copy size={18} />
                                        </button>
                                        <button
                                            onClick={() => handleDeletePassword(item.id)}
                                            className="p-2 text-gray-400 hover:text-red-500 transition-colors hover:bg-white/5 rounded"
                                            title="Delete"
                                        >
                                            <Trash2 size={18} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                        {filteredPasswords.length === 0 && (
                            <tr>
                                <td colSpan="5" className="p-8 text-center text-gray-500">
                                    No passwords found. Add one to get started.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Add Password Modal */}
            <AnimatePresence>
                {isAddModalOpen && (
                    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            className="bg-surface border border-white/10 rounded-xl p-6 w-full max-w-md shadow-2xl"
                        >
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                    <Lock size={20} className="text-primary" />
                                    Add New Password
                                </h3>
                                <button onClick={() => setIsAddModalOpen(false)} className="text-gray-400 hover:text-white">
                                    <X size={24} />
                                </button>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm text-gray-400 mb-1">Website</label>
                                    <input
                                        type="text"
                                        value={newPassword.site}
                                        onChange={e => setNewPassword({ ...newPassword, site: e.target.value })}
                                        className="w-full bg-black/20 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
                                        placeholder="e.g. google.com"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-400 mb-1">Username</label>
                                    <input
                                        type="text"
                                        value={newPassword.username}
                                        onChange={e => setNewPassword({ ...newPassword, username: e.target.value })}
                                        className="w-full bg-black/20 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
                                        placeholder="e.g. user@email.com"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-400 mb-1">Password</label>
                                    <input
                                        type="password"
                                        value={newPassword.password}
                                        onChange={e => setNewPassword({ ...newPassword, password: e.target.value })}
                                        className="w-full bg-black/20 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none tracking-widest"
                                        placeholder="••••••••"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-400 mb-1">Category</label>
                                    <select
                                        value={newPassword.category}
                                        onChange={e => setNewPassword({ ...newPassword, category: e.target.value })}
                                        className="w-full bg-black/20 border border-white/10 rounded-lg p-2 text-white focus:border-primary outline-none"
                                    >
                                        <option value="General">General</option>
                                        <option value="Social">Social</option>
                                        <option value="Finance">Finance</option>
                                        <option value="Work">Work</option>
                                    </select>
                                </div>
                            </div>

                            <div className="flex justify-end gap-3 mt-8">
                                <button
                                    onClick={() => setIsAddModalOpen(false)}
                                    className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleAddPassword}
                                    className="bg-primary text-black font-bold px-6 py-2 rounded-lg hover:bg-primary/90 transition-colors flex items-center gap-2"
                                >
                                    <Save size={18} />
                                    Save Password
                                </button>
                            </div>
                        </motion.div>
                    </div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default PasswordManager;
