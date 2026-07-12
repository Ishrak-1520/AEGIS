import React, { useState, useEffect, useCallback } from 'react';
import ThreatNotification from './ThreatNotification';
import ThreatAlertDialog from './ThreatAlertDialog';

const ThreatAlertManager = () => {
    const [pendingAlerts, setPendingAlerts] = useState([]);
    const [currentNotification, setCurrentNotification] = useState(null);
    const [currentDialog, setCurrentDialog] = useState(null);
    const [isPolling, setIsPolling] = useState(true);

    // Poll for new alerts
    useEffect(() => {
        if (!isPolling) return;

        const pollAlerts = async () => {
            if (window.pywebview?.api) {
                try {
                    console.log("Polling for threat alerts...");
                    const alerts = await window.pywebview.api.get_pending_threat_alerts();
                    console.log("Poll result:", alerts);
                    if (alerts && alerts.length > 0) {
                        console.log("New threats received:", alerts);
                        setPendingAlerts(prev => [...prev, ...alerts]);
                    }
                } catch (error) {
                    console.error("Failed to poll threat alerts:", error);
                }
            } else {
                console.warn("pywebview API not available");
            }
        };

        const interval = setInterval(pollAlerts, 2000); // Poll every 2 seconds
        return () => clearInterval(interval);
    }, [isPolling]);

    // Process queue
    useEffect(() => {
        // If we have pending alerts and no current notification/dialog, show next one
        if (pendingAlerts.length > 0 && !currentNotification && !currentDialog) {
            const nextAlert = pendingAlerts[0];
            setPendingAlerts(prev => prev.slice(1));
            setCurrentNotification(nextAlert);

            // Play alert sound
            playAlertSound(nextAlert.level);
        }
    }, [pendingAlerts, currentNotification, currentDialog]);

    const playAlertSound = (level) => {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();

            if (level === 'CRITICAL' || level === 'HIGH') {
                // Urgent descending siren — two rapid sweeps
                const playBeep = (startTime, startFreq, endFreq, duration) => {
                    const osc = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.type = 'square';
                    osc.frequency.setValueAtTime(startFreq, ctx.currentTime + startTime);
                    osc.frequency.linearRampToValueAtTime(endFreq, ctx.currentTime + startTime + duration);
                    gain.gain.setValueAtTime(0.18, ctx.currentTime + startTime);
                    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + startTime + duration);
                    osc.connect(gain).connect(ctx.destination);
                    osc.start(ctx.currentTime + startTime);
                    osc.stop(ctx.currentTime + startTime + duration);
                };
                // Two descending sweeps for urgency
                playBeep(0, 1800, 400, 0.35);
                playBeep(0.4, 1800, 400, 0.35);
                // Third sharp stab for CRITICAL
                if (level === 'CRITICAL') {
                    playBeep(0.85, 2200, 600, 0.25);
                }
            } else if (level === 'MEDIUM') {
                // Double-pulse warning beep
                const playPulse = (startTime) => {
                    const osc = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.type = 'triangle';
                    osc.frequency.setValueAtTime(880, ctx.currentTime + startTime);
                    gain.gain.setValueAtTime(0.15, ctx.currentTime + startTime);
                    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + startTime + 0.15);
                    osc.connect(gain).connect(ctx.destination);
                    osc.start(ctx.currentTime + startTime);
                    osc.stop(ctx.currentTime + startTime + 0.15);
                };
                playPulse(0);
                playPulse(0.2);
            } else {
                // Gentle single notification chime
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(660, ctx.currentTime);
                osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.1);
                gain.gain.setValueAtTime(0.12, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
                osc.connect(gain).connect(ctx.destination);
                osc.start(ctx.currentTime);
                osc.stop(ctx.currentTime + 0.4);
            }
        } catch (e) {
            console.warn('Could not play alert sound:', e);
        }
    };

    const handleDismissNotification = useCallback(() => {
        setCurrentNotification(null);
    }, []);

    const handleViewDetails = useCallback(() => {
        setCurrentDialog(currentNotification);
        setCurrentNotification(null);
    }, [currentNotification]);

    const handleCloseDialog = useCallback(() => {
        setCurrentDialog(null);
    }, []);

    const handleAction = useCallback(async (action) => {
        console.log(`User took action: ${action} on threat`, currentDialog);

        // Here we could call back to backend to log the action or perform blocking
        // e.g., await window.pywebview.api.handle_threat_action(currentDialog.id, action);

        setCurrentDialog(null);
    }, [currentDialog]);

    return (
        <>
            {/* Compact Notification */}
            <ThreatNotification
                threat={currentNotification}
                onDismiss={handleDismissNotification}
                onViewDetails={handleViewDetails}
            />

            {/* Full Dialog */}
            {currentDialog && (
                <ThreatAlertDialog
                    threat={currentDialog}
                    onClose={handleCloseDialog}
                    onAction={handleAction}
                />
            )}
        </>
    );
};

export default ThreatAlertManager;
