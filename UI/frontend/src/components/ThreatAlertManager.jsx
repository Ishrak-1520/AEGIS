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
        // Simple beep logic or audio file could go here
        // For now, just log
        console.log(`Playing alert sound for ${level} threat`);
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
