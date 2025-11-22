import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import ThreatNotification from './components/ThreatNotification';
import ThreatAlertDialog from './components/ThreatAlertDialog';
import './index.css';

function NotificationApp() {
    const [threat, setThreat] = useState(null);
    const [showDialog, setShowDialog] = useState(false);

    useEffect(() => {
        // Wait for pywebview API to be ready
        const checkAPI = () => {
            if (window.pywebview?.api) {
                // Get threat data from Python
                window.pywebview.api.get_threat_data().then(data => {
                    setThreat(data);
                }).catch(err => {
                    console.error('Failed to get threat data:', err);
                });
            } else {
                // Retry after a short delay
                setTimeout(checkAPI, 100);
            }
        };

        checkAPI();
    }, []);

    const handleDismiss = () => {
        if (window.pywebview?.api) {
            window.pywebview.api.dismiss();
        }
    };

    const handleViewDetails = () => {
        setShowDialog(true);
    };

    const handleCloseDialog = () => {
        setShowDialog(false);
    };

    const handleAction = (action) => {
        console.log(`Action: ${action}`);
        if (window.pywebview?.api) {
            window.pywebview.api.dismiss();
        }
    };

    return (
        <div className="notification-container" style={{
            position: 'fixed',
            bottom: 0,
            right: 0,
            zIndex: 9999
        }}>
            {threat && !showDialog && (
                <ThreatNotification
                    threat={threat}
                    onDismiss={handleDismiss}
                    onViewDetails={handleViewDetails}
                />
            )}

            {threat && showDialog && (
                <ThreatAlertDialog
                    threat={threat}
                    onClose={handleCloseDialog}
                    onAction={handleAction}
                />
            )}
        </div>
    );
}

ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
        <NotificationApp />
    </React.StrictMode>
);
