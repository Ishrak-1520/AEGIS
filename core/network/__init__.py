"""
AEGIS Network Module
====================
Network-related detection and monitoring components.

Components:
- NIDSEngine: Real-time network intrusion detection using ML
- NetworkFlow: Flow tracking and feature extraction
- SnifferService: Legacy sniffer service (deprecated, use NIDSEngine)
"""

# Import NIDS components
try:
    from core.network.nids_engine import (
        NIDSEngine,
        NetworkFlow,
        get_nids_engine,
        SCAPY_AVAILABLE,
        JOBLIB_AVAILABLE,
    )
    NIDS_AVAILABLE = True
except ImportError as e:
    NIDSEngine = None
    NetworkFlow = None
    get_nids_engine = None
    SCAPY_AVAILABLE = False
    JOBLIB_AVAILABLE = False
    NIDS_AVAILABLE = False
    print(f"Warning: NIDS components not available: {e}")

# Legacy import for compatibility
try:
    from core.network.sniffer_service import SnifferService
except ImportError:
    SnifferService = None

# Data adapter for network statistics
try:
    from core.network.data_adapter import DataAdapter
except ImportError:
    DataAdapter = None


__all__ = [
    'NIDSEngine',
    'NetworkFlow', 
    'get_nids_engine',
    'SnifferService',
    'DataAdapter',
    'NIDS_AVAILABLE',
    'SCAPY_AVAILABLE',
    'JOBLIB_AVAILABLE',
]
