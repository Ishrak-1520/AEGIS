# Core Package
"""
AEGIS Core Module
Contains the main security engines and monitoring components.
"""

# Import NIDS from network subpackage
try:
    from core.network.nids_engine import NIDSEngine, NetworkFlow, get_nids_engine
    from core.network import NIDS_AVAILABLE
except ImportError:
    NIDSEngine = None
    NetworkFlow = None
    get_nids_engine = None
    NIDS_AVAILABLE = False

__all__ = [
    'NIDSEngine',
    'NetworkFlow',
    'get_nids_engine',
    'NIDS_AVAILABLE',
]