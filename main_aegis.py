# Load environment variables early
from dotenv import load_dotenv
load_dotenv()

import webview
import os
import sys
import threading
import queue
import time
import subprocess
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_bridge import AegisAPI
from core.network.sniffer_service import SnifferService


def build_frontend(force=False, dev_mode=False):
    """
    Checks if the frontend build exists. If not, runs 'npm run build'.
    Args:
        force (bool): If True, forces a rebuild.
        dev_mode (bool): If True, skips build for dev server usage (if implemented).
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(project_root, 'ui', 'frontend')
    dist_dir = os.path.join(frontend_dir, 'dist')
    index_path = os.path.join(dist_dir, 'index.html')

    if dev_mode:
        print("Starting in DEV mode. Assuming external dev server...")
        return None

    if force or not os.path.exists(index_path):
        print("Frontend build not found or rebuild requested. Building...", flush=True)
        try:
            # Use shell=True for Windows command execution
            cmd = "npm run build"
            if sys.platform == "win32":
                cmd = f"cd /d \"{frontend_dir}\" && npm run build"
            else:
                cmd = f"cd \"{frontend_dir}\" && npm run build"
            
            result = subprocess.run(cmd, shell=True, check=True, capture_output=False)
            print("Frontend build complete.", flush=True)
        except subprocess.CalledProcessError as e:
            print(f"Error building frontend: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error during build: {e}")
            sys.exit(1)
    else:
        print(f"Loading existing frontend from: {index_path}", flush=True)
    
    return index_path


def main():
    # --- NIDS Initialization ---
    # Create shared resources for NIDS
    network_alert_queue = queue.Queue()
    sniffer_stop_event = threading.Event()
    
    # Initialize the sniffer service (runs as daemon thread)
    sniffer = SnifferService(sniffer_stop_event, network_alert_queue)
    sniffer.start()
    
    # --- API Initialization ---
    api = AegisAPI(
        network_alert_queue=network_alert_queue,
        sniffer_service=sniffer
    )
    
    # Parse Arguments
    parser = argparse.ArgumentParser(description='AEGIS Cyber Defense System')
    parser.add_argument('--rebuild', action='store_true', help='Force rebuild of frontend')
    parser.add_argument('--dev', action='store_true', help='Run in dev mode (skip build check)')
    args = parser.parse_args()

    # Build/Check Frontend
    index_path = build_frontend(force=args.rebuild, dev_mode=args.dev)
    
    # Path to the built React app (or dev server URL if we supported it fully)
    # For now, we point to the file if built.
    if not index_path and args.dev:
         # Fallback or external dev server URL
         index_path = 'http://localhost:5173'

    if not index_path or (not args.dev and not os.path.exists(index_path)):
         print(f"Critical Error: Frontend index not found at {index_path}")
         sys.exit(1)

    # Create window
    window = webview.create_window(
        'AEGIS Cyber Defense', 
        url=index_path,
        js_api=api,
        width=1200,
        height=800,
        resizable=True,
        frameless=False,
        background_color='#050B14'
    )
    
    # Give API reference to window for auto-focusing on threats
    api.set_window(window)
    
    # --- Cleanup callback ---
    def on_closing():
        """Graceful shutdown when window closes."""
        sniffer_stop_event.set()
        # Give threads time to cleanup
        if sniffer.is_alive():
            sniffer.join(timeout=2.0)
    
    window.events.closing += on_closing
    
    # Start webview (debug=False to prevent dev tools from opening)
    webview.start(debug=False)


if __name__ == '__main__':
    main()

