import webview
import os
import sys
import threading
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_bridge import AegisAPI

def main():
    api = AegisAPI()
    
    # Path to the built React app
    frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ui', 'frontend', 'dist')
    index_path = os.path.join(frontend_dir, 'index.html')
    
    if not os.path.exists(index_path):
        print(f"Error: Frontend build not found at {index_path}")
        print("Please run 'npm run build' in ui/frontend directory.")
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
    
    # Start webview (debug=False to prevent dev tools from opening)
    webview.start(debug=False)

if __name__ == '__main__':
    main()
