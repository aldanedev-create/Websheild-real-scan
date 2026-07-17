#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebShield Scanner - Application Entry Point
Run this file to start the Flask development server.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask application
from app import create_app

# Create application instance
app = create_app()

if __name__ == '__main__':
    # Get configuration from environment
    debug = os.getenv('DEBUG', 'True').lower() == 'true'
    use_reloader = os.getenv('USE_RELOADER', 'False').lower() == 'true'
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=use_reloader,
        threaded=True
    )
