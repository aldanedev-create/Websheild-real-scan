# -*- coding: utf-8 -*-

"""
WebShield Scanner - WSGI Entry Point
For production deployment with Gunicorn or uWSGI.
"""

import os
import sys

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import the Flask application
from app import create_app

# Create application instance
app = create_app()

# For Gunicorn to find the app
application = app

if __name__ == '__main__':
    app.run()