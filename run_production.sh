#!/bin/bash
# Production runner for HomeNetMon

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set production defaults
export FLASK_ENV=production
export HOST=0.0.0.0
export PORT=5000

# Run the application
exec venv/bin/python app.py
