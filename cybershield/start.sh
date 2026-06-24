#!/bin/bash
# CyberShield — Start both servers (Linux/macOS)
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REACT_DIR="$(dirname "$SCRIPT_DIR")/cybershield-ui"

echo ""
echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗"
echo " ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo " ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║"
echo " ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo " ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝"
echo ""
echo "  AI-Powered Cybersecurity Platform"
echo ""

# Activate virtualenv if present
if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
    echo "  ✅ Virtual environment activated"
fi

# Check model
if [ ! -f "$SCRIPT_DIR/ml_engine/saved_models/ensemble_model.pkl" ]; then
    echo "  ⚙️  ML model not found — training now (takes ~3 minutes)..."
    cd "$SCRIPT_DIR" && python scripts/train_model.py
fi

echo "  🚀 Starting Django API  → http://localhost:8000"
cd "$SCRIPT_DIR" && python manage.py runserver 8000 &
DJANGO_PID=$!

echo "  🚀 Starting React UI   → http://localhost:5173"
cd "$REACT_DIR" && npm run dev &
REACT_PID=$!

echo ""
echo "  ──────────────────────────────────────────"
echo "  Open browser: http://localhost:5173"
echo "  Login: admin / admin123"
echo "  Admin: http://localhost:8000/admin"
echo "  ──────────────────────────────────────────"
echo "  Press Ctrl+C to stop both servers"
echo ""

cleanup() {
    echo ""
    echo "  Shutting down..."
    kill $DJANGO_PID $REACT_PID 2>/dev/null
    wait $DJANGO_PID $REACT_PID 2>/dev/null
    echo "  Done."
}
trap cleanup SIGINT SIGTERM
wait
