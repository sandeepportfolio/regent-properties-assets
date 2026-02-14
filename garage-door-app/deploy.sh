#!/bin/bash
# Regent Properties - Garage Door Controller
# One-command deploy script
# Usage: ./deploy.sh [password]

set -e

PASSWORD="${1:-regent2026}"
PORT="${PORT:-3000}"

echo ""
echo "================================================="
echo "  Regent Properties - Garage Door Controller"
echo "================================================="
echo ""

# Install dependencies
echo "[1/3] Installing dependencies..."
npm install --production 2>/dev/null

# Start the server
echo "[2/3] Starting server on port $PORT..."
ACCESS_PASSWORD="$PASSWORD" node server.js &
SERVER_PID=$!
sleep 2

# Start cloudflared tunnel for public URL
echo "[3/3] Creating public tunnel..."
echo ""

if command -v cloudflared &> /dev/null; then
    cloudflared tunnel --url http://localhost:$PORT --no-autoupdate 2>&1 | while read -r line; do
        if echo "$line" | grep -q "https://"; then
            URL=$(echo "$line" | grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com')
            if [ -n "$URL" ]; then
                echo ""
                echo "================================================="
                echo "  YOUR PUBLIC URL: $URL"
                echo "  Password: $PASSWORD"
                echo "================================================="
                echo ""
                echo "  Share this URL to access your garage control."
                echo "  Press Ctrl+C to stop."
                echo ""
            fi
        fi
        echo "$line"
    done
else
    echo "cloudflared not found. Install it:"
    echo "  macOS: brew install cloudflared"
    echo "  Linux: curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared"
    echo ""
    echo "Or use ngrok: npx ngrok http $PORT"
    echo ""
    echo "Server is running at: http://localhost:$PORT"
    echo "Password: $PASSWORD"
    wait $SERVER_PID
fi

# Cleanup
trap "kill $SERVER_PID 2>/dev/null" EXIT
