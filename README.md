# Spladpad Online

## Run locally
1. Install Node.js 18 or newer.
2. Open this folder in a terminal.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000` in your browser.

Do **not** open `public/index.html` directly if you want the online server features. The HTML file can connect to `http://localhost:3000/api` when opened directly, but the Node server must already be running.

### Windows
Double-click `start-server.bat`.

### Linux/macOS/ChromeOS Linux
Run `./start-server.sh` (or `npm install` then `npm start`).

## Server check
With the server running, open `http://localhost:3000/api/health`. It should return JSON containing `"ok":true`.

## Public hosting
Deploy the Node service with the included `render.yaml`, or another Node-compatible host. When served from a host, the site automatically uses `/api` on the same server.
