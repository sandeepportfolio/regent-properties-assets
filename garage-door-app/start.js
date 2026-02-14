const { spawn } = require('child_process');
const localtunnel = require('localtunnel');

// Start the Express server
const server = spawn('node', ['server.js'], {
  cwd: __dirname,
  stdio: 'inherit'
});

// Wait a moment for the server to start, then open the tunnel
setTimeout(async () => {
  try {
    const tunnel = await localtunnel({ port: 3000 });
    console.log(`\n=============================================`);
    console.log(`  PUBLIC URL: ${tunnel.url}`);
    console.log(`  Password: regent2026`);
    console.log(`=============================================\n`);

    tunnel.on('close', () => {
      console.log('Tunnel closed');
    });

    tunnel.on('error', (err) => {
      console.error('Tunnel error:', err);
    });
  } catch (err) {
    console.error('Failed to create tunnel:', err.message);
  }
}, 2000);

process.on('SIGINT', () => {
  server.kill();
  process.exit(0);
});
