const localtunnel = require('localtunnel');
const fs = require('fs');

(async () => {
  console.log('Starting tunnel...');
  try {
    const tunnel = await localtunnel({ port: 3000 });
    const url = tunnel.url;
    console.log('TUNNEL_URL=' + url);
    fs.writeFileSync('/tmp/tunnel-url.txt', url);
    tunnel.on('close', () => console.log('Tunnel closed'));
    tunnel.on('error', (err) => console.error('Tunnel error:', err));
  } catch (err) {
    console.error('TUNNEL_ERROR=' + err.message);
    console.error(err.stack);
  }
})();
