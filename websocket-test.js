const WebSocket = require('ws');

console.log('🧪 Testing WebSocket connection to ws://localhost:3333...');
console.log('🔄 Will send stats requests every 10 seconds - press Ctrl+C to stop');

const ws = new WebSocket('ws://localhost:3333');
let requestCount = 0;
let statsInterval;

ws.on('open', () => {
  console.log('✅ WebSocket connected successfully!');
  
  // Send initial stats request
  sendStatsRequest();
  
  // Set up periodic stats requests every 10 seconds
  statsInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      sendStatsRequest();
    } else {
      console.log('❌ WebSocket not open, stopping requests');
      clearInterval(statsInterval);
    }
  }, 10000);
});

function sendStatsRequest() {
  requestCount++;
  const statsRequest = { what: 'stats' };
  ws.send(JSON.stringify(statsRequest));
  console.log(`📡 [${requestCount}] Sent stats request at ${new Date().toLocaleTimeString()}`);
}

ws.on('message', (data) => {
  try {
    const message = JSON.parse(data.toString());
    const timestamp = new Date().toLocaleTimeString();
    
    console.log(`📨 [${timestamp}] Received message type: ${message.what || 'unknown'}`);
    
    if (message.what === 'stats' && message.value) {
      const stats = message.value;
      console.log(`✅ Stats data - Sessions: ${stats.sessions}, Users: ${stats.users}, Points: ${stats.walletLifePoints}, Traffic: ${stats.syncLifeTraffic}, Connection: ${stats.proxyConnectionState}`);
    } else {
      console.log(`📊 Raw message: ${data.toString().substring(0, 150)}...`);
    }
  } catch (error) {
    console.log(`📊 Raw data: ${data.toString().substring(0, 150)}...`);
  }
});

ws.on('error', (error) => {
  console.log('❌ WebSocket error:', error.message);
  clearInterval(statsInterval);
  process.exit(1);
});

ws.on('close', (code, reason) => {
  console.log(`🔌 WebSocket closed: ${code} ${reason.toString()}`);
  clearInterval(statsInterval);
  process.exit(0);
});

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
  console.log('\n🛑 Stopping WebSocket test...');
  clearInterval(statsInterval);
  if (ws.readyState === WebSocket.OPEN) {
    ws.close();
  } else {
    process.exit(0);
  }
}); 