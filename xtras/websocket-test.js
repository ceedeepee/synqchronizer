const WebSocket = require('ws');

console.log('🧪 Testing WebSocket connection to ws://localhost:3333...');

const ws = new WebSocket('ws://localhost:3333');

ws.on('open', () => {
  console.log('✅ WebSocket connected successfully!');
  
  // Send stats request
  const statsRequest = { what: 'stats' };
  ws.send(JSON.stringify(statsRequest));
  console.log('📡 Sent stats request:', JSON.stringify(statsRequest));
  
  // Close after 5 seconds
  setTimeout(() => {
    console.log('🏁 Test completed - closing connection');
    ws.close();
  }, 5000);
});

ws.on('message', (data) => {
  try {
    const message = JSON.parse(data.toString());
    console.log('📨 Received message type:', message.what || 'unknown');
    if (message.what === 'stats' && message.value) {
      console.log('✅ Stats data received with fields:', Object.keys(message.value).join(', '));
    } else {
      console.log('📊 Raw message:', data.toString().substring(0, 150) + '...');
    }
  } catch (error) {
    console.log('📊 Raw data:', data.toString().substring(0, 150) + '...');
  }
});

ws.on('error', (error) => {
  console.log('❌ WebSocket error:', error.message);
  process.exit(1);
});

ws.on('close', (code, reason) => {
  console.log('🔌 WebSocket closed:', code, reason.toString());
  process.exit(0);
}); 