const WebSocket = require('ws');

console.log('Testing WebSocket connection to localhost:3333...');

const ws = new WebSocket('ws://localhost:3333');

ws.on('open', () => {
  console.log('✅ WebSocket connected successfully');
  console.log('📡 Sending stats request...');
  ws.send(JSON.stringify({what: 'stats'}));
});

ws.on('message', (data) => {
  console.log('📊 Received response:', data.toString());
//   ws.close();
});

ws.on('error', (error) => {
  console.log('❌ WebSocket error:', error.message);
  process.exit(1);
});

ws.on('close', () => {
  console.log('🔌 WebSocket closed');
  process.exit(0);
});

// Timeout after 5 seconds
// setTimeout(() => {
//   console.log('⏱️ Timeout after 5 seconds - no response');
//   process.exit(1);
// }, 5000);