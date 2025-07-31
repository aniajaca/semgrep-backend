// Debug connection test - Run this in browser console
console.log('🧪 Testing connection to backend...');

fetch('https://semgrep-backend-production.up.railway.app/healthz', {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  mode: 'cors'
})
.then(response => {
  console.log('✅ Status:', response.status);
  console.log('✅ Headers:', [...response.headers.entries()]);
  return response.json();
})
.then(data => console.log('✅ SUCCESS:', data))
.catch(error => console.error('❌ ERROR:', error));

// Also test with the environment variable
const API_BASE = import.meta?.env?.VITE_API_BASE_URL || 'https://semgrep-backend-production.up.railway.app';
console.log('🔧 Environment API URL:', API_BASE);

fetch(`${API_BASE}/healthz`, {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  mode: 'cors'
})
.then(response => {
  console.log('✅ ENV Status:', response.status);
  return response.json();
})
.then(data => console.log('✅ ENV SUCCESS:', data))
.catch(error => console.error('❌ ENV ERROR:', error));