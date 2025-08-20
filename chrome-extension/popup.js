const API_URL = "http://localhost:8080/api/v1";

function setOutput(msg) {
  document.getElementById('output').textContent = msg;
}

// Load token from storage
function loadToken() {
  chrome.storage.local.get(['authToken'], (result) => {
    document.getElementById('authToken').value = result.authToken || '';
  });
}

// Save token to storage
function saveToken() {
  const token = document.getElementById('authToken').value;
  chrome.storage.local.set({ authToken: token });
}

document.getElementById('saveTokenBtn').onclick = saveToken;

document.getElementById('setBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  const value = document.getElementById('value').value;
  chrome.storage.local.get(['authToken'], async (result) => {
    const AUTH_TOKEN = result.authToken || '';
    try {
      const res = await fetch(`${API_URL}/secrets`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${AUTH_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ key, value })
      });
      setOutput(await res.text());
    } catch (e) {
      setOutput(e.toString());
    }
  });
};

document.getElementById('getBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  chrome.storage.local.get(['authToken'], async (result) => {
    const AUTH_TOKEN = result.authToken || '';
    try {
      const res = await fetch(`${API_URL}/secrets/${key}`, {
        headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
      });
      setOutput(await res.text());
    } catch (e) {
      setOutput(e.toString());
    }
  });
};

document.getElementById('deleteBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  chrome.storage.local.get(['authToken'], async (result) => {
    const AUTH_TOKEN = result.authToken || '';
    try {
      const res = await fetch(`${API_URL}/secrets/${key}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
      });
      setOutput(res.status === 204 ? 'Deleted.' : await res.text());
    } catch (e) {
      setOutput(e.toString());
    }
  });
};

// On load
window.onload = loadToken;
