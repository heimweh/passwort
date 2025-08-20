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

// On load
window.onload = function() {
  loadToken();

  // Theme logic
  const theme = localStorage.getItem('theme');
  setTheme(theme === 'dark');

  // Attach all button event listeners safely
  setTimeout(() => {
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    if (themeToggleBtn) themeToggleBtn.onclick = toggleTheme;

    const saveTokenBtn = document.getElementById('saveTokenBtn');
    if (saveTokenBtn) saveTokenBtn.onclick = function() {
      saveToken();
      // Hide token after saving
      const authTokenInput = document.getElementById('authToken');
      if (authTokenInput) authTokenInput.type = 'password';
    };

    // Hide token if already saved
    const authTokenInput = document.getElementById('authToken');
    chrome.storage.local.get(['authToken'], (result) => {
      if (result.authToken && authTokenInput) {
        authTokenInput.type = 'password';
      }
    });

    const setBtn = document.getElementById('setBtn');
    if (setBtn) setBtn.onclick = async () => {
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

    const getBtn = document.getElementById('getBtn');
    if (getBtn) getBtn.onclick = async () => {
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

    const deleteBtn = document.getElementById('deleteBtn');
    if (deleteBtn) deleteBtn.onclick = async () => {
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
  }, 0);
};

function setTheme(dark) {
  document.documentElement.classList.toggle('dark', dark);
  localStorage.setItem('theme', dark ? 'dark' : 'light');
  const icon = document.getElementById('themeToggleIcon');
  if (icon) icon.textContent = dark ? '☀️' : '🌙';
}

function toggleTheme() {
  setTheme(!document.documentElement.classList.contains('dark'));
}
