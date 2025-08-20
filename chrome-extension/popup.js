const API_URL = "http://localhost:8080/api/v1";
const AUTH_TOKEN = "foo"; // Set your token here

function setOutput(msg) {
  document.getElementById('output').textContent = msg;
}

document.getElementById('setBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  const value = document.getElementById('value').value;
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
};

document.getElementById('getBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  try {
    const res = await fetch(`${API_URL}/secrets/${key}`, {
      headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
    });
    setOutput(await res.text());
  } catch (e) {
    setOutput(e.toString());
  }
};

document.getElementById('deleteBtn').onclick = async () => {
  const key = document.getElementById('key').value;
  try {
    const res = await fetch(`${API_URL}/secrets/${key}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
    });
    setOutput(res.status === 204 ? 'Deleted.' : await res.text());
  } catch (e) {
    setOutput(e.toString());
  }
};
