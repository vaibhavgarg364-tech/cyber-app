// Get backend API URL from environment variables
// In production: https://veyron-backend.onrender.com/api
// In development: http://127.0.0.1:8000/api
const PRIMARY_URL = import.meta.env.VITE_BACKEND_API_URL || 'http://127.0.0.1:8000/api';

// Fallback candidates to gracefully withstand port switches and local proxies
const CANDIDATE_URLS = [
  PRIMARY_URL,
  '/api',
  'http://127.0.0.1:8000/api',
  'http://127.0.0.1:8001/api',
  'http://localhost:8000/api',
  'http://localhost:8001/api',
].filter((u, i, arr) => arr.indexOf(u) === i);

async function parseResponse(res) {
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    let errMsg = 'Request failed. Please try again.';
    if (data?.detail) {
      if (Array.isArray(data.detail)) {
        errMsg = data.detail.map((err) => err.msg || JSON.stringify(err)).join(', ');
      } else {
        errMsg = data.detail;
      }
    }
    throw new Error(errMsg);
  }
  return data;
}

async function request(path, body) {
  let lastError = null;
  for (const base of CANDIDATE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return await parseResponse(res);
    } catch (networkErr) {
      lastError = networkErr;
      // If the error came from parseResponse (i.e. server answered with error status), do not failover
      if (
        networkErr.message &&
        !networkErr.message.includes('fetch') &&
        !networkErr.message.includes('Failed to fetch') &&
        !networkErr.message.includes('NetworkError')
      ) {
        throw networkErr;
      }
    }
  }

  console.error(`[Veyron API] Network error for ${path}:`, lastError);
  throw new Error(
    'Unable to connect to server. Please check that the backend is running and try again.'
  );
}

async function requestForm(path, formData) {
  let lastError = null;
  for (const base of CANDIDATE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: 'POST',
        body: formData,
      });
      return await parseResponse(res);
    } catch (networkErr) {
      lastError = networkErr;
      if (
        networkErr.message &&
        !networkErr.message.includes('fetch') &&
        !networkErr.message.includes('Failed to fetch') &&
        !networkErr.message.includes('NetworkError')
      ) {
        throw networkErr;
      }
    }
  }

  console.error(`[Veyron API] Network error for ${path}:`, lastError);
  throw new Error(
    'Unable to connect to server. Please check that the backend is running and try again.'
  );
}

export async function chatWithSaathi(message, history = [], language = 'English') {
  let lastError = null;
  for (const base of CANDIDATE_URLS) {
    const url = `${base}/chat`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, history, language }),
      });

      const rawText = await res.text();
      
      if (!res.ok) {
        if (res.status === 429) {
          console.warn('[CyberSaathi API] Rate limited (429)');
          throw new Error('CyberSaathi is experiencing high traffic right now. Please try again shortly.');
        }
        if (res.status >= 500) {
          console.error('[CyberSaathi API] Server error:', res.status);
          throw new Error('CyberSaathi is temporarily unavailable. Please try again in a moment.');
        }
        throw new Error('Something went wrong. Please try again.');
      }

      let data;
      try {
        data = JSON.parse(rawText);
      } catch {
        throw new Error('CyberSaathi received an unexpected response. Please try again.');
      }

      return data;
    } catch (err) {
      lastError = err;
      if (
        err.message &&
        !err.message.includes('fetch') &&
        !err.message.includes('Failed to fetch') &&
        !err.message.includes('NetworkError')
      ) {
        throw err;
      }
    }
  }

  throw new Error('Unable to reach CyberSaathi. Please check your connection and try again.');
}

export async function checkEmail(email) {
  return request('/check-email', { email });
}

export async function scanLink(url) {
  return request('/scan-link', { url });
}

export async function checkApp(appName, packageName) {
  return request('/check-app', { appName, packageName });
}

export async function detectDeepfake(fileOrUrl) {
  if (typeof fileOrUrl === 'string') {
    const form = new FormData();
    form.append('mediaUrl', fileOrUrl);
    return requestForm('/detect-deepfake', form);
  }
  const form = new FormData();
  form.append('file', fileOrUrl);
  return requestForm('/detect-deepfake', form);
}

export async function getHelplines(incidentType, userState) {
  return request('/get-helplines', { incidentType, userState });
}

export async function getCyberCell({ state, lat, lng } = {}) {
  const params = new URLSearchParams();
  if (state) params.set('state', state);
  if (typeof lat === 'number') params.set('lat', String(lat));
  if (typeof lng === 'number') params.set('lng', String(lng));
  const suffix = params.toString() ? `?${params.toString()}` : '';
  return request(`/get-cybercell${suffix}`, {});
}
