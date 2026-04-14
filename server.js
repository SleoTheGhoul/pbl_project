const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
const DATABASE_FILE = path.join(__dirname, 'database.json');

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static(PUBLIC_DIR));

// ====== Default API Keys ======
const DEFAULT_KEYS = {
  abstractApi: '2ad8550cf98543a5bfb506c5cd734f19',
  ipinfo: 'fd0e59e20dd12e',
  abuseipdb: 'd62ad6105e6732deb3aec415f27751076f0148172ccf478f3782b1bba1742522ae9eea4b12f7acc1',
  whoisxml: 'at_8LbXqMOxpO3dYxLxIDDaDVjpYvBLc',
  shodan: 'L7pqOfWWozY3pNeJQ9PIK5rTADlHmvRU',
  virustotal: 'efcebd0b738964c77c1396da17280f663bc677d22d46b6a2421b1e88ccc68fb3'
};

// ====== Load / Save Settings ======
function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      return { ...DEFAULT_KEYS, ...data };
    }
  } catch (e) {
    console.error('Error loading settings:', e.message);
  }
  return { ...DEFAULT_KEYS };
}

function saveSettings(keys) {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(keys, null, 2));
    return true;
  } catch (e) {
    console.error('Error saving settings:', e.message);
    return false;
  }
}

let API_KEYS = loadSettings();

// ====== Database Persistence ======
function loadDatabase() {
  try {
    if (fs.existsSync(DATABASE_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATABASE_FILE, 'utf8'));
      console.log(`📂 Loaded ${data.queries.length} records from database.json`);
      return { queries: data.queries || [], nextId: data.nextId || data.queries.length + 1 };
    }
  } catch (e) {
    console.error('Error loading database:', e.message);
  }
  return null;
}

function saveDatabase() {
  try {
    fs.writeFileSync(DATABASE_FILE, JSON.stringify({ queries, nextId }, null, 2));
  } catch (e) {
    console.error('Error saving database:', e.message);
  }
}

// ====== Data Sets (for seed data only) ======
const commonIPs = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '4.2.2.2', '208.67.222.222'];
const commonDomains = [
  'google.com', 'facebook.com', 'github.com', 'microsoft.com', 'amazon.com',
  'apple.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'linkedin.com',
  'cloudflare.com', 'netflix.com'
];
const commonEmails = [
  'support@google.com', 'security@facebook.com', 'noreply@github.com',
  'postmaster@amazon.com', 'contact@apple.com', 'webmaster@wikipedia.org',
  'support@paypal.com', 'abuse@cloudflare.com', 'help@linkedin.com', 'info@microsoft.com'
];
const threatLevels = ['Safe', 'Low', 'Medium', 'High'];
const sources = ['Shodan', 'VirusTotal', 'AbuseIPDB', 'WHOIS', 'HaveIBeenPwned', 'IPinfo'];

// ===== Helpers =====
const padId = (n) => String(n).padStart(4, '0');
const now = () => new Date().toISOString().replace('T', ' ').split('.')[0];

function shuffleArray(array) {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ===== Initialize Database (load from file or build seed data) =====
let queries;
let nextId;

const savedDB = loadDatabase();
if (savedDB) {
  queries = savedDB.queries;
  nextId = savedDB.nextId;
} else {
  // Build seed dataset
  const allData = [
    ...commonIPs.map(ip => ({ type: 'IP', query: ip })),
    ...commonDomains.map(domain => ({ type: 'Domain', query: domain })),
    ...commonEmails.map(email => ({ type: 'Email', query: email }))
  ];

  const shuffledData = shuffleArray(allData);

  queries = shuffledData.map((item, i) => {
    const day = String((i % 28) + 1).padStart(2, '0');
    const hour = String(i % 24).padStart(2, '0');
    const minute = String((i * 7) % 60).padStart(2, '0');
    return {
      id: `#${padId(i + 1)}`,
      type: item.type,
      query: item.query,
      threat: threatLevels[Math.floor(Math.random() * threatLevels.length)],
      source: sources[Math.floor(Math.random() * sources.length)],
      timestamp: `2025-10-${day} ${hour}:${minute}`,
      apisUsed: [],
      details: null
    };
  });

  nextId = queries.length + 1;
  // Save the seed data right away
  saveDatabase();
  console.log(`🌱 Created seed database with ${queries.length} records`);
}

// ====================================================
// INDIVIDUAL API LOOKUP FUNCTIONS
// ====================================================

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return res;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// --- 1. IPinfo ---
async function lookupIPinfo(ip) {
  try {
    const res = await fetchWithTimeout(`https://ipinfo.io/${ip}?token=${API_KEYS.ipinfo}`);
    if (!res.ok) return { error: `IPinfo returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 2. AbuseIPDB ---
async function lookupAbuseIPDB(ip) {
  try {
    const res = await fetchWithTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: { 'Key': API_KEYS.abuseipdb, 'Accept': 'application/json' }
    });
    if (!res.ok) return { error: `AbuseIPDB returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 3. Shodan ---
async function lookupShodan(ip) {
  try {
    const res = await fetchWithTimeout(`https://api.shodan.io/shodan/host/${ip}?key=${API_KEYS.shodan}`);
    if (!res.ok) return { error: `Shodan returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 4. ip-api ---
async function lookupIpApi(ip) {
  try {
    const res = await fetchWithTimeout(`http://ip-api.com/json/${ip}`);
    if (!res.ok) return { error: `ip-api returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 5. VirusTotal (IP) ---
async function lookupVirusTotalIP(ip) {
  try {
    const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': API_KEYS.virustotal }
    });
    if (!res.ok) return { error: `VirusTotal returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 6. VirusTotal (Domain) ---
async function lookupVirusTotalDomain(domain) {
  try {
    const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': API_KEYS.virustotal }
    });
    if (!res.ok) return { error: `VirusTotal returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 7. WHOIS XML API ---
async function lookupWhois(domain) {
  try {
    const res = await fetchWithTimeout(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}&outputFormat=JSON&apiKey=${API_KEYS.whoisxml}`
    );
    if (!res.ok) return { error: `WHOIS returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 8. crt.sh ---
async function lookupCrtsh(domain) {
  try {
    const res = await fetchWithTimeout(`https://crt.sh/?q=%25.${domain}&output=json`, {}, 15000);
    if (!res.ok) return { error: `crt.sh returned ${res.status}` };
    const data = await res.json();
    // Deduplicate and limit
    const unique = [...new Set(data.map(e => e.name_value).flatMap(v => v.split('\n')))].filter(v => !v.startsWith('*')).slice(0, 50);
    return { subdomains: unique, total: unique.length };
  } catch (e) {
    return { error: e.message };
  }
}

// --- 9. Abstract API (Email Validation) ---
async function lookupAbstractEmail(email) {
  try {
    const res = await fetchWithTimeout(
      `https://emailvalidation.abstractapi.com/v1/?api_key=${API_KEYS.abstractApi}&email=${email}`
    );
    if (!res.ok) return { error: `Abstract API returned ${res.status}` };
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// --- 10. HIBP Pwned Passwords ---
async function lookupHIBPPassword(passwordOrHash) {
  try {
    // We accept either a raw password or a SHA-1 hash prefix
    const crypto = require('crypto');
    const sha1 = crypto.createHash('sha1').update(passwordOrHash).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);
    const res = await fetchWithTimeout(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return { error: `HIBP returned ${res.status}` };
    const text = await res.text();
    const lines = text.split('\n');
    const match = lines.find(line => line.startsWith(suffix));
    if (match) {
      const count = parseInt(match.split(':')[1].trim());
      return { found: true, count, message: `This password has been seen ${count} times in data breaches.` };
    }
    return { found: false, count: 0, message: 'This password has not been found in any known data breaches.' };
  } catch (e) {
    return { error: e.message };
  }
}

// ====================================================
// THREAT LEVEL COMPUTATION
// ====================================================
function computeThreatLevel(type, results) {
  let score = 0;

  if (type === 'IP' || type === 'ip') {
    // AbuseIPDB confidence score
    if (results.abuseipdb && results.abuseipdb.data) {
      score += results.abuseipdb.data.abuseConfidenceScore || 0;
    }
    // VirusTotal malicious detections
    if (results.virustotal && results.virustotal.data) {
      const stats = results.virustotal.data.attributes?.last_analysis_stats;
      if (stats) score += (stats.malicious || 0) * 5;
    }
  }

  if (type === 'Domain' || type === 'domain') {
    if (results.virustotal && results.virustotal.data) {
      const stats = results.virustotal.data.attributes?.last_analysis_stats;
      if (stats) score += (stats.malicious || 0) * 5;
    }
  }

  if (type === 'Email' || type === 'email') {
    if (results.abstractEmail) {
      const q = results.abstractEmail.quality_score;
      if (q !== undefined && q < 0.3) score += 30;
      if (results.abstractEmail.is_disposable_email?.value) score += 40;
    }
  }

  if (score >= 50) return 'High';
  if (score >= 20) return 'Medium';
  if (score >= 5) return 'Low';
  return 'Safe';
}

// ====================================================
// ROUTES
// ====================================================

// --- Platform Info (fast, no API calls) ---
app.get('/api/info', (req, res) => {
  res.json({
    ok: true,
    totalApis: 9,
    categories: 4,
    apiList: [
      'IPinfo', 'AbuseIPDB', 'Shodan', 'ip-api',
      'VirusTotal', 'WHOIS XML', 'crt.sh',
      'Abstract API', 'HIBP Passwords'
    ]
  });
});

// --- Settings ---
app.get('/api/settings', (req, res) => {
  // Return masked keys
  const masked = {};
  for (const [key, val] of Object.entries(API_KEYS)) {
    if (!val) { masked[key] = ''; continue; }
    masked[key] = val.substring(0, 4) + '****' + val.substring(val.length - 4);
  }
  res.json({ ok: true, keys: masked });
});

app.post('/api/settings', (req, res) => {
  const { keys } = req.body;
  if (!keys || typeof keys !== 'object') return res.status(400).json({ ok: false, error: 'Invalid keys' });
  // Only update non-empty values
  for (const [key, val] of Object.entries(keys)) {
    if (val && DEFAULT_KEYS.hasOwnProperty(key)) {
      API_KEYS[key] = val;
    }
  }
  const saved = saveSettings(API_KEYS);
  res.json({ ok: saved, message: saved ? 'Settings saved' : 'Failed to save' });
});

// --- API Health Status ---
app.get('/api/status', async (req, res) => {
  const checks = [
    { name: 'IPinfo', test: () => fetchWithTimeout(`https://ipinfo.io/8.8.8.8?token=${API_KEYS.ipinfo}`, {}, 5000) },
    { name: 'AbuseIPDB', test: () => fetchWithTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1`, { headers: { 'Key': API_KEYS.abuseipdb, 'Accept': 'application/json' } }, 5000) },
    { name: 'Shodan', test: () => fetchWithTimeout(`https://api.shodan.io/api-info?key=${API_KEYS.shodan}`, {}, 5000) },
    { name: 'ip-api', test: () => fetchWithTimeout(`http://ip-api.com/json/8.8.8.8`, {}, 5000) },
    { name: 'VirusTotal', test: () => fetchWithTimeout(`https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8`, { headers: { 'x-apikey': API_KEYS.virustotal } }, 5000) },
    { name: 'WHOIS XML', test: () => fetchWithTimeout(`https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=google.com&outputFormat=JSON&apiKey=${API_KEYS.whoisxml}`, {}, 5000) },
    // crt.sh: use a small domain to keep the check fast (avoid google.com which returns huge datasets)
    { name: 'crt.sh', test: () => fetchWithTimeout(`https://crt.sh/?q=example.com&output=json`, {}, 10000) },
    { name: 'Abstract API', test: () => fetchWithTimeout(`https://emailvalidation.abstractapi.com/v1/?api_key=${API_KEYS.abstractApi}&email=test@test.com`, {}, 5000) },
    { name: 'HIBP Passwords', test: () => fetchWithTimeout(`https://api.pwnedpasswords.com/range/5BAA6`, {}, 5000) }
  ];

  const apis = await Promise.all(checks.map(async (check) => {
    try {
      const r = await check.test();
      return { name: check.name, status: r.ok ? 'Active' : 'Error' };
    } catch (e) {
      return { name: check.name, status: 'Offline' };
    }
  }));

  res.json({ ok: true, apis });
});

// --- Individual API lookup routes ---
app.get('/api/lookup/ipinfo/:ip', async (req, res) => {
  const data = await lookupIPinfo(req.params.ip);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/abuseipdb/:ip', async (req, res) => {
  const data = await lookupAbuseIPDB(req.params.ip);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/shodan/:ip', async (req, res) => {
  const data = await lookupShodan(req.params.ip);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/ip-api/:ip', async (req, res) => {
  const data = await lookupIpApi(req.params.ip);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/virustotal/ip/:ip', async (req, res) => {
  const data = await lookupVirusTotalIP(req.params.ip);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/virustotal/domain/:domain', async (req, res) => {
  const data = await lookupVirusTotalDomain(req.params.domain);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/whois/:domain', async (req, res) => {
  const data = await lookupWhois(req.params.domain);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/crtsh/:domain', async (req, res) => {
  const data = await lookupCrtsh(req.params.domain);
  res.json({ ok: !data.error, data });
});

app.get('/api/lookup/abstract-email/:email', async (req, res) => {
  const data = await lookupAbstractEmail(req.params.email);
  res.json({ ok: !data.error, data });
});

app.post('/api/lookup/hibp-password', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: 'Missing password' });
  const data = await lookupHIBPPassword(password);
  res.json({ ok: !data.error, data });
});

// --- Get all queries ---
app.get('/api/queries', (req, res) => res.json({ ok: true, queries }));

// --- Run a unified query ---
app.post('/api/query', async (req, res) => {
  const { type, q } = req.body;
  if (!type || !q) return res.status(400).json({ ok: false, error: 'Missing query or type' });

  const timestamp = now();
  const results = {};
  const apisUsed = [];
  const queryType = type.toLowerCase();

  try {
    if (queryType === 'ip') {
      const [ipinfo, abuseipdb, shodan, ipApi, virustotal] = await Promise.allSettled([
        lookupIPinfo(q),
        lookupAbuseIPDB(q),
        lookupShodan(q),
        lookupIpApi(q),
        lookupVirusTotalIP(q)
      ]);

      if (ipinfo.status === 'fulfilled' && !ipinfo.value.error) { results.ipinfo = ipinfo.value; apisUsed.push('IPinfo'); }
      else results.ipinfo = ipinfo.value || { error: 'Failed' };

      if (abuseipdb.status === 'fulfilled' && !abuseipdb.value.error) { results.abuseipdb = abuseipdb.value; apisUsed.push('AbuseIPDB'); }
      else results.abuseipdb = abuseipdb.value || { error: 'Failed' };

      if (shodan.status === 'fulfilled' && !shodan.value.error) { results.shodan = shodan.value; apisUsed.push('Shodan'); }
      else results.shodan = shodan.value || { error: 'Failed' };

      if (ipApi.status === 'fulfilled' && !ipApi.value.error) { results.ipApi = ipApi.value; apisUsed.push('ip-api'); }
      else results.ipApi = ipApi.value || { error: 'Failed' };

      if (virustotal.status === 'fulfilled' && !virustotal.value.error) { results.virustotal = virustotal.value; apisUsed.push('VirusTotal'); }
      else results.virustotal = virustotal.value || { error: 'Failed' };

    } else if (queryType === 'domain') {
      const [whois, crtsh, virustotal] = await Promise.allSettled([
        lookupWhois(q),
        lookupCrtsh(q),
        lookupVirusTotalDomain(q)
      ]);

      if (whois.status === 'fulfilled' && !whois.value.error) { results.whois = whois.value; apisUsed.push('WHOIS'); }
      else results.whois = whois.value || { error: 'Failed' };

      if (crtsh.status === 'fulfilled' && !crtsh.value.error) { results.crtsh = crtsh.value; apisUsed.push('crt.sh'); }
      else results.crtsh = crtsh.value || { error: 'Failed' };

      if (virustotal.status === 'fulfilled' && !virustotal.value.error) { results.virustotal = virustotal.value; apisUsed.push('VirusTotal'); }
      else results.virustotal = virustotal.value || { error: 'Failed' };

    } else if (queryType === 'email') {
      const [abstractEmail] = await Promise.allSettled([
        lookupAbstractEmail(q)
      ]);

      if (abstractEmail.status === 'fulfilled' && !abstractEmail.value.error) { results.abstractEmail = abstractEmail.value; apisUsed.push('Abstract API'); }
      else results.abstractEmail = abstractEmail.value || { error: 'Failed' };
    }
  } catch (e) {
    console.error('Query error:', e.message);
  }

  const threat = computeThreatLevel(queryType, results);

  const newEntry = {
    id: `#${padId(nextId++)}`,
    type: type.toUpperCase(),
    query: q,
    threat,
    source: apisUsed.join(', ') || 'None',
    timestamp,
    apisUsed,
    details: results
  };

  queries.unshift(newEntry);

  // Persist to disk
  saveDatabase();

  res.json({ ok: true, result: newEntry });
});

// --- Fallback ---
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.listen(PORT, () => console.log(`ReconHub backend running → http://localhost:${PORT}`));
