const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static(PUBLIC_DIR));

// ====== Data Sets ======
const commonIPs = [
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '4.2.2.2', '208.67.222.222'
];

const commonDomains = [
  'google.com','facebook.com','github.com','microsoft.com','amazon.com',
  'apple.com','stackoverflow.com','wikipedia.org','reddit.com','linkedin.com',
  'cloudflare.com','netflix.com'
];

const commonEmails = [
  'support@google.com','security@facebook.com','noreply@github.com',
  'postmaster@amazon.com','contact@apple.com','webmaster@wikipedia.org',
  'support@paypal.com','abuse@cloudflare.com','help@linkedin.com','info@microsoft.com'
];

const threatLevels = ['Safe', 'Low', 'Medium', 'High'];
const sources = ['Shodan', 'VirusTotal', 'AbuseIPDB', 'WHOIS', 'HaveIBeenPwned', 'IPinfo'];

// ===== Helpers =====
const padId = (n) => String(n).padStart(4, '0');
const now = () => new Date().toISOString().replace('T', ' ').split('.')[0];

// Fisher-Yates shuffle
function shuffleArray(array) {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ===== Build Dataset =====
const allData = [
  ...commonIPs.map(ip => ({ type: 'IP', query: ip })),
  ...commonDomains.map(domain => ({ type: 'Domain', query: domain })),
  ...commonEmails.map(email => ({ type: 'Email', query: email }))
];

// Randomize order
const shuffledData = shuffleArray(allData);

let queries = shuffledData.map((item, i) => {
  const day = String((i % 28) + 1).padStart(2, '0');
  const hour = String(i % 24).padStart(2, '0');
  const minute = String((i * 7) % 60).padStart(2, '0');

  return {
    id: `#${padId(i + 1)}`,
    type: item.type,
    query: item.query,
    threat: threatLevels[Math.floor(Math.random() * threatLevels.length)],
    source: sources[Math.floor(Math.random() * sources.length)],
    timestamp: `2025-10-${day} ${hour}:${minute}`
  };
});

let nextId = queries.length + 1;

// ===== Routes =====

// --- API Status ---
app.get('/api/status', (req, res) => {
  const apis = [
    'Shodan', 'VirusTotal', 'IPinfo', 'AbuseIPDB',
    'SecurityTrails', 'Hunter.io', 'GreyNoise', 'WHOIS'
  ].map(name => {
    const r = Math.random();
    let status = 'Active';
    if (r < 0.15) status = 'Checking...';
    else if (r < 0.2) status = 'Offline';
    return { name, status };
  });
  res.json({ ok: true, apis });
});

// --- Get all queries ---
app.get('/api/queries', (req, res) => res.json({ ok: true, queries }));

// --- Run a query ---
app.post('/api/query', (req, res) => {
  const { type, q } = req.body;
  if (!type || !q) return res.status(400).json({ ok: false, error: 'Missing query or type' });

  const timestamp = now();
  const threat = threatLevels[Math.floor(Math.random() * threatLevels.length)];
  const newEntry = {
    id: `#${padId(nextId++)}`,
    type: type.toUpperCase(),
    query: q,
    threat,
    source: sources[Math.floor(Math.random() * sources.length)],
    timestamp
  };

  queries.unshift(newEntry);
  res.json({ ok: true, result: newEntry });
});

// --- Fallback ---
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.listen(PORT, () => console.log(`ReconHub backend running → http://localhost:${PORT}`));
