// =====================================================
// ReconHub Frontend Script
// Handles: Dashboard, Query, Database, and APIs pages
// =====================================================

document.addEventListener('DOMContentLoaded', () => {

  // --- DASHBOARD PAGE ---
  const apiStatusGrid = document.getElementById('api-status-grid');
  if (apiStatusGrid) loadApiStatus();

  const recentQueriesList = document.getElementById('recent-queries-list');
  if (recentQueriesList) loadDashboardData();

  // --- QUERY PAGE ---
  const inputTabs = document.querySelector('.input-tabs');
  if (inputTabs) setupQueryPage();

  // --- DATABASE PAGE ---
  const tbody = document.querySelector('.db-table tbody');
  if (tbody) loadDatabaseData();

  // --- APIS PAGE ---
  const apiCardsGrid = document.getElementById('api-cards-container');
  if (apiCardsGrid) loadApisPageStatus();

  // --- SETTINGS PAGE ---
  const settingsForm = document.getElementById('settings-form');
  if (settingsForm) setupSettingsPage();
});

// =====================================================
// DASHBOARD PAGE
// =====================================================
async function loadApiStatus() {
  const grid = document.getElementById('api-status-grid');
  if (!grid) return;

  grid.innerHTML = '<div class="loading-indicator"><i class="fas fa-spinner fa-spin"></i> Checking API status...</div>';

  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (!data.ok) return;

    grid.innerHTML = data.apis.map(api => {
      const statusClass = api.status === 'Active' ? 'active' : api.status === 'Offline' ? 'failed' : 'pending';
      return `
        <div class="api-status-item">
          <div class="status-dot ${statusClass}"></div>
          <div class="api-status-info">
            <span class="api-status-title">${api.name}</span>
            <span class="api-status-label">${api.status}</span>
          </div>
        </div>
      `;
    }).join('');
  } catch (e) {
    grid.innerHTML = '<div class="loading-indicator error">Failed to check API status</div>';
  }
}

async function loadDashboardData() {
  try {
    const res = await fetch('/api/queries');
    const data = await res.json();
    if (!data.ok) return;

    const records = data.queries;

    // Update stat cards
    const totalEl = document.getElementById('stat-total-queries');
    const apisEl = document.getElementById('stat-active-apis');
    const threatsEl = document.getElementById('stat-threats');
    const dbEl = document.getElementById('stat-db-records');

    if (totalEl) totalEl.textContent = records.length.toLocaleString();
    if (dbEl) dbEl.textContent = records.length.toLocaleString();
    if (threatsEl) threatsEl.textContent = records.filter(r => r.threat === 'High').length;

    // Set active APIs count immediately from the fast /api/info endpoint
    try {
      const infoRes = await fetch('/api/info');
      const infoData = await infoRes.json();
      if (apisEl && infoData.ok) {
        apisEl.textContent = infoData.totalApis;
      }
    } catch (e) {
      if (apisEl) apisEl.textContent = '9';
    }

    // Recent queries
    const list = document.getElementById('recent-queries-list');
    if (list) {
      const recent = records.slice(0, 5);
      list.innerHTML = recent.map(r => `
        <div class="query-item">
          <div class="query-info">
            <span class="type-tag">${r.type}</span>
            <span class="query-target">${r.query}</span>
          </div>
          <div class="query-status">
            <span class="tag tag-${r.threat.toLowerCase()}">
              <i class="fas fa-${r.threat === 'Safe' ? 'check-circle' : r.threat === 'High' ? 'exclamation-triangle' : 'shield-alt'}"></i>
              ${r.threat}${r.threat === 'Safe' ? '' : ' Risk'}
            </span>
            <span class="query-time">${r.timestamp}</span>
          </div>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Dashboard data error:', e);
  }
}


// =====================================================
// QUERY PAGE
// =====================================================
function setupQueryPage() {
  const tabLinks = document.querySelectorAll('.input-tabs .tab-link');
  const inputField = document.getElementById('query-input');
  const queryButton = document.getElementById('query-button');
  const buttonText = document.getElementById('query-button-text');
  const helperText = document.querySelector('.input-helper');

  const config = {
    ip: {
      placeholder: 'e.g., 8.8.8.8 or 1.1.1.1',
      button: 'Query IP',
      helper: 'Query IP reputation, geolocation, ASN, and open ports via IPinfo, AbuseIPDB, Shodan, ip-api, and VirusTotal'
    },
    domain: {
      placeholder: 'e.g., google.com or github.com',
      button: 'Query Domain',
      helper: 'Query domain WHOIS info, subdomains via crt.sh, and malware analysis via VirusTotal'
    },
    email: {
      placeholder: 'e.g., test@example.com',
      button: 'Query Email',
      helper: 'Validate email via Abstract API, check reputation via EmailRep.io'
    }
  };

  let currentType = 'ip';

  tabLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      tabLinks.forEach(t => t.classList.remove('active'));
      link.classList.add('active');
      currentType = link.dataset.type;
      const cfg = config[currentType];
      if (inputField) inputField.placeholder = cfg.placeholder;
      if (buttonText) buttonText.textContent = cfg.button;
      if (helperText) helperText.textContent = cfg.helper;
    });
  });

  // Query button
  if (queryButton) {
    queryButton.addEventListener('click', () => runQuery(currentType));
  }

  // Enter key
  if (inputField) {
    inputField.addEventListener('keydown', e => {
      if (e.key === 'Enter') runQuery(currentType);
    });
  }
}

async function runQuery(type) {
  const inputField = document.getElementById('query-input');
  const resultsPanel = document.getElementById('results-panel');
  const queryButton = document.getElementById('query-button');
  const buttonText = document.getElementById('query-button-text');

  const q = inputField?.value?.trim();
  if (!q) return;

  // Show loading
  if (queryButton) queryButton.disabled = true;
  if (buttonText) buttonText.textContent = 'Querying...';
  if (resultsPanel) {
    resultsPanel.style.display = 'block';
    resultsPanel.innerHTML = `
      <div class="results-loading">
        <div class="spinner"></div>
        <p>Querying ${type.toUpperCase()} intelligence sources for <strong>${q}</strong>...</p>
        <p class="loading-sub">This may take a few seconds as we query multiple APIs simultaneously.</p>
      </div>
    `;
  }

  try {
    const res = await fetch('/api/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, q })
    });
    const data = await res.json();

    if (data.ok) {
      renderResults(type, data.result, resultsPanel);
    } else {
      resultsPanel.innerHTML = `<div class="results-error"><i class="fas fa-exclamation-circle"></i> Error: ${data.error}</div>`;
    }
  } catch (e) {
    if (resultsPanel) {
      resultsPanel.innerHTML = `<div class="results-error"><i class="fas fa-exclamation-circle"></i> Network error: ${e.message}</div>`;
    }
  }

  if (queryButton) queryButton.disabled = false;
  const cfg = { ip: 'Query IP', domain: 'Query Domain', email: 'Query Email' };
  if (buttonText) buttonText.textContent = cfg[type] || 'Query';
}

// =====================================================
// RENDER RESULT CARDS
// =====================================================
function renderResults(type, result, panel) {
  if (!panel || !result.details) return;

  const d = result.details;
  let html = `
    <div class="results-header">
      <div class="results-header-info">
        <h3><i class="fas fa-check-circle"></i> Results for <span class="highlight">${result.query}</span></h3>
        <span class="tag tag-${result.threat.toLowerCase()}">${result.threat}${result.threat === 'Safe' ? '' : ' Risk'}</span>
      </div>
      <div class="results-meta">
        <span><i class="fas fa-clock"></i> ${result.timestamp}</span>
        <span><i class="fas fa-plug"></i> ${result.apisUsed?.join(', ') || 'None'}</span>
      </div>
    </div>
    <div class="results-grid">
  `;

  if (type === 'ip') {
    // IPinfo card
    if (d.ipinfo) {
      const ip = d.ipinfo;
      html += buildCard('IPinfo — Geolocation', 'fa-map-marker-alt', ip.error ? `<p class="api-error">${ip.error}</p>` : `
        <div class="result-row"><span class="label">IP</span><span class="value">${ip.ip || '-'}</span></div>
        <div class="result-row"><span class="label">City</span><span class="value">${ip.city || '-'}</span></div>
        <div class="result-row"><span class="label">Region</span><span class="value">${ip.region || '-'}</span></div>
        <div class="result-row"><span class="label">Country</span><span class="value">${ip.country || '-'}</span></div>
        <div class="result-row"><span class="label">Org</span><span class="value">${ip.org || '-'}</span></div>
        <div class="result-row"><span class="label">Timezone</span><span class="value">${ip.timezone || '-'}</span></div>
        <div class="result-row"><span class="label">Location</span><span class="value">${ip.loc || '-'}</span></div>
      `);
    }

    // AbuseIPDB card
    if (d.abuseipdb) {
      const ab = d.abuseipdb;
      html += buildCard('AbuseIPDB — Threat Intel', 'fa-shield-alt', ab.error ? `<p class="api-error">${ab.error}</p>` : `
        <div class="result-row"><span class="label">Abuse Score</span><span class="value threat-score">${ab.data?.abuseConfidenceScore ?? '-'}%</span></div>
        <div class="result-row"><span class="label">ISP</span><span class="value">${ab.data?.isp || '-'}</span></div>
        <div class="result-row"><span class="label">Domain</span><span class="value">${ab.data?.domain || '-'}</span></div>
        <div class="result-row"><span class="label">Usage Type</span><span class="value">${ab.data?.usageType || '-'}</span></div>
        <div class="result-row"><span class="label">Country</span><span class="value">${ab.data?.countryCode || '-'}</span></div>
        <div class="result-row"><span class="label">Total Reports</span><span class="value">${ab.data?.totalReports ?? '-'}</span></div>
        <div class="result-row"><span class="label">Whitelisted</span><span class="value">${ab.data?.isWhitelisted ? 'Yes' : 'No'}</span></div>
      `);
    }

    // Shodan card
    if (d.shodan) {
      const sh = d.shodan;
      html += buildCard('Shodan — Network Info', 'fa-server', sh.error ? `<p class="api-error">${sh.error}</p>` : `
        <div class="result-row"><span class="label">OS</span><span class="value">${sh.os || '-'}</span></div>
        <div class="result-row"><span class="label">Ports</span><span class="value">${(sh.ports || []).join(', ') || '-'}</span></div>
        <div class="result-row"><span class="label">Hostnames</span><span class="value">${(sh.hostnames || []).join(', ') || '-'}</span></div>
        <div class="result-row"><span class="label">Org</span><span class="value">${sh.org || '-'}</span></div>
        <div class="result-row"><span class="label">ISP</span><span class="value">${sh.isp || '-'}</span></div>
        <div class="result-row"><span class="label">Vulns</span><span class="value">${sh.vulns ? Object.keys(sh.vulns).join(', ') : 'None'}</span></div>
      `);
    }

    // ip-api card
    if (d.ipApi) {
      const ia = d.ipApi;
      html += buildCard('ip-api — Geolocation & ISP', 'fa-globe', ia.error ? `<p class="api-error">${ia.error}</p>` : `
        <div class="result-row"><span class="label">Country</span><span class="value">${ia.country || '-'}</span></div>
        <div class="result-row"><span class="label">Region</span><span class="value">${ia.regionName || '-'}</span></div>
        <div class="result-row"><span class="label">City</span><span class="value">${ia.city || '-'}</span></div>
        <div class="result-row"><span class="label">ISP</span><span class="value">${ia.isp || '-'}</span></div>
        <div class="result-row"><span class="label">AS</span><span class="value">${ia.as || '-'}</span></div>
        <div class="result-row"><span class="label">Lat/Lon</span><span class="value">${ia.lat || '-'}, ${ia.lon || '-'}</span></div>
      `);
    }

    // VirusTotal card
    if (d.virustotal) {
      const vt = d.virustotal;
      const stats = vt.data?.attributes?.last_analysis_stats;
      html += buildCard('VirusTotal — Malware Detection', 'fa-virus', vt.error ? `<p class="api-error">${vt.error}</p>` : `
        <div class="result-row"><span class="label">Malicious</span><span class="value threat-score">${stats?.malicious ?? '-'}</span></div>
        <div class="result-row"><span class="label">Suspicious</span><span class="value">${stats?.suspicious ?? '-'}</span></div>
        <div class="result-row"><span class="label">Harmless</span><span class="value">${stats?.harmless ?? '-'}</span></div>
        <div class="result-row"><span class="label">Undetected</span><span class="value">${stats?.undetected ?? '-'}</span></div>
        <div class="result-row"><span class="label">Network</span><span class="value">${vt.data?.attributes?.network || '-'}</span></div>
        <div class="result-row"><span class="label">Owner</span><span class="value">${vt.data?.attributes?.as_owner || '-'}</span></div>
      `);
    }

  } else if (type === 'domain') {
    // WHOIS card
    if (d.whois) {
      const w = d.whois;
      const wr = w.WhoisRecord;
      html += buildCard('WHOIS — Domain Registration', 'fa-id-card', w.error ? `<p class="api-error">${w.error}</p>` : `
        <div class="result-row"><span class="label">Domain</span><span class="value">${wr?.domainName || '-'}</span></div>
        <div class="result-row"><span class="label">Registrar</span><span class="value">${wr?.registrarName || '-'}</span></div>
        <div class="result-row"><span class="label">Created</span><span class="value">${wr?.createdDate || '-'}</span></div>
        <div class="result-row"><span class="label">Updated</span><span class="value">${wr?.updatedDate || '-'}</span></div>
        <div class="result-row"><span class="label">Expires</span><span class="value">${wr?.expiresDate || '-'}</span></div>
        <div class="result-row"><span class="label">Name Servers</span><span class="value">${wr?.nameServers?.hostNames?.join(', ') || '-'}</span></div>
        <div class="result-row"><span class="label">Registrant</span><span class="value">${wr?.registrant?.organization || wr?.registrant?.name || '-'}</span></div>
        <div class="result-row"><span class="label">Status</span><span class="value">${wr?.status || '-'}</span></div>
      `);
    }

    // crt.sh card
    if (d.crtsh) {
      const c = d.crtsh;
      html += buildCard('crt.sh — Subdomains', 'fa-sitemap', c.error ? `<p class="api-error">${c.error}</p>` : `
        <div class="result-row"><span class="label">Total Found</span><span class="value">${c.total || 0}</span></div>
        <div class="subdomain-list">${(c.subdomains || []).slice(0, 20).map(s => `<span class="subdomain-tag">${s}</span>`).join('')}${c.total > 20 ? `<span class="subdomain-more">...and ${c.total - 20} more</span>` : ''}</div>
      `);
    }

    // VirusTotal domain card
    if (d.virustotal) {
      const vt = d.virustotal;
      const stats = vt.data?.attributes?.last_analysis_stats;
      html += buildCard('VirusTotal — Domain Analysis', 'fa-virus', vt.error ? `<p class="api-error">${vt.error}</p>` : `
        <div class="result-row"><span class="label">Malicious</span><span class="value threat-score">${stats?.malicious ?? '-'}</span></div>
        <div class="result-row"><span class="label">Suspicious</span><span class="value">${stats?.suspicious ?? '-'}</span></div>
        <div class="result-row"><span class="label">Harmless</span><span class="value">${stats?.harmless ?? '-'}</span></div>
        <div class="result-row"><span class="label">Undetected</span><span class="value">${stats?.undetected ?? '-'}</span></div>
        <div class="result-row"><span class="label">Reputation</span><span class="value">${vt.data?.attributes?.reputation ?? '-'}</span></div>
        <div class="result-row"><span class="label">Categories</span><span class="value">${vt.data?.attributes?.categories ? Object.values(vt.data.attributes.categories).join(', ') : '-'}</span></div>
      `);
    }

  } else if (type === 'email') {
    // Abstract API card
    if (d.abstractEmail) {
      const ae = d.abstractEmail;
      html += buildCard('Abstract API — Email Validation', 'fa-envelope-open-text', ae.error ? `<p class="api-error">${ae.error}</p>` : `
        <div class="result-row"><span class="label">Email</span><span class="value">${ae.email || '-'}</span></div>
        <div class="result-row"><span class="label">Deliverability</span><span class="value">${ae.deliverability || '-'}</span></div>
        <div class="result-row"><span class="label">Quality Score</span><span class="value">${ae.quality_score !== undefined ? (ae.quality_score * 100).toFixed(0) + '%' : '-'}</span></div>
        <div class="result-row"><span class="label">Valid Format</span><span class="value">${ae.is_valid_format?.value !== undefined ? (ae.is_valid_format.value ? '✅ Yes' : '❌ No') : '-'}</span></div>
        <div class="result-row"><span class="label">Free Provider</span><span class="value">${ae.is_free_email?.value !== undefined ? (ae.is_free_email.value ? 'Yes' : 'No') : '-'}</span></div>
        <div class="result-row"><span class="label">Disposable</span><span class="value">${ae.is_disposable_email?.value !== undefined ? (ae.is_disposable_email.value ? '⚠️ Yes' : 'No') : '-'}</span></div>
        <div class="result-row"><span class="label">MX Found</span><span class="value">${ae.is_mx_found?.value !== undefined ? (ae.is_mx_found.value ? '✅ Yes' : '❌ No') : '-'}</span></div>
        <div class="result-row"><span class="label">SMTP Valid</span><span class="value">${ae.is_smtp_valid?.value !== undefined ? (ae.is_smtp_valid.value ? '✅ Yes' : '❌ No') : '-'}</span></div>
      `);
    }
  }

  html += '</div>';
  panel.innerHTML = html;
}

function buildCard(title, icon, content) {
  return `
    <div class="result-card">
      <div class="result-card-header">
        <i class="fas ${icon}"></i>
        <span>${title}</span>
      </div>
      <div class="result-card-body">
        ${content}
      </div>
    </div>
  `;
}


// =====================================================
// DATABASE PAGE
// =====================================================
let dbAutoRefresh = null;

function loadDatabaseData() {
  fetch('/api/queries')
    .then(res => res.json())
    .then(data => {
      if (!data.ok) return console.error('Failed to load data');

      const records = data.queries;
      const tbody = document.querySelector('.db-table tbody');
      const totalEl = document.getElementById('total-records');
      const highThreatsEl = document.getElementById('high-threats');
      const uniqueSourcesEl = document.getElementById('unique-sources');

      // --- Populate Table ---
      tbody.innerHTML = records.map(r => `
        <tr>
          <td>${r.id}</td>
          <td><span class="type-tag">${r.type}</span></td>
          <td>${r.query}</td>
          <td>
            <span class="tag tag-${r.threat.toLowerCase()}">
              ${r.threat}${r.threat === 'Safe' ? '' : ' Risk'}
            </span>
          </td>
          <td><span class="source-tag">${r.source || (r.apisUsed || []).join(', ') || '-'}</span></td>
          <td>${r.timestamp}</td>
          <td>${r.details ? '<button class="details-btn" onclick="toggleDetails(this)"><i class="fas fa-chevron-down"></i></button>' : '-'}</td>
        </tr>
        ${r.details ? `<tr class="details-row" style="display:none;"><td colspan="7"><pre class="details-pre">${JSON.stringify(r.details, null, 2)}</pre></td></tr>` : ''}
      `).join('');

      // --- Update Stats ---
      if (totalEl) totalEl.textContent = records.length;
      if (highThreatsEl) highThreatsEl.textContent = records.filter(r => r.threat === 'High').length;
      if (uniqueSourcesEl) {
        const allSources = new Set();
        records.forEach(r => {
          if (r.apisUsed) r.apisUsed.forEach(s => allSources.add(s));
          else if (r.source) r.source.split(', ').forEach(s => allSources.add(s));
        });
        uniqueSourcesEl.textContent = allSources.size;
      }

      // --- Live Search ---
      const searchInput = document.querySelector('.search-bar input');
      if (searchInput && !searchInput.dataset.bound) {
        searchInput.dataset.bound = 'true';
        searchInput.addEventListener('input', e => {
          const term = e.target.value.toLowerCase();
          const filtered = records.filter(r =>
            Object.values(r).some(val => String(val).toLowerCase().includes(term))
          );
          tbody.innerHTML = filtered.map(r => `
            <tr>
              <td>${r.id}</td>
              <td><span class="type-tag">${r.type}</span></td>
              <td>${r.query}</td>
              <td>
                <span class="tag tag-${r.threat.toLowerCase()}">
                  ${r.threat}${r.threat === 'Safe' ? '' : ' Risk'}
                </span>
              </td>
              <td><span class="source-tag">${r.source || (r.apisUsed || []).join(', ') || '-'}</span></td>
              <td>${r.timestamp}</td>
              <td>${r.details ? '<button class="details-btn" onclick="toggleDetails(this)"><i class="fas fa-chevron-down"></i></button>' : '-'}</td>
            </tr>
            ${r.details ? `<tr class="details-row" style="display:none;"><td colspan="7"><pre class="details-pre">${JSON.stringify(r.details, null, 2)}</pre></td></tr>` : ''}
          `).join('');
        });
      }
    })
    .catch(err => console.error('Error loading DB data:', err));
}

// Toggle details row
function toggleDetails(btn) {
  const detailsRow = btn.closest('tr').nextElementSibling;
  if (detailsRow && detailsRow.classList.contains('details-row')) {
    const isHidden = detailsRow.style.display === 'none';
    detailsRow.style.display = isHidden ? 'table-row' : 'none';
    btn.querySelector('i').className = isHidden ? 'fas fa-chevron-up' : 'fas fa-chevron-down';
  }
}

// Auto-refresh for database
function toggleAutoRefresh() {
  const btn = document.getElementById('auto-refresh-btn');
  if (dbAutoRefresh) {
    clearInterval(dbAutoRefresh);
    dbAutoRefresh = null;
    if (btn) { btn.classList.remove('active'); btn.innerHTML = '<i class="fas fa-sync-alt"></i><span>Auto-Refresh: Off</span>'; }
  } else {
    dbAutoRefresh = setInterval(loadDatabaseData, 10000);
    if (btn) { btn.classList.add('active'); btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i><span>Auto-Refresh: On</span>'; }
  }
}


// =====================================================
// APIS PAGE - Live Status
// =====================================================
async function loadApisPageStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (!data.ok) return;

    data.apis.forEach(api => {
      const dot = document.querySelector(`.api-card[data-api="${api.name}"] .status-dot`);
      if (dot) {
        dot.classList.remove('active', 'pending', 'failed');
        dot.classList.add(api.status === 'Active' ? 'active' : api.status === 'Offline' ? 'failed' : 'pending');
      }
      const statusLabel = document.querySelector(`.api-card[data-api="${api.name}"] .api-live-status`);
      if (statusLabel) statusLabel.textContent = api.status;
    });
  } catch (e) {
    console.error('API status check failed:', e);
  }
}


// =====================================================
// SETTINGS PAGE
// =====================================================
async function setupSettingsPage() {
  const form = document.getElementById('settings-form');
  const statusEl = document.getElementById('settings-status');

  // Load current keys
  try {
    const res = await fetch('/api/settings');
    const data = await res.json();
    if (data.ok) {
      Object.entries(data.keys).forEach(([key, val]) => {
        const input = document.getElementById(`key-${key}`);
        if (input) input.placeholder = val || 'Not set';
      });
    }
  } catch (e) { /* ignore */ }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const keys = {};
    const inputs = form.querySelectorAll('input[data-key]');
    inputs.forEach(input => {
      if (input.value.trim()) keys[input.dataset.key] = input.value.trim();
    });

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keys })
      });
      const data = await res.json();
      if (statusEl) {
        statusEl.textContent = data.ok ? '✅ Settings saved successfully!' : '❌ Failed to save settings';
        statusEl.className = data.ok ? 'status-msg success' : 'status-msg error';
        setTimeout(() => statusEl.textContent = '', 3000);
      }
    } catch (err) {
      if (statusEl) { statusEl.textContent = '❌ Network error'; statusEl.className = 'status-msg error'; }
    }
  });
}

// Make toggleDetails and toggleAutoRefresh globally accessible
window.toggleDetails = toggleDetails;
window.toggleAutoRefresh = toggleAutoRefresh;
