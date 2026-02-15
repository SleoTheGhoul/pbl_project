// =====================================================
// ReconHub Frontend Script
// Handles: Dashboard, Query, and Database pages
// =====================================================

document.addEventListener('DOMContentLoaded', () => {

  // --- DASHBOARD PAGE ---
  const apiStatusGrid = document.querySelector('.api-status-grid');
  if (apiStatusGrid) simulateApiStatusCheck();

  // --- QUERY PAGE ---
  const inputTabs = document.querySelector('.input-tabs');
  if (inputTabs) setupQueryTabs();

  // --- DATABASE PAGE ---
  const tbody = document.querySelector('.db-table tbody');
  if (tbody) loadDatabaseData();

});

// =====================================================
// DASHBOARD PAGE: API STATUS SIMULATION
// =====================================================
function simulateApiStatusCheck() {
  const apiItems = document.querySelectorAll('.api-status-item');

  apiItems.forEach(item => {
    const dot = item.querySelector('.status-dot');
    const label = item.querySelector('.api-status-label');
    dot.classList.add('pending');
    label.textContent = 'Checking...';
  });

  setTimeout(() => {
    apiItems.forEach((item, index) => {
      const dot = item.querySelector('.status-dot');
      const label = item.querySelector('.api-status-label');
      dot.classList.remove('pending');

      if (index % 5 === 0) {
        dot.classList.add('failed');
        label.textContent = 'Offline';
      } else {
        dot.classList.add('active');
        label.textContent = 'Active';
      }
    });
  }, 1500);
}

// =====================================================
// QUERY PAGE: INPUT TAB FUNCTIONALITY
// =====================================================
function setupQueryTabs() {
  const tabLinks = document.querySelectorAll('.input-tabs .tab-link');
  const inputField = document.querySelector('.input-area input[type="text"]');

  const placeholders = {
    'ip-tab': 'e.g., 192.168.1.1 or 8.8.8.8',
    'domain-tab': 'e.g., example.com',
    'email-tab': 'e.g., test@example.com'
  };

  tabLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();

      tabLinks.forEach(tab => tab.classList.remove('active'));
      link.classList.add('active');

      const tabId = link.id;
      if (placeholders[tabId]) {
        inputField.placeholder = placeholders[tabId];
      }
    });
  });
}

// =====================================================
// DATABASE PAGE: DYNAMIC TABLE + STATS UPDATE
// =====================================================
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
          <td><span class="source-tag">${r.source}</span></td>
          <td>${r.timestamp}</td>
        </tr>
      `).join('');

      // --- Update Stats ---
      if (totalEl) totalEl.textContent = records.length;
      if (highThreatsEl)
        highThreatsEl.textContent = records.filter(r => r.threat === 'High').length;
      if (uniqueSourcesEl) {
        const uniqueSources = new Set(records.map(r => r.source));
        uniqueSourcesEl.textContent = uniqueSources.size;
      }

      // --- Live Search ---
      const searchInput = document.querySelector('.search-bar input');
      if (searchInput) {
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
              <td><span class="source-tag">${r.source}</span></td>
              <td>${r.timestamp}</td>
            </tr>
          `).join('');
        });
      }
    })
    .catch(err => console.error('Error loading DB data:', err));
}
