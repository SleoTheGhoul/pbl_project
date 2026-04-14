/**
 * ReconHub API Integration Test Suite
 * Runs tests against the live server and populates the database with real queries.
 */

const fetch = require('node-fetch');
const BASE = 'http://localhost:3000';

const tests = [
  // IP Queries (1-8)
  { id: 1, type: 'ip', q: '8.8.8.8', desc: 'Google DNS - Full IP query' },
  { id: 2, type: 'ip', q: '1.1.1.1', desc: 'Cloudflare DNS - Full IP query' },
  { id: 3, type: 'ip', q: '208.67.222.222', desc: 'OpenDNS - Full IP query' },
  { id: 4, type: 'ip', q: '9.9.9.9', desc: 'Quad9 DNS - Full IP query' },
  { id: 5, type: 'ip', q: '104.26.10.78', desc: 'Cloudflare CDN IP - Full IP query' },
  { id: 6, type: 'ip', q: '185.199.108.153', desc: 'GitHub Pages IP - Full IP query' },
  { id: 7, type: 'ip', q: '13.107.42.14', desc: 'Microsoft IP - Full IP query' },
  { id: 8, type: 'ip', q: '151.101.1.140', desc: 'Reddit CDN IP - Full IP query' },

  // Domain Queries (9-16)
  { id: 9, type: 'domain', q: 'google.com', desc: 'Google - WHOIS + crt.sh + VT' },
  { id: 10, type: 'domain', q: 'github.com', desc: 'GitHub - WHOIS + crt.sh + VT' },
  { id: 11, type: 'domain', q: 'microsoft.com', desc: 'Microsoft - WHOIS + crt.sh + VT' },
  { id: 12, type: 'domain', q: 'cloudflare.com', desc: 'Cloudflare - WHOIS + crt.sh' },
  { id: 13, type: 'domain', q: 'amazon.com', desc: 'Amazon - WHOIS + crt.sh + VT' },
  { id: 14, type: 'domain', q: 'reddit.com', desc: 'Reddit - WHOIS + crt.sh + VT' },
  { id: 15, type: 'domain', q: 'netflix.com', desc: 'Netflix - WHOIS + crt.sh + VT' },
  { id: 16, type: 'domain', q: 'twitter.com', desc: 'Twitter/X - WHOIS + crt.sh + VT' },

  // Email Queries (17-20)
  { id: 17, type: 'email', q: 'test@gmail.com', desc: 'Gmail test - Abstract API' },
  { id: 18, type: 'email', q: 'support@google.com', desc: 'Google support - Abstract API' },
  { id: 19, type: 'email', q: 'info@microsoft.com', desc: 'Microsoft - Abstract API' },
  { id: 20, type: 'email', q: 'noreply@github.com', desc: 'GitHub noreply - Abstract API' },

  // More IPs (21-25)
  { id: 21, type: 'ip', q: '76.76.21.21', desc: 'Control D DNS - Full IP query' },
  { id: 22, type: 'ip', q: '198.41.0.4', desc: 'Root DNS server A - IP query' },
  { id: 23, type: 'ip', q: '172.217.14.206', desc: 'Google server IP - Full IP query' },
  { id: 24, type: 'ip', q: '31.13.65.36', desc: 'Facebook IP - Full IP query' },
  { id: 25, type: 'ip', q: '52.84.150.11', desc: 'AWS CloudFront IP - Full IP query' },

  // More Domains (26-30)
  { id: 26, type: 'domain', q: 'apple.com', desc: 'Apple - WHOIS + crt.sh + VT' },
  { id: 27, type: 'domain', q: 'wikipedia.org', desc: 'Wikipedia - WHOIS + crt.sh + VT' },
  { id: 28, type: 'domain', q: 'linkedin.com', desc: 'LinkedIn - WHOIS + crt.sh + VT' },
  { id: 29, type: 'domain', q: 'stackoverflow.com', desc: 'StackOverflow - WHOIS + crt.sh' },
  { id: 30, type: 'domain', q: 'shopify.com', desc: 'Shopify - WHOIS + crt.sh + VT' },

  // Individual API endpoint tests (31-35)
  { id: 31, type: 'endpoint', endpoint: '/api/lookup/ip-api/8.8.8.8', desc: 'ip-api direct endpoint' },
  { id: 32, type: 'endpoint', endpoint: '/api/status', desc: 'API health check status' },
  { id: 33, type: 'endpoint', endpoint: '/api/queries', desc: 'Database query list' },
  { id: 34, type: 'endpoint', endpoint: '/api/info', desc: 'Platform info endpoint' },
  { id: 35, type: 'endpoint', endpoint: '/api/lookup/crtsh/example.com', desc: 'crt.sh subdomain lookup' },
];

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function runTest(test) {
  const start = Date.now();
  try {
    let res, data;
    if (test.type === 'endpoint') {
      res = await fetch(`${BASE}${test.endpoint}`, { timeout: 30000 });
      data = await res.json();
    } else {
      res = await fetch(`${BASE}/api/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: test.type, q: test.q })
      });
      data = await res.json();
    }

    const elapsed = Date.now() - start;
    const passed = res.ok && data.ok !== false;

    // Determine which APIs returned data
    let apisWorking = [];
    let apisFailed = [];

    if (data.result && data.result.details) {
      const details = data.result.details;
      for (const [key, val] of Object.entries(details)) {
        if (val && !val.error) apisWorking.push(key);
        else if (val && val.error) apisFailed.push(`${key}: ${val.error}`);
      }
    }

    return {
      id: test.id,
      desc: test.desc,
      passed,
      elapsed: `${elapsed}ms`,
      apisWorking: apisWorking.length > 0 ? apisWorking.join(', ') : (test.type === 'endpoint' ? 'N/A' : 'None'),
      apisFailed: apisFailed.length > 0 ? apisFailed : [],
      threat: data.result?.threat || 'N/A',
      status: res.status
    };
  } catch (e) {
    return {
      id: test.id,
      desc: test.desc,
      passed: false,
      elapsed: `${Date.now() - start}ms`,
      error: e.message,
      apisWorking: 'None',
      apisFailed: [],
      threat: 'N/A',
      status: 'ERROR'
    };
  }
}

async function main() {
  console.log('\n==========================================');
  console.log('  ReconHub API Integration Test Suite');
  console.log(`  Testing ${tests.length} queries against live APIs`);
  console.log('==========================================\n');

  // Check server is running
  try {
    await fetch(`${BASE}/api/info`);
  } catch (e) {
    console.error('❌ Server is not running! Start it with: npm start');
    process.exit(1);
  }

  const results = [];
  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    process.stdout.write(`Test #${String(test.id).padStart(2, '0')}: ${test.desc}... `);

    const result = await runTest(test);
    results.push(result);

    if (result.passed) {
      passed++;
      console.log(`✅ PASS (${result.elapsed}) [Threat: ${result.threat}] APIs: ${result.apisWorking}`);
    } else {
      failed++;
      console.log(`❌ FAIL (${result.elapsed}) ${result.error || ''}`);
      if (result.apisFailed.length > 0) {
        result.apisFailed.forEach(f => console.log(`     ↳ ${f}`));
      }
    }

    // Rate limit protection — wait between tests
    await sleep(1500);
  }

  console.log('\n==========================================');
  console.log(`  Results: ${passed} passed, ${failed} failed out of ${tests.length}`);
  console.log('==========================================');

  // Print failures summary
  if (failed > 0) {
    console.log('\n  Failed tests:');
    results.filter(r => !r.passed).forEach(r => {
      console.log(`  - Test #${r.id}: ${r.desc}`);
      if (r.error) console.log(`    Error: ${r.error}`);
      if (r.apisFailed.length > 0) r.apisFailed.forEach(f => console.log(`    API: ${f}`));
    });
  }

  // Verify database was updated
  console.log('\n  Verifying database...');
  try {
    const dbRes = await fetch(`${BASE}/api/queries`);
    const dbData = await dbRes.json();
    console.log(`  📊 Database now contains ${dbData.queries.length} records`);

    const recentCustom = dbData.queries.filter(q => q.apisUsed && q.apisUsed.length > 0);
    console.log(`  📊 Records with real API data: ${recentCustom.length}`);
  } catch (e) {
    console.log(`  ❌ Could not verify database: ${e.message}`);
  }

  console.log('\n  ✅ Test suite complete!\n');
}

main().catch(console.error);
