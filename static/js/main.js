// main.js — Combined Admin & User JS (Production-ready)
AOS.init({ duration: 450, once: true });

/* ---------- Shared Fetch Utility ---------- */
async function ph_fetchJson(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || res.statusText);
  }
  return res.json();
}

/* ---------- Utilities ---------- */
function verdictClass(verdict) {
  switch ((verdict ?? '').toLowerCase()) {
    case 'phishing': return 'bar-phish';
    case 'suspicious': return 'bar-susp';
    default: return 'bar-safe';
  }
}

function formatDomain(h) {
  if (!h) return '(unknown)';
  if (h.type === 'file' && h.uploaded_file)
    return `<span class="italic text-sm text-gray-600">file: ${h.uploaded_file}</span>`;
  return h.domain || (h.input && h.input.slice(0, 120)) || '(unknown)';
}

/* ---------- User: Scanning & History ---------- */
const scanForm = document.getElementById('scanForm');
const resultCard = document.getElementById('resultCard');
const userHistory = document.getElementById('userHistory');

function renderResult(data) {
  if (!data) return;

  const verdict = (data.verdict ?? "unknown").toUpperCase();
  const cl = verdictClass(data.verdict);
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const perModel = data.per_model || {};
  const perModelHtml = Object.entries(perModel)
    .map(([k, v]) => `<div class="text-xs text-gray-600">${k.toUpperCase()}: ${Number(v).toFixed(3)}</div>`).join('');

  const inputDisplay = data.type === 'file' && data.uploaded_file
    ? `<a href="/uploads/${encodeURIComponent(data.uploaded_file)}" class="text-blue-600 hover:underline">${data.uploaded_file}</a>`
    : (data.input || data.domain || '(unknown)');

  resultCard.innerHTML = `
    <div class="flex items-start justify-between gap-4">
      <div>
        <div class="inline-flex items-center gap-3">
          <div class="px-3 py-1 rounded text-sm font-semibold ${verdict==='PHISHING'?'text-red-600 bg-red-50':verdict==='SUSPICIOUS'?'text-yellow-600 bg-yellow-50':'text-green-600 bg-green-50'}">
            ${verdict}
          </div>
          <div class="text-sm text-gray-500">${inputDisplay}</div>
        </div>
        <div class="mt-4 text-sm text-gray-600">
          <strong>Final score:</strong> ${data.final_score ?? 'N/A'} • <strong>ML prob:</strong> ${data.ml_probability ?? 'N/A'}
        </div>
      </div>
      <div class="text-right">
        <div class="text-xs text-gray-400">Analyzed</div>
        <div class="text-sm text-gray-600">${data.timestamp ?? ''}</div>
        <div class="mt-2 text-xs text-gray-500">User: <span class="font-mono">${data.user_id ?? '(anonymous)'}</span></div>
      </div>
    </div>

    <div class="mt-4">
      <div class="w-full h-3 rounded-full overflow-hidden bg-gray-100">
        <div class="${cl}" style="width:${Math.min(100, Math.round((data.final_score || 0)*100))}%; height:100%"></div>
      </div>
    </div>

    <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <h4 class="text-sm font-semibold text-gray-700">Why this verdict?</h4>
        <ul class="list-disc pl-5 text-sm text-gray-600 mt-2">${reasons.length ? reasons.map(r=>`<li>${r}</li>`).join('') : '<li>No heuristic flags</li>'}</ul>
      </div>
      <div>
        <h4 class="text-sm font-semibold text-gray-700">Per-model probabilities</h4>
        <div class="mt-2">${perModelHtml || '<div class="text-xs text-gray-500">Not available</div>'}</div>
      </div>
    </div>

    <div class="mt-4 text-xs text-gray-400">Threshold: ${data.threshold ?? 'N/A'}</div>
  `;
  resultCard.classList.remove('hidden');
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function loadUserHistory() {
  if (!userHistory) return;
  try {
    const hist = await ph_fetchJson('/history?json=1');
    if (!Array.isArray(hist) || hist.length === 0) {
      userHistory.innerHTML = '<div class="text-sm text-gray-500">No recent scans.</div>';
      return;
    }
    userHistory.innerHTML = hist.slice(0,10).map(r => {
      const verdict = (r.verdict ?? 'unknown').toUpperCase();
      const color = verdict==='PHISHING'?'text-red-500':verdict==='SUSPICIOUS'?'text-yellow-600':'text-green-600';
      const reasons = Array.isArray(r.reasons)?r.reasons.slice(0,3).join(' • '): '';
      return `
        <div class="bg-white border rounded p-3 shadow-sm">
          <div class="flex justify-between items-center">
            <div class="text-sm text-gray-700 font-semibold">${formatDomain(r)}</div>
            <div class="text-sm ${color}">${verdict}</div>
          </div>
          <div class="text-xs text-gray-500 mt-1">${r.timestamp ?? ''}</div>
          <div class="mt-2 text-xs text-gray-500">${reasons}</div>
        </div>
      `;
    }).join('');
  } catch (err) {
    userHistory.innerHTML = `<div class="text-red-500">Failed to load history</div>`;
    console.error(err);
  }
}

/* ---------- User Scan Submit ---------- */
if (scanForm) {
  scanForm.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData(scanForm);
    try {
      const res = await fetch('/scan', { method: 'POST', body: fd });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      const d = Array.isArray(data)?data[0]:data;
      renderResult(d);
      loadUserHistory();
    } catch (err) {
      resultCard.innerHTML = `<div class="text-red-500">Scan failed: ${err.message}</div>`;
      resultCard.classList.remove('hidden');
      console.error(err);
    }
  });
}

/* ---------- Clear User History ---------- */
const clearUserBtn = document.getElementById('clearUserHistory');
if (clearUserBtn) {
  clearUserBtn.addEventListener('click', async () => {
    try {
      await ph_fetchJson('/clear_history', { method:'POST' });
      window.ph_toast('History cleared');
      loadUserHistory();
    } catch (err) { window.ph_toast('Failed to clear', 'err'); }
  });
}

/* ---------- Admin Functions ---------- */
async function adminLoadSettings() {
  try {
    const s = await ph_fetchJson('/admin/settings.json');
    document.getElementById('threshold').value = s.threshold ?? 0.55;
    document.getElementById('ml_weight').value = s.ml_weight ?? 0.9;
    document.getElementById('domainList').innerHTML = (s.trusted_domains||[]).map(d=>`<li>${d}</li>`).join('');
  } catch(err){ console.warn('No admin settings', err); }
}

async function adminLoadHistory() {
  try {
    const data = await ph_fetchJson('/admin/history.json');
    const el = document.getElementById('historyData');
    if (!el) return;
    el.textContent = JSON.stringify(data, null, 2);
  } catch(err){ console.warn('Load history failed', err); }
}

// Admin save settings
const saveSettingsBtn = document.getElementById('saveSettings');
if (saveSettingsBtn) {
  adminLoadSettings();
  saveSettingsBtn.addEventListener('click', async () => {
    const threshold = parseFloat(document.getElementById('threshold').value || 0.6);
    const ml_weight = parseFloat(document.getElementById('ml_weight').value || 0.85);
    try {
      await ph_fetchJson('/admin/save', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({threshold, ml_weight})
      });
      window.ph_toast('Settings saved');
    } catch(err){ window.ph_toast('Save failed', 'err'); }
  });
}

// Admin add domain
const addDomainBtn = document.getElementById('addDomain');
if(addDomainBtn){
  addDomainBtn.addEventListener('click', async ()=>{
    const d = document.getElementById('newDomain').value.trim();
    if(!d) return;
    try{
      await ph_fetchJson('/admin/add_domain',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({domain:d})
      });
      window.ph_toast('Domain added');
      document.getElementById('newDomain').value = '';
      adminLoadSettings();
    } catch(err){ window.ph_toast('Add domain failed','err'); }
  });
}

// Admin upload CSV
const csvForm = document.getElementById('csvForm');
if(csvForm){
  csvForm.addEventListener('submit', async e=>{
    e.preventDefault();
    const fd = new FormData(csvForm);
    try{
      await ph_fetchJson('/admin/upload_csv',{ method:'POST', body:fd });
      window.ph_toast('CSV uploaded and training started');
    } catch(err){ window.ph_toast('Upload failed','err'); }
  });
}

// Admin retrain model
const retrainBtn = document.getElementById('retrain');
if(retrainBtn){
  retrainBtn.addEventListener('click', async ()=>{
    try{
      await ph_fetchJson('/admin/retrain',{ method:'POST' });
      window.ph_toast('Model retrained');
    } catch(err){ window.ph_toast('Retrain failed','err'); }
  });
}

// Admin clear history
const clearHistoryBtn = document.getElementById('clearHistory');
if(clearHistoryBtn){
  clearHistoryBtn.addEventListener('click', async ()=>{
    try{
      await ph_fetchJson('/admin/clear_history',{ method:'POST' });
      window.ph_toast('History cleared');
      adminLoadHistory();
    } catch(err){ window.ph_toast('Clear failed','err'); }
  });
}

/* ---------- Initialize ---------- */
if(document.getElementById('userHistory')) loadUserHistory();
if(document.getElementById('historyData') || document.getElementById('threshold')){
  adminLoadHistory();
  adminLoadSettings();
}
