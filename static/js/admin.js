AOS.init({ duration: 450, once: true });

async function ph_fetchJson(url, opts){
  const res = await fetch(url, opts);
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}

// ================== Load Settings ==================
async function loadSettings(){
  try {
    const s = await ph_fetchJson('/__admin_portal__/api/settings');

    // Settings inputs
    document.getElementById('threshold').value = s.threshold ?? 0.6;
    document.getElementById('ml_weight').value = s.ml_weight ?? 0.85;

    // Trusted domains list
    const list = document.getElementById('domainList');
    if(s.trusted_domains && s.trusted_domains.length){
      list.innerHTML = s.trusted_domains.map(d => `
        <div class="flex justify-between items-center p-1 border rounded">
          <span>${d}</span>
          <button class="removeDomain bg-red-500 text-white px-2 py-0.5 rounded hover:bg-red-600" data-domain="${d}">Remove</button>
        </div>
      `).join('');
    } else {
      list.innerHTML = "<div class='text-gray-400'>No trusted domains</div>";
    }

    // Add remove button listeners
    document.querySelectorAll('.removeDomain').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const domain = e.target.dataset.domain;
        try {
          await ph_fetchJson('/__admin_portal__/api/domain/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
          });
          loadSettings();
        } catch (err) {
          alert('Failed to remove domain');
          console.error(err);
        }
      });
    });

  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

// ================== Save Settings ==================
document.getElementById('saveSettings')?.addEventListener('click', async () => {
  try {
    const current = await ph_fetchJson('/__admin_portal__/api/settings');

    const updated = {
      ...current,
      threshold: parseFloat(document.getElementById('threshold').value || 0.6),
      ml_weight: parseFloat(document.getElementById('ml_weight').value || 0.85)
    };

    await ph_fetchJson('/__admin_portal__/api/settings/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updated)
    });

    alert('Settings saved successfully');
    loadSettings();

  } catch (err) {
    alert('Save failed');
    console.error(err);
  }
});

// ================== Add Domain ==================
document.getElementById('addDomain')?.addEventListener('click', async () => {
  const domain = document.getElementById('domainInput').value.trim().toLowerCase();
  if(!domain) return;

  try {
    await ph_fetchJson('/__admin_portal__/api/domain/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });

    document.getElementById('domainInput').value = '';
    loadSettings();

  } catch (err) {
    alert('Add domain failed');
    console.error(err);
  }
});

// ================== Retrain ML ==================
document.getElementById('retrainModel')?.addEventListener('click', async () => {
  try {
    const fileInput = document.getElementById('retrainCsv');
    const fd = new FormData();
    if(fileInput?.files.length) fd.append('file', fileInput.files[0]);

    if(fd.has('file')){
      await ph_fetchJson('/__admin_portal__/api/upload_csv', { method: 'POST', body: fd });
    }

    await ph_fetchJson('/__admin_portal__/api/retrain', { method: 'POST' });
    alert('Model retrained');

  } catch (err) {
    alert('Retrain failed');
    console.error(err);
  }
});

// ================== Load History ==================
async function loadHistory(){
  try {
    const res = await ph_fetchJson('/history?json=1');
    const list = document.getElementById('historyList');

    if(res.length){
      list.innerHTML = res.map(r => `
        <div class="p-2 border rounded">
          <span class="font-semibold">${r.input || r.domain || 'N/A'}</span> — 
          <span class="italic">${r.verdict || r.final_score || 'Unknown'}</span>
        </div>
      `).join('');
    } else {
      list.innerHTML = "<div class='text-gray-400'>No history yet</div>";
    }

  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

// ================== Clear History ==================
document.getElementById('clearAll')?.addEventListener('click', async () => {
  if(!confirm('Clear all history?')) return;

  try {
    await ph_fetchJson('/__admin_portal__/api/history/clear', { method: 'POST' });
    loadHistory();
  } catch (err) {
    alert('Clear failed');
    console.error(err);
  }
});

// ================== Initial Load ==================
loadSettings();
loadHistory();
