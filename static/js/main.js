// main.js
AOS.init({ duration: 450, once: true });

const scanForm = document.getElementById('scanForm');
const resultCard = document.getElementById('resultCard');
const userHistory = document.getElementById('userHistory');

function verdictClass(verdict){
  return verdict==='phishing' ? 'bar-phish' : verdict==='suspicious' ? 'bar-susp' : 'bar-safe';
}

function formatDomain(h){
  if(h.type==='file' && h.uploaded_file) return `<span class="italic text-sm text-gray-600">file: ${h.uploaded_file}</span>`;
  return h.domain || (h.input?.slice(0,120)) || '(unknown)';
}

function renderResult(data){
  const cl = verdictClass(data.verdict);
  const reasons = (data.reasons || []).map(r => `<li>${r}</li>`).join('');
  const perModel = data.per_model || {};
  const perModelHtml = Object.entries(perModel).map(([k,v]) => `<div class="text-xs text-gray-600">${k.toUpperCase()}: ${v.toFixed(3)}</div>`).join('');
  const inputDisplay = data.type==='file' && data.uploaded_file ? `<a href="/uploads/${encodeURIComponent(data.uploaded_file)}" class="text-blue-600 hover:underline">${data.uploaded_file}</a>` : (data.input || data.domain || '');

  resultCard.innerHTML = `
    <div class="flex items-start justify-between gap-4">
      <div>
        <div class="inline-flex items-center gap-3">
          <div class="px-3 py-1 rounded text-sm font-semibold ${data.verdict==='phishing'?'text-red-600 bg-red-50':data.verdict==='suspicious'?'text-yellow-600 bg-yellow-50':'text-green-600 bg-green-50'}">
            ${data.verdict.toUpperCase()}
          </div>
          <div class="text-sm text-gray-500">${inputDisplay}</div>
        </div>
        <div class="mt-4 text-sm text-gray-600">
          <strong>Final score:</strong> ${data.final_score.toFixed(2)} • <strong>ML prob:</strong> ${data.ml_probability.toFixed(2)}
        </div>
      </div>
      <div class="text-right">
        <div class="text-xs text-gray-400">Analyzed</div>
        <div class="text-sm text-gray-600">${data.timestamp || ''}</div>
        <div class="mt-2 text-xs text-gray-500">User: <span class="font-mono">${data.user_id || ''}</span></div>
      </div>
    </div>

    <div class="mt-4">
      <div class="w-full h-3 rounded-full overflow-hidden bg-gray-100">
        <div class="${cl}" style="width:${Math.min(100, Math.round((data.final_score||0)*100))}%; height:100%"></div>
      </div>
    </div>

    <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <h4 class="text-sm font-semibold text-gray-700">Why this verdict?</h4>
        <ul class="list-disc pl-5 text-sm text-gray-600 mt-2">${reasons || '<li>No heuristic flags</li>'}</ul>
      </div>
      <div>
        <h4 class="text-sm font-semibold text-gray-700">Per-model probabilities</h4>
        <div class="mt-2">${perModelHtml || '<div class="text-xs text-gray-500">Not available</div>'}</div>
      </div>
    </div>

    <div class="mt-4 text-xs text-gray-400">Threshold: ${data.threshold}</div>
  `;
  resultCard.classList.remove('hidden');
  resultCard.scrollIntoView({ behavior:'smooth', block:'center' });
}

async function loadHistory(){
  try{
    const res = await fetch('/history?json=1');
    const hist = await res.json();
    if(!hist.length){ userHistory.innerHTML='<div class="text-sm text-gray-500">No recent scans.</div>'; return; }
    userHistory.innerHTML = hist.slice(0,10).map(r=>`
      <div class="bg-white border rounded p-3 shadow-sm hover:shadow-md transition">
        <div class="flex justify-between items-center">
          <div class="text-sm text-gray-700 font-semibold">${formatDomain(r)}</div>
          <div class="text-sm ${r.verdict==='phishing'?'text-red-500':r.verdict==='suspicious'?'text-yellow-600':'text-green-600'}">${r.verdict.toUpperCase()}</div>
        </div>
        <div class="text-xs text-gray-500 mt-1">${r.timestamp}</div>
        <div class="mt-2 text-xs text-gray-500">${(r.reasons||[]).slice(0,3).join(' • ')}</div>
      </div>
    `).join('');
  }catch(e){
    userHistory.innerHTML='<div class="text-red-500">Failed to load history</div>';
  }
}

scanForm.addEventListener('submit', async e=>{
  e.preventDefault();
  const fd = new FormData(scanForm);
  try{
    const res = await fetch('/scan',{ method:'POST', body: fd });
    const data = await res.json();
    const d = Array.isArray(data)?data[0]:data;
    renderResult(d);
    loadHistory();
  }catch(err){
    resultCard.innerHTML=`<div class="text-red-500">Scan failed: ${err.message}</div>`;
    resultCard.classList.remove('hidden');
  }
});

loadHistory();
