/* CyberShield — Main JS */

// ── Upload Zone Drag & Drop ──────────────────────────────────────────────────
const uploadZone = document.getElementById('upload-zone');
const fileInput  = document.getElementById('file-input');
const fileList   = document.getElementById('file-list');
const scanSubmit = document.getElementById('scan-submit');

if (uploadZone && fileInput) {
  uploadZone.addEventListener('click', () => fileInput.click());

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
  });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    const dt = new DataTransfer();
    [...e.dataTransfer.files].forEach(f => dt.items.add(f));
    fileInput.files = dt.files;
    updateFileList(fileInput.files);
  });

  fileInput.addEventListener('change', () => updateFileList(fileInput.files));
}

function updateFileList(files) {
  if (!fileList) return;
  fileList.innerHTML = '';
  [...files].forEach(f => {
    const chip = document.createElement('span');
    chip.className = 'file-chip';
    chip.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path></svg> ${f.name}`;
    fileList.appendChild(chip);
  });
  if (scanSubmit) scanSubmit.disabled = files.length === 0;
}

// ── Loading Overlay ──────────────────────────────────────────────────────────
const loadingOverlay = document.getElementById('loading-overlay');

function showLoading(message = 'Scanning URL...') {
  if (!loadingOverlay) return;
  const txt = loadingOverlay.querySelector('.loading-text');
  if (txt) txt.textContent = message;
  loadingOverlay.classList.add('show');
}
function hideLoading() {
  if (loadingOverlay) loadingOverlay.classList.remove('show');
}

// ── Form submissions with loading state ──────────────────────────────────────
const urlForm = document.getElementById('url-scan-form');
if (urlForm) {
  urlForm.addEventListener('submit', () => showLoading('Scanning URL — running ML model + threat intelligence checks...'));
}

const qrForm = document.getElementById('qr-scan-form');
if (qrForm) {
  qrForm.addEventListener('submit', () => showLoading('Decoding QR code and scanning embedded URL...'));
}

// ── Risk Score Color Helper ──────────────────────────────────────────────────
function riskClass(score) {
  if (score <= 20)  return 'risk-0-20';
  if (score <= 40)  return 'risk-21-40';
  if (score <= 60)  return 'risk-41-60';
  if (score <= 80)  return 'risk-61-80';
  return 'risk-81-100';
}

// ── Apply risk colors to all risk circles on page load ───────────────────────
document.querySelectorAll('.risk-circle[data-score]').forEach(el => {
  const score = parseInt(el.dataset.score, 10);
  el.classList.add(riskClass(score));
});

// ── Animate progress bars on page load ──────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    document.querySelectorAll('.score-bar[data-width]').forEach(bar => {
      bar.style.width = bar.dataset.width + '%';
    });
    document.querySelectorAll('.progress-bar[data-width]').forEach(bar => {
      bar.style.width = bar.dataset.width + '%';
    });
    document.querySelectorAll('.donut-bar[data-width]').forEach(bar => {
      bar.style.width = bar.dataset.width + '%';
    });
  }, 100);
});

// ── Delete scan from history ──────────────────────────────────────────────────
function deleteScan(scanId, btn) {
  if (!confirm('Delete this scan from history?')) return;
  fetch(`/api/delete/${scanId}/`, { method: 'DELETE', headers: { 'X-CSRFToken': getCsrf() } })
    .then(r => r.json())
    .then(d => { if (d.success) btn.closest('tr')?.remove(); })
    .catch(() => alert('Delete failed'));
}

function getCsrf() {
  const el = document.querySelector('[name=csrfmiddlewaretoken]');
  return el ? el.value : '';
}

// ── Sample URL chips ─────────────────────────────────────────────────────────
document.querySelectorAll('.sample-url').forEach(chip => {
  chip.addEventListener('click', () => {
    const input = document.getElementById('url-input');
    if (input) { input.value = chip.dataset.url; input.focus(); }
  });
});
