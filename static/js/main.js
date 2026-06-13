const STEPS = [
  { id: 's1', label: 'Resolving target',        sub: 'DNS lookup & IP resolution' },
  { id: 's2', label: 'Scanning ports',           sub: 'Threading 200 concurrent probes' },
  { id: 's3', label: 'Analysing vulnerabilities',sub: 'CVE matching + ML classification' },
  { id: 's4', label: 'Threat intelligence',      sub: 'Checking blacklists & geolocation' },
  { id: 's5', label: 'Compliance mapping',       sub: 'Evaluating OWASP Top 10 controls' },
  { id: 's6', label: 'Generating report',        sub: 'Building PDF intelligence report' },
];

let _stepIdx = 0;

function _advanceStep(msgIndex) {
  const idx = Math.min(Math.floor(msgIndex / 1.5), STEPS.length - 1);
  if (idx > _stepIdx) {
    const prev = document.getElementById(STEPS[_stepIdx]?.id);
    if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
    _stepIdx = idx;
  }
  const cur = document.getElementById(STEPS[_stepIdx]?.id);
  if (cur) cur.classList.add('active');
  const step = STEPS[_stepIdx];
  if (step) {
    document.getElementById('status-text').textContent = step.label + '...';
    document.getElementById('status-sub').textContent  = step.sub;
  }
}

function startScan() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) { alert('Please enter a target IP, hostname, or URL.'); return; }

  const consent = document.getElementById('consent-checkbox');
  if (consent && !consent.checked) {
    alert('You must confirm you have permission to scan this target before proceeding.');
    return;
  }

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  document.getElementById('btn-text').textContent = 'Scanning...';
  document.getElementById('btn-icon').textContent = '⟳';

  document.getElementById('progress-section').classList.remove('hidden');
  document.getElementById('progress-log').innerHTML = '';
  _stepIdx = 0;
  STEPS.forEach(s => {
    const el = document.getElementById(s.id);
    if (el) { el.classList.remove('active','done'); }
  });
  document.getElementById(STEPS[0].id)?.classList.add('active');

  fetch('/scan/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { showError(data.error, btn); return; }
    pollStatus(data.job_id, btn);
  })
  .catch(err => showError(err.toString(), btn));
}

function pollStatus(jobId, btn) {
  let lastCount = 0;
  const log = document.getElementById('progress-log');

  const iv = setInterval(() => {
    fetch(`/scan/status/${jobId}`)
    .then(r => r.json())
    .then(data => {
      if (data.messages && data.messages.length > lastCount) {
        for (let i = lastCount; i < data.messages.length; i++) {
          const line = document.createElement('div');
          line.className = 'log-line';
          line.textContent = data.messages[i];
          log.appendChild(line);
          log.scrollTop = log.scrollHeight;
        }
        _advanceStep(data.messages.length);
        lastCount = data.messages.length;
      }

      if (data.status === 'done') {
        clearInterval(iv);
        STEPS.forEach(s => {
          const el = document.getElementById(s.id);
          if (el) { el.classList.remove('active'); el.classList.add('done'); }
        });
        document.getElementById('status-text').textContent = 'Complete!';
        document.getElementById('status-sub').textContent  = 'Redirecting to report...';
        fetch(`/scan/result/${jobId}`)
        .then(r => r.json())
        .then(result => {
          if (result.scan_id) window.location.href = `/report/${result.scan_id}`;
        });
      } else if (data.status === 'error') {
        clearInterval(iv);
        showError(data.error || 'Scan failed', btn);
      }
    })
    .catch(() => {});
  }, 1500);
}

function showError(msg, btn) {
  alert('Error: ' + msg);
  btn.disabled = false;
  document.getElementById('btn-text').textContent = 'Scan Now';
  document.getElementById('btn-icon').textContent = '▶';
  document.getElementById('progress-section').classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('ip-input');
  if (input) {
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
  }
});
