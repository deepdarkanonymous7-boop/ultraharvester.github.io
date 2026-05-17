/**
 * UltraHarvester Web Dashboard — Client JS
 */

// Theme toggle (dark is default)
const Theme = {
  toggle() {
    document.body.classList.toggle('light-mode');
    localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
  },
  init() {
    if (localStorage.getItem('theme') === 'light') document.body.classList.add('light-mode');
  }
};

// Clipboard copy
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!');
  });
}

// Toast notifications
function showToast(message, type = 'success') {
  const colors = { success: '#00ff88', error: '#ff4d6d', warning: '#ffd166', info: '#00d4ff' };
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed; bottom:1.5rem; right:1.5rem; z-index:9999;
    background:#1a2235; border:1px solid ${colors[type] || colors.success};
    color:${colors[type] || colors.success}; padding:0.75rem 1.25rem;
    border-radius:8px; font-size:0.875rem; font-family:'JetBrains Mono',monospace;
    box-shadow:0 4px 20px rgba(0,0,0,0.4); animation:slideIn 0.3s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Format numbers
function fmt(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n;
}

// Risk color helper
function riskColor(level) {
  return {CRITICAL:'#ff4d6d', HIGH:'#ff8c42', MEDIUM:'#ffd166', LOW:'#00ff88', INFO:'#00d4ff'}[level] || '#64748b';
}

// Poll a scan until completion
async function pollScanUntilDone(scanId, onUpdate, onComplete) {
  const interval = setInterval(async () => {
    try {
      const r = await fetch(`/api/scan/${scanId}/status`);
      const s = await r.json();
      if (onUpdate) onUpdate(s);
      if (s.status === 'completed' || s.status === 'error') {
        clearInterval(interval);
        if (onComplete) onComplete(s);
      }
    } catch (e) {
      console.error('Poll error:', e);
    }
  }, 2500);
  return interval;
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  Theme.init();
});
