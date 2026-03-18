// VaultP2P Dashboard — vanilla JS

let sessionId = null;
let pollInterval = null;
let lastPollData = null;
const API = '/api';

function api(path, opts = {}) {
    const url = new URL(path, window.location.origin);
    if (sessionId) url.searchParams.set('session_id', sessionId);
    return fetch(url, {
        headers: { 'Content-Type': 'application/json', ...opts.headers },
        ...opts,
    }).then(async r => {
        const text = await r.text();
        let body = {};
        if (text) {
            try {
                body = JSON.parse(text);
            } catch (_e) {
                body = { error: text };
            }
        }
        if (!r.ok && !body.error) {
            body.error = `Request failed (${r.status})`;
        }
        return body;
    });
}

function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

// --- Toast notifications ---
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// --- Auth ---
async function loginPassword() {
    const pw = document.getElementById('password-input').value;
    const res = await api(`${API}/auth/login`, {
        method: 'POST',
        body: JSON.stringify({ password: pw }),
    });
    if (res.session_id) {
        sessionId = res.session_id;
        onAuthenticated();
    } else {
        alert(res.error || 'Login failed');
    }
}

async function registerPassword() {
    const pw = document.getElementById('password-input').value;
    if (!pw || pw.length < 8) { alert('Password must be at least 8 characters'); return; }
    const res = await api(`${API}/auth/register`, {
        method: 'POST',
        body: JSON.stringify({ password: pw }),
    });
    if (res.session_id) {
        sessionId = res.session_id;
        onAuthenticated();
    } else {
        alert(res.error || 'Registration failed');
    }
}

async function verifyTotp() {
    const code = document.getElementById('totp-input').value;
    const res = await api(`${API}/auth/totp/verify`, {
        method: 'POST',
        body: JSON.stringify({ code }),
    });
    if (res.session_id) {
        sessionId = res.session_id;
        onAuthenticated();
    } else {
        alert(res.error || 'Invalid code');
    }
}

async function lockVault() {
    await api(`${API}/auth/lock`, { method: 'POST' });
    sessionId = null;
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('auth-section').style.display = 'flex';
    document.getElementById('auth-status').textContent = 'Locked';
    document.getElementById('btn-lock').style.display = 'none';
    document.getElementById('challenge-banner').style.display = 'none';
}

function onAuthenticated() {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('auth-status').textContent = 'Authenticated';
    document.getElementById('btn-lock').style.display = 'inline';
    loadCredentials();
    startPolling();
}

// --- Tabs ---
function showTab(name) {
    document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${name}`).style.display = 'block';
    event.target.classList.add('active');

    if (name === 'credentials') loadCredentials();
    if (name === 'guides') loadGuides();
    if (name === 'sync') loadSyncStatus();
    if (name === 'audit') loadAudit();
}

// --- Polling ---
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollEvents(); // immediate first poll
    pollInterval = setInterval(pollEvents, 5000);
}

async function pollEvents() {
    if (!sessionId) return;
    const res = await api(`${API}/events/poll`);
    if (res.error) return;

    // Update challenge banner
    if (res.challenges > 0) {
        loadPendingChallenges();
    } else {
        document.getElementById('challenge-banner').style.display = 'none';
    }

    // Detect count changes and refresh current tab
    if (lastPollData) {
        if (res.credentials !== lastPollData.credentials) {
            const credTab = document.getElementById('tab-credentials');
            if (credTab && credTab.style.display !== 'none') loadCredentials();
        }
        if (res.guides !== lastPollData.guides) {
            const guideTab = document.getElementById('tab-guides');
            if (guideTab && guideTab.style.display !== 'none') loadGuides();
        }
    }
    lastPollData = res;
}

// --- Challenges ---
async function loadPendingChallenges() {
    const res = await api(`${API}/challenges/pending`);
    if (!Array.isArray(res) || res.length === 0) {
        document.getElementById('challenge-banner').style.display = 'none';
        return;
    }

    const banner = document.getElementById('challenge-banner');
    const textEl = document.getElementById('challenge-banner-text');
    const actionsEl = document.getElementById('challenge-banner-actions');

    textEl.textContent = `${res.length} pending operator challenge${res.length > 1 ? 's' : ''} awaiting confirmation`;

    actionsEl.innerHTML = '';
    res.forEach(c => {
        const btn = document.createElement('button');
        btn.className = 'btn-approve';
        btn.textContent = `Approve: ${escapeHtml(c.action)}`;
        btn.onclick = () => confirmChallenge(c.challenge_id, c.action);
        actionsEl.appendChild(btn);
    });

    banner.style.display = 'flex';
}

async function confirmChallenge(id, action) {
    const res = await api(`${API}/challenges/${encodeURIComponent(id)}/confirm`, {
        method: 'POST',
        body: JSON.stringify({ action }),
    });
    if (res.status === 'confirmed') {
        showToast('Challenge confirmed', 'success');
        loadPendingChallenges();
    } else {
        showToast(res.error || 'Failed to confirm challenge', 'error');
    }
}

function dismissChallengeBanner() {
    document.getElementById('challenge-banner').style.display = 'none';
}

// --- Credentials ---
async function loadCredentials() {
    const res = await api(`${API}/credentials`);
    const tbody = document.querySelector('#credentials-table tbody');
    tbody.innerHTML = (res.entries || []).map(e => {
        const encodedPath = encodeURIComponent(e.path || '');
        return `<tr>
            <td>${escapeHtml(e.path)}</td>
            <td>${escapeHtml(e.value)}</td>
            <td>${escapeHtml(e.category)}</td>
            <td>${escapeHtml(e.service || '-')}</td>
            <td><button class="btn-copy" onclick="copyCredential('${encodedPath}', this)">Copy</button></td>
        </tr>`;
    }).join('');
}

async function searchCredentials() {
    const q = document.getElementById('search-input').value.toLowerCase();
    const rows = document.querySelectorAll('#credentials-table tbody tr');
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

async function copyCredential(encodedPath, btn) {
    const path = decodeURIComponent(encodedPath);
    const res = await api(`${API}/clipboard/${encodeURIComponent(path)}`, {
        method: 'POST',
    });
    if (res.status === 'copied') {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        showToast(`Copied to clipboard (auto-clears in ${res.auto_clear_seconds}s)`, 'success');
        setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
        }, 2000);
    } else {
        showToast(res.error || 'Failed to copy', 'error');
    }
}

// --- Guides ---
async function loadGuides() {
    const res = await api(`${API}/guides`);
    if (res.error) {
        showToast(res.error, 'error');
        return;
    }
    const tbody = document.querySelector('#guides-table tbody');
    tbody.innerHTML = (res.guides || []).map(g => {
        const encodedName = encodeURIComponent(g.name || '');
        return `<tr>
            <td><a class="guide-name-link" onclick="viewGuide('${encodedName}')">${escapeHtml(g.name)}</a></td>
            <td>${escapeHtml(g.category)}</td>
            <td>${escapeHtml(g.status)}</td>
            <td>${escapeHtml((g.tags || []).join(', '))}</td>
            <td><button onclick="deleteGuide('${encodedName}')">Delete</button></td>
        </tr>`;
    }).join('');
}

async function viewGuide(encodedName) {
    const name = decodeURIComponent(encodedName);
    const res = await api(`${API}/guides/${encodeURIComponent(name)}`);
    if (res.error) {
        showToast(res.error, 'error');
        return;
    }

    document.getElementById('guide-modal-title').textContent = res.name;
    document.getElementById('guide-modal-meta').innerHTML = [
        `<span>Category: ${escapeHtml(res.category)}</span>`,
        `<span>Status: ${escapeHtml(res.status)}</span>`,
        res.tags && res.tags.length ? `<span>Tags: ${escapeHtml(res.tags.join(', '))}</span>` : '',
        res.updated_at ? `<span>Updated: ${escapeHtml(res.updated_at)}</span>` : '',
    ].filter(Boolean).join('');

    document.getElementById('guide-modal-body').innerHTML =
        `<pre>${escapeHtml(res.content)}</pre>`;
    document.getElementById('guide-modal').style.display = 'flex';
}

function closeGuideModal() {
    document.getElementById('guide-modal').style.display = 'none';
}

async function deleteGuide(encodedName) {
    const name = decodeURIComponent(encodedName || '').trim();
    if (!name) {
        alert('Missing guide/document name');
        return;
    }
    if (!confirm(`Delete "${name}"?`)) return;

    let res = await api(`${API}/guides/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (res.error) {
        // Fallback for clients/routes that use POST delete endpoint.
        res = await api(`${API}/guides/delete`, {
            method: 'POST',
            body: JSON.stringify({ name }),
        });
    }
    if (res.error) {
        showToast(res.error, 'error');
        return;
    }
    showToast(`Guide "${name}" deleted`, 'success');
    await loadGuides();
}

// --- Guide Create Form ---
function showGuideCreateForm() {
    document.getElementById('guide-form').reset();
    document.getElementById('guide-form-modal').style.display = 'flex';
}

function closeGuideFormModal() {
    document.getElementById('guide-form-modal').style.display = 'none';
}

async function submitGuideForm(e) {
    e.preventDefault();
    const name = document.getElementById('guide-name').value.trim();
    const content = document.getElementById('guide-content').value;
    const category = document.getElementById('guide-category').value;
    const tagsRaw = document.getElementById('guide-tags').value;
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];

    if (!name) { showToast('Guide name is required', 'error'); return; }
    if (!content) { showToast('Guide content is required', 'error'); return; }

    const body = { name, content, category };
    if (tags.length > 0) body.tags = tags;

    const res = await api(`${API}/guides`, {
        method: 'POST',
        body: JSON.stringify(body),
    });

    if (res.status === 'created') {
        showToast(`Guide "${name}" created`, 'success');
        closeGuideFormModal();
        loadGuides();
    } else {
        showToast(res.error || 'Failed to create guide', 'error');
    }
}

// --- Sync ---
async function loadSyncStatus() {
    const res = await api(`${API}/sync/status`);
    document.getElementById('sync-info').innerHTML = `
        <p><strong>Machine ID:</strong> ${escapeHtml(res.machine_id || 'unknown')}</p>
        <p><strong>DB Version:</strong> ${escapeHtml(res.db_version || 0)}</p>
        <p><strong>cr-sqlite:</strong> ${res.cr_sqlite ? 'enabled' : 'disabled'}</p>
    `;
}

// --- Audit ---
async function loadAudit() {
    const res = await api(`${API}/audit`);
    const tbody = document.querySelector('#audit-table tbody');
    tbody.innerHTML = (res.entries || []).map(e =>
        `<tr>
            <td>${escapeHtml(e.timestamp)}</td>
            <td>${escapeHtml(e.action)}</td>
            <td>${escapeHtml(e.path || '-')}</td>
            <td>${e.success ? 'ok' : 'fail'}</td>
        </tr>`
    ).join('');
}

// --- TOTP ---
async function setupTotp() {
    const res = await api(`${API}/auth/totp/setup`, {
        method: 'POST',
        body: JSON.stringify({}),
    });
    const el = document.getElementById('totp-result');
    if (res.secret) {
        el.innerHTML = `<p>Secret: <code>${escapeHtml(res.secret)}</code></p><p>URI: <code>${escapeHtml(res.otpauth_uri)}</code></p>`;
        document.getElementById('totp-section').style.display = 'block';
    } else {
        el.innerHTML = `<p style="color:var(--error)">${escapeHtml(res.error || 'Failed')}</p>`;
    }
}

// --- Close modals on backdrop click ---
document.addEventListener('click', (e) => {
    if (e.target.id === 'guide-modal') closeGuideModal();
    if (e.target.id === 'guide-form-modal') closeGuideFormModal();
});

// --- Close modals on Escape key ---
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeGuideModal();
        closeGuideFormModal();
    }
});

// Check auth status on load
(async function init() {
    const res = await api(`${API}/auth/status`);
    if (!res.configured) {
        // Auth not configured — must register before accessing data
        document.getElementById('auth-section').style.display = 'flex';
        document.getElementById('dashboard').style.display = 'none';
        document.getElementById('auth-status').textContent = 'Set up authentication to continue';
    }
})();
