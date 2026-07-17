/**
 * WebShield Scanner - Scan History
 * Provides searchable, filterable scan history with report and deletion actions.
 */

(function() {
    'use strict';

    const state = {
        page: 1,
        pages: 1,
        perPage: 10,
        status: 'all',
        query: '',
        sortBy: 'created_at',
        sortOrder: 'desc',
        scans: []
    };

    const archiveKey = 'webshield_archived_scans';
    let archivedIds = loadArchivedIds();

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        const form = document.getElementById('history-filter-form');
        if (form) {
            form.addEventListener('submit', function(event) {
                event.preventDefault();
                applyFilters();
            });
        }

        const search = document.getElementById('history-search');
        if (search) {
            const debounced = WebShield.debounce(function(value) {
                state.query = value.trim();
                state.page = 1;
                loadHistory();
            }, 250);
            search.addEventListener('input', function() {
                debounced(this.value);
            });
        }

        bindPager();
        bindActions();
        loadHistory();
    }

    function applyFilters() {
        const statusEl = document.getElementById('history-status');
        const sortEl = document.getElementById('history-sort');
        const searchEl = document.getElementById('history-search');
        const sortParts = (sortEl ? sortEl.value : 'created_at:desc').split(':');

        state.status = statusEl ? statusEl.value : 'all';
        state.query = searchEl ? searchEl.value.trim() : '';
        state.sortBy = sortParts[0] || 'created_at';
        state.sortOrder = sortParts[1] || 'desc';
        state.page = 1;
        loadHistory();
    }

    function bindPager() {
        const prev = document.getElementById('history-prev');
        const next = document.getElementById('history-next');
        if (prev) {
            prev.addEventListener('click', function() {
                if (state.page <= 1) return;
                state.page -= 1;
                loadHistory();
            });
        }
        if (next) {
            next.addEventListener('click', function() {
                if (state.page >= state.pages) return;
                state.page += 1;
                loadHistory();
            });
        }
    }

    function bindActions() {
        document.addEventListener('click', function(event) {
            const button = event.target.closest('[data-history-action]');
            if (!button) return;
            const scanId = Number(button.dataset.scanId || 0);
            if (!scanId) return;

            const action = button.dataset.historyAction;
            if (action === 'archive') archiveScan(scanId);
            if (action === 'restore') restoreScan(scanId);
            if (action === 'delete') deleteScan(scanId);
        });
    }

    async function loadHistory() {
        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }

        renderLoading();

        try {
            const serverStatus = state.status === 'archived' ? 'all' : state.status;
            const data = await window.api.scan.history(state.page, state.perPage, serverStatus, {
                query: state.query,
                sortBy: state.sortBy,
                sortOrder: state.sortOrder
            });

            const scans = Array.isArray(data.scans) ? data.scans : [];
            state.scans = scans.filter(scan => {
                const archived = archivedIds.has(Number(scan.id));
                return state.status === 'archived' ? archived : !archived;
            });
            state.pages = Math.max(1, Number(data.pagination?.pages || 1));

            renderHistory(state.scans);
            updatePager(data.pagination || {});
        } catch (error) {
            console.error('History load error:', error);
            renderError(error.message || 'Could not load scan history.');
        }
    }

    function renderHistory(scans) {
        if (!scans.length) {
            renderEmpty();
            return;
        }

        const tbody = document.getElementById('history-table-body');
        const cards = document.getElementById('history-cards');

        if (tbody) {
            tbody.innerHTML = scans.map(renderRow).join('');
        }
        if (cards) {
            cards.innerHTML = scans.map(renderCard).join('');
        }
    }

    function renderRow(scan) {
        const status = safeStatus(scan.scan_status);
        const risk = safeRisk(scan.risk_level);
        return `
            <tr>
                <td>
                    <div class="target-url">${escapeHtml(scan.target_url)}</div>
                    <div class="scan-meta">#${Number(scan.id)} - ${formatDate(scan.created_at)}</div>
                </td>
                <td><span class="status-pill status-${status}">${escapeHtml(status)}</span></td>
                <td><span class="history-score">${scoreText(scan.security_score)}</span></td>
                <td>${findingCounts(scan)}</td>
                <td><span class="risk-pill risk-${risk}">${escapeHtml(risk)}</span></td>
                <td>${actionsHtml(scan)}</td>
            </tr>
        `;
    }

    function renderCard(scan) {
        const status = safeStatus(scan.scan_status);
        const risk = safeRisk(scan.risk_level);
        return `
            <div class="history-card">
                <div class="history-card-head">
                    <div>
                        <div class="target-url">${escapeHtml(scan.target_url)}</div>
                        <div class="scan-meta">#${Number(scan.id)} - ${formatDate(scan.created_at)}</div>
                    </div>
                    <span class="status-pill status-${status}">${escapeHtml(status)}</span>
                </div>
                <div class="d-flex align-items-center justify-content-between mb-2">
                    <span class="history-score">${scoreText(scan.security_score)}</span>
                    <span class="risk-pill risk-${risk}">${escapeHtml(risk)}</span>
                </div>
                <div class="mb-3">${findingCounts(scan)}</div>
                ${actionsHtml(scan)}
            </div>
        `;
    }

    function actionsHtml(scan) {
        const id = Number(scan.id);
        const status = safeStatus(scan.scan_status);
        const archived = archivedIds.has(id);
        const reportHref = status === 'completed' ? `/report/${id}` : `/scan-progress/${id}`;
        const reportTitle = status === 'completed' ? 'Open report' : 'Open progress';
        const canDelete = !['running', 'pending'].includes(status);

        return `
            <div class="history-actions">
                <a class="btn btn-outline-info btn-sm" href="${reportHref}" title="${reportTitle}">
                    <i class="fas ${status === 'completed' ? 'fa-file-lines' : 'fa-spinner'}"></i>
                </a>
                ${status === 'completed' ? `
                    <a class="btn btn-outline-light btn-sm" href="/attack-surface/${id}" title="Attack surface">
                        <i class="fas fa-diagram-project"></i>
                    </a>
                ` : ''}
                <button class="btn btn-outline-secondary btn-sm" type="button" title="${archived ? 'Restore' : 'Archive'}" data-history-action="${archived ? 'restore' : 'archive'}" data-scan-id="${id}">
                    <i class="fas ${archived ? 'fa-box-open' : 'fa-box-archive'}"></i>
                </button>
                <button class="btn btn-outline-danger btn-sm" type="button" title="Delete" data-history-action="delete" data-scan-id="${id}" ${canDelete ? '' : 'disabled'}>
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
    }

    function findingCounts(scan) {
        return `
            <div class="finding-counts">
                <span class="sev-critical" title="Critical">${Number(scan.critical_findings || 0)}</span>
                <span class="sev-high" title="High">${Number(scan.high_findings || 0)}</span>
                <span class="sev-medium" title="Medium">${Number(scan.medium_findings || 0)}</span>
                <span class="sev-low" title="Low">${Number(scan.low_findings || 0)}</span>
                <span title="Total">${Number(scan.total_findings || 0)}</span>
            </div>
        `;
    }

    async function deleteScan(scanId) {
        const scan = state.scans.find(item => Number(item.id) === scanId);
        const label = scan ? scan.target_url : `scan #${scanId}`;
        if (!confirm(`Delete ${label}? This cannot be undone.`)) return;

        try {
            await window.api.scan.delete(scanId);
            archivedIds.delete(scanId);
            saveArchivedIds();
            WebShield.showToast('Scan deleted.', 'success');
            loadHistory();
        } catch (error) {
            console.error('Delete scan error:', error);
            WebShield.showToast(error.message || 'Could not delete scan.', 'danger');
        }
    }

    function archiveScan(scanId) {
        archivedIds.add(scanId);
        saveArchivedIds();
        WebShield.showToast('Scan archived in this browser.', 'info');
        loadHistory();
    }

    function restoreScan(scanId) {
        archivedIds.delete(scanId);
        saveArchivedIds();
        WebShield.showToast('Scan restored.', 'success');
        loadHistory();
    }

    function renderLoading() {
        const tbody = document.getElementById('history-table-body');
        const cards = document.getElementById('history-cards');
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="history-loading"><i class="fas fa-spinner fa-spin"></i>Loading</div>
                    </td>
                </tr>
            `;
        }
        if (cards) {
            cards.innerHTML = '<div class="history-loading"><i class="fas fa-spinner fa-spin"></i>Loading</div>';
        }
    }

    function renderEmpty() {
        const html = '<div class="history-empty"><i class="fas fa-search"></i>No scans found</div>';
        const tbody = document.getElementById('history-table-body');
        const cards = document.getElementById('history-cards');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6">${html}</td></tr>`;
        }
        if (cards) {
            cards.innerHTML = html;
        }
    }

    function renderError(message) {
        const html = `<div class="history-empty"><i class="fas fa-triangle-exclamation"></i>${escapeHtml(message)}</div>`;
        const tbody = document.getElementById('history-table-body');
        const cards = document.getElementById('history-cards');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6">${html}</td></tr>`;
        }
        if (cards) {
            cards.innerHTML = html;
        }
    }

    function updatePager(pagination) {
        const page = Number(pagination.page || state.page || 1);
        const pages = Math.max(1, Number(pagination.pages || state.pages || 1));
        state.page = page;
        state.pages = pages;

        setText('history-page-label', `Page ${page} of ${pages}`);
        const prev = document.getElementById('history-prev');
        const next = document.getElementById('history-next');
        if (prev) prev.disabled = page <= 1;
        if (next) next.disabled = page >= pages;
    }

    function loadArchivedIds() {
        try {
            const raw = localStorage.getItem(archiveKey);
            const parsed = raw ? JSON.parse(raw) : [];
            return new Set(Array.isArray(parsed) ? parsed.map(Number).filter(Boolean) : []);
        } catch (err) {
            return new Set();
        }
    }

    function saveArchivedIds() {
        localStorage.setItem(archiveKey, JSON.stringify(Array.from(archivedIds)));
    }

    function scoreText(score) {
        return score === null || score === undefined ? '--/100' : `${Number(score)}/100`;
    }

    function formatDate(value) {
        return window.WebShield && WebShield.formatDate ? WebShield.formatDate(value, 'relative') : '';
    }

    function safeStatus(status) {
        const normalized = String(status || 'unknown').toLowerCase();
        return ['completed', 'running', 'pending', 'failed', 'cancelled'].includes(normalized)
            ? normalized
            : 'pending';
    }

    function safeRisk(risk) {
        const normalized = String(risk || 'info').toLowerCase();
        return ['critical', 'high', 'medium', 'low', 'info'].includes(normalized)
            ? normalized
            : 'info';
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    function escapeHtml(value) {
        const div = document.createElement('div');
        div.textContent = value === null || value === undefined ? '' : String(value);
        return div.innerHTML;
    }

})();
