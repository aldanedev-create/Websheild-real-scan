/**
 * WebShield Scanner - Admin Console
 */

(function() {
    'use strict';

    const state = {
        users: {
            page: 1,
            pages: 1,
            perPage: 20,
            search: '',
            plan: 'all',
            items: []
        },
        scans: {
            page: 1,
            pages: 1,
            perPage: 20,
            status: 'all',
            userId: ''
        },
        audit: {
            page: 1,
            pages: 1,
            perPage: 20,
            action: '',
            severity: 'all',
            days: 30
        }
    };

    let currentUserId = 0;
    let userModal = null;
    let deleteModal = null;
    const requestSeq = {
        overview: 0,
        users: 0,
        scans: 0,
        audit: 0
    };

    document.addEventListener('DOMContentLoaded', initAdmin);

    function initAdmin() {
        const root = document.querySelector('.admin-page');
        if (!root) return;

        currentUserId = Number(root.dataset.currentUserId || 0);

        const userModalEl = document.getElementById('admin-user-modal');
        const deleteModalEl = document.getElementById('admin-delete-modal');
        userModal = userModalEl ? new bootstrap.Modal(userModalEl) : null;
        deleteModal = deleteModalEl ? new bootstrap.Modal(deleteModalEl) : null;

        bindEvents();

        if (!window.api || typeof window.api.isAuthenticated !== 'function' || !window.api.isAuthenticated()) {
            showAuthState('Admin token missing. Sign in again from the login page.');
            return;
        }

        loadAll();
    }

    function bindEvents() {
        const refreshBtn = document.getElementById('admin-refresh-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', loadAll);

        const userFilter = document.getElementById('admin-users-filter');
        if (userFilter) {
            userFilter.addEventListener('submit', function(event) {
                event.preventDefault();
                state.users.page = 1;
                state.users.search = document.getElementById('admin-user-search').value.trim();
                state.users.plan = allowedValue(
                    document.getElementById('admin-user-plan').value,
                    ['all', 'free', 'premium', 'enterprise'],
                    'all'
                );
                loadUsers();
            });
        }

        const scanFilter = document.getElementById('admin-scans-filter');
        if (scanFilter) {
            scanFilter.addEventListener('submit', function(event) {
                event.preventDefault();
                state.scans.page = 1;
                state.scans.status = allowedValue(
                    document.getElementById('admin-scan-status').value,
                    ['all', 'pending', 'running', 'completed', 'failed', 'cancelled'],
                    'all'
                );
                state.scans.userId = cleanNumericId(document.getElementById('admin-scan-user').value);
                loadScans();
            });
        }

        const auditFilter = document.getElementById('admin-audit-filter');
        if (auditFilter) {
            auditFilter.addEventListener('submit', function(event) {
                event.preventDefault();
                state.audit.page = 1;
                state.audit.action = document.getElementById('admin-audit-action').value.trim();
                state.audit.severity = allowedValue(
                    document.getElementById('admin-audit-severity').value,
                    ['all', 'info', 'warning', 'error', 'critical'],
                    'all'
                );
                state.audit.days = boundedInt(document.getElementById('admin-audit-days').value, 30, 1, 365);
                loadAuditLogs();
            });
        }

        bindPager('users', loadUsers);
        bindPager('scans', loadScans);
        bindPager('audit', loadAuditLogs);

        const usersBody = document.getElementById('admin-users-body');
        if (usersBody) {
            usersBody.addEventListener('click', function(event) {
                const button = event.target.closest('[data-admin-action]');
                if (!button) return;
                const userId = Number(button.dataset.userId);
                if (button.dataset.adminAction === 'edit') openEditUser(userId);
                if (button.dataset.adminAction === 'delete') openDeleteUser(userId);
            });
        }

        const userForm = document.getElementById('admin-user-form');
        if (userForm) userForm.addEventListener('submit', saveUser);

        const deleteConfirm = document.getElementById('admin-delete-confirm-btn');
        if (deleteConfirm) deleteConfirm.addEventListener('click', deleteUser);
    }

    function bindPager(name, loader) {
        const prev = document.getElementById(`admin-${name}-prev`);
        const next = document.getElementById(`admin-${name}-next`);

        if (prev) {
            prev.addEventListener('click', function() {
                if (state[name].page <= 1) return;
                state[name].page -= 1;
                loader();
            });
        }

        if (next) {
            next.addEventListener('click', function() {
                if (state[name].page >= state[name].pages) return;
                state[name].page += 1;
                loader();
            });
        }
    }

    function loadAll() {
        hideAuthState();
        loadOverview();
        loadUsers();
        loadScans();
        loadAuditLogs();
    }

    async function loadOverview() {
        const requestId = ++requestSeq.overview;
        try {
            const [statsData, healthData] = await Promise.all([
                window.api.admin.stats(),
                window.api.admin.health()
            ]);

            if (requestId !== requestSeq.overview) return;
            if (statsData.success) renderStats(statsData.stats);
            if (healthData.success) renderHealth(healthData.health);
        } catch (error) {
            if (requestId !== requestSeq.overview) return;
            handleError(error, 'overview');
        }
    }

    async function loadUsers() {
        const tbody = document.getElementById('admin-users-body');
        const requestId = ++requestSeq.users;
        setLoading(tbody, 6);

        try {
            const data = await window.api.admin.users({
                page: state.users.page,
                perPage: state.users.perPage,
                search: state.users.search,
                plan: state.users.plan
            });

            if (requestId !== requestSeq.users) return;
            state.users.items = data.users || [];
            state.users.pages = Math.max(1, data.pagination?.pages || 1);
            renderUsers(state.users.items);
            updatePager('users', data.pagination);
        } catch (error) {
            if (requestId !== requestSeq.users) return;
            renderTableError(tbody, 6, error);
        }
    }

    async function loadScans() {
        const tbody = document.getElementById('admin-scans-body');
        const requestId = ++requestSeq.scans;
        setLoading(tbody, 6);

        try {
            const data = await window.api.admin.scans({
                page: state.scans.page,
                perPage: state.scans.perPage,
                status: state.scans.status,
                userId: state.scans.userId
            });

            if (requestId !== requestSeq.scans) return;
            state.scans.pages = Math.max(1, data.pagination?.pages || 1);
            renderScans(data.scans || []);
            updatePager('scans', data.pagination);
        } catch (error) {
            if (requestId !== requestSeq.scans) return;
            renderTableError(tbody, 6, error);
        }
    }

    async function loadAuditLogs() {
        const tbody = document.getElementById('admin-audit-body');
        const requestId = ++requestSeq.audit;
        setLoading(tbody, 6);

        try {
            const data = await window.api.admin.auditLogs({
                page: state.audit.page,
                perPage: state.audit.perPage,
                action: state.audit.action,
                severity: state.audit.severity,
                days: state.audit.days
            });

            if (requestId !== requestSeq.audit) return;
            state.audit.pages = Math.max(1, data.pagination?.pages || 1);
            renderAuditLogs(data.logs || []);
            updatePager('audit', data.pagination);
        } catch (error) {
            if (requestId !== requestSeq.audit) return;
            renderTableError(tbody, 6, error);
        }
    }

    function renderStats(stats) {
        const users = stats.users || {};
        const scans = stats.scans || {};
        const findings = stats.findings || {};
        const security = stats.security || {};
        const revenue = stats.revenue || {};
        const bySeverity = findings.by_severity || {};
        const criticalHigh = Number(bySeverity.critical || 0) + Number(bySeverity.high || 0);

        setText('admin-stat-users', formatNumber(users.total || 0));
        setText('admin-stat-users-foot', `${formatNumber(users.active || 0)} active, ${formatNumber(users.admin || 0)} admin`);
        setText('admin-stat-scans', formatNumber(scans.total || 0));
        setText('admin-stat-scans-foot', `${formatNumber(scans.completed || 0)} completed, ${formatNumber(scans.running || 0)} running`);
        setText('admin-stat-findings', formatNumber(findings.total || 0));
        setText('admin-stat-findings-foot', `${formatNumber(criticalHigh)} critical/high`);
        setText('admin-stat-score', formatScore(security.average_score));
        setText('admin-stat-revenue', `${formatMoney(revenue.total || 0, revenue.currency || 'USD')} revenue`);

        renderSeverityBars(bySeverity);
    }

    function renderSeverityBars(bySeverity) {
        const container = document.getElementById('admin-severity-bars');
        if (!container) return;

        const order = ['critical', 'high', 'medium', 'low', 'info'];
        const colors = {
            critical: '#f44336',
            high: '#ff7043',
            medium: '#ff9800',
            low: '#4caf50',
            info: '#00f0ff'
        };
        const max = Math.max(1, ...order.map((key) => Number(bySeverity[key] || 0)));

        container.innerHTML = order.map((key) => {
            const count = Number(bySeverity[key] || 0);
            const width = Math.max(2, Math.round((count / max) * 100));
            return `
                <div class="severity-bar-row">
                    <div class="severity-bar-label">${escapeHtml(key)}</div>
                    <div class="severity-track">
                        <div class="severity-fill" style="width:${width}%;background:${colors[key]};"></div>
                    </div>
                    <div class="severity-count">${formatNumber(count)}</div>
                </div>
            `;
        }).join('');
    }

    function renderHealth(health) {
        const status = health.status || 'unknown';
        const statusEl = document.getElementById('admin-health-status');
        if (statusEl) {
            statusEl.textContent = status;
            statusEl.className = `status-pill ${statusClass(status)}`;
        }

        const checks = health.checks || {};
        const entries = Object.keys(checks).map((key) => [key, checks[key]]);
        const container = document.getElementById('admin-health-list');
        if (!container) return;

        if (!entries.length) {
            container.innerHTML = emptyState('No checks returned');
            return;
        }

        container.innerHTML = entries.map(([key, check]) => {
            const label = key.replace(/_/g, ' ');
            const checkStatus = check.status || 'unknown';
            return `
                <div class="health-item">
                    <div>
                        <div class="health-name">${escapeHtml(label)}</div>
                        <div class="health-message">${escapeHtml(check.message || '')}</div>
                    </div>
                    <span class="status-pill ${statusClass(checkStatus)}">${escapeHtml(checkStatus)}</span>
                </div>
            `;
        }).join('');
    }

    function renderUsers(users) {
        const tbody = document.getElementById('admin-users-body');
        if (!tbody) return;

        if (!users.length) {
            tbody.innerHTML = rowEmpty(6, 'No users found');
            return;
        }

        tbody.innerHTML = users.map((user) => {
            const plan = user.plan || 'free';
            const status = user.is_active ? 'active' : 'inactive';
            const role = user.is_admin ? 'Admin' : 'User';
            const deleteDisabled = Number(user.id) === currentUserId ? 'disabled' : '';
            const deleteTitle = deleteDisabled ? 'Cannot delete current user' : 'Delete user';

            return `
                <tr>
                    <td>
                        <div class="admin-row-title">${escapeHtml(user.full_name || user.username || 'User')}</div>
                        <div class="admin-row-subtitle">${escapeHtml(user.email || '')} &middot; ${escapeHtml(user.username || '')} &middot; ${role}</div>
                    </td>
                    <td><span class="plan-pill ${escapeClass(plan)}">${escapeHtml(plan)}</span></td>
                    <td><span class="status-pill ${statusClass(status)}">${status}</span></td>
                    <td>${formatNumber(user.total_scans || 0)}</td>
                    <td>${formatDate(user.created_at)}</td>
                    <td class="text-end">
                        <span class="admin-actions">
                            <button type="button" class="btn btn-outline-primary btn-sm admin-icon-btn" title="Edit user" data-admin-action="edit" data-user-id="${Number(user.id)}">
                                <i class="fas fa-pen"></i>
                            </button>
                            <button type="button" class="btn btn-outline-danger btn-sm admin-icon-btn" title="${deleteTitle}" data-admin-action="delete" data-user-id="${Number(user.id)}" ${deleteDisabled}>
                                <i class="fas fa-trash"></i>
                            </button>
                        </span>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function renderScans(scans) {
        const tbody = document.getElementById('admin-scans-body');
        if (!tbody) return;

        if (!scans.length) {
            tbody.innerHTML = rowEmpty(6, 'No scans found');
            return;
        }

        tbody.innerHTML = scans.map((scan) => {
            const status = scan.scan_status || 'unknown';
            const score = scan.security_score === null || scan.security_score === undefined ? '--' : scan.security_score;
            return `
                <tr>
                    <td>
                        <div class="admin-row-title">${escapeHtml(scan.target_url || 'Target')}</div>
                        <div class="admin-row-subtitle">Scan #${Number(scan.id) || 0}</div>
                    </td>
                    <td><span class="status-pill ${statusClass(status)}">${escapeHtml(status)}</span></td>
                    <td>${escapeHtml(String(score))}</td>
                    <td>${formatNumber(scan.total_findings || 0)}</td>
                    <td>#${Number(scan.user_id) || 0}</td>
                    <td>${formatDate(scan.created_at)}</td>
                </tr>
            `;
        }).join('');
    }

    function renderAuditLogs(logs) {
        const tbody = document.getElementById('admin-audit-body');
        if (!tbody) return;

        if (!logs.length) {
            tbody.innerHTML = rowEmpty(6, 'No audit entries found');
            return;
        }

        tbody.innerHTML = logs.map((log) => {
            const severity = log.severity || 'info';
            return `
                <tr>
                    <td>
                        <div class="admin-row-title">${escapeHtml(log.action || 'event')}</div>
                    </td>
                    <td><span class="severity-pill ${severityClass(severity)}">${escapeHtml(severity)}</span></td>
                    <td>${log.user_id ? '#' + Number(log.user_id) : '--'}</td>
                    <td>${escapeHtml(log.ip_address || '--')}</td>
                    <td>
                        <div class="admin-row-subtitle">${escapeHtml(log.details || '')}</div>
                    </td>
                    <td>${formatDate(log.created_at)}</td>
                </tr>
            `;
        }).join('');
    }

    function openEditUser(userId) {
        const user = state.users.items.find((item) => Number(item.id) === Number(userId));
        if (!user) return;

        setValue('admin-edit-user-id', user.id);
        setValue('admin-edit-name', user.full_name || '');
        setValue('admin-edit-bio', user.bio || '');
        setValue('admin-edit-plan', user.plan || 'free');
        setChecked('admin-edit-active', Boolean(user.is_active));
        setChecked('admin-edit-admin', Boolean(user.is_admin));

        const form = document.getElementById('admin-user-form');
        if (form) {
            form.dataset.originalAdmin = String(Boolean(user.is_admin));
            form.dataset.originalActive = String(Boolean(user.is_active));
        }

        if (userModal) userModal.show();
    }

    async function saveUser(event) {
        event.preventDefault();

        const userId = Number(document.getElementById('admin-edit-user-id').value);
        const form = document.getElementById('admin-user-form');
        const existingUser = state.users.items.find((item) => Number(item.id) === userId);
        const payload = {
            full_name: document.getElementById('admin-edit-name').value.trim(),
            bio: document.getElementById('admin-edit-bio').value.trim(),
            plan: allowedValue(
                document.getElementById('admin-edit-plan').value,
                ['free', 'premium', 'enterprise'],
                'free'
            ),
            is_active: document.getElementById('admin-edit-active').checked,
            is_admin: document.getElementById('admin-edit-admin').checked
        };

        if (userId === currentUserId && (!payload.is_active || !payload.is_admin)) {
            toast('You cannot deactivate or remove admin access from your own account.', 'warning');
            setChecked('admin-edit-active', true);
            setChecked('admin-edit-admin', true);
            return;
        }

        const wasAdmin = form ? form.dataset.originalAdmin === 'true' : Boolean(existingUser?.is_admin);
        if (!wasAdmin && payload.is_admin) {
            const label = existingUser?.email || existingUser?.username || `user #${userId}`;
            if (!window.confirm(`Grant admin access to ${label}? This gives full administrative control.`)) {
                setChecked('admin-edit-admin', false);
                return;
            }
        }

        const button = document.getElementById('admin-user-save-btn');
        setButtonBusy(button, true);

        try {
            await window.api.admin.updateUser(userId, payload);

            if (userModal) userModal.hide();
            toast('User updated', 'success');
            await Promise.all([loadUsers(), loadOverview(), loadAuditLogs()]);
        } catch (error) {
            toast(error.message || 'Could not update user', 'danger');
        } finally {
            setButtonBusy(button, false);
        }
    }

    function openDeleteUser(userId) {
        if (Number(userId) === currentUserId) return;

        const user = state.users.items.find((item) => Number(item.id) === Number(userId));
        if (!user) return;

        setValue('admin-delete-user-id', user.id);
        setText('admin-delete-user-name', user.email || user.username || `user #${user.id}`);
        if (deleteModal) deleteModal.show();
    }

    async function deleteUser() {
        const userId = Number(document.getElementById('admin-delete-user-id').value);
        if (!userId || userId === currentUserId) return;

        const button = document.getElementById('admin-delete-confirm-btn');
        setButtonBusy(button, true);

        try {
            await window.api.admin.deleteUser(userId);
            if (deleteModal) deleteModal.hide();
            toast('User deleted', 'success');
            await Promise.all([loadUsers(), loadOverview(), loadAuditLogs()]);
        } catch (error) {
            toast(error.message || 'Could not delete user', 'danger');
        } finally {
            setButtonBusy(button, false);
        }
    }

    function updatePager(name, pagination = {}) {
        const page = Number(pagination.page || state[name].page || 1);
        const pages = Math.max(1, Number(pagination.pages || state[name].pages || 1));
        state[name].page = page;
        state[name].pages = pages;

        setText(`admin-${name}-page`, `Page ${page} of ${pages}`);

        const prev = document.getElementById(`admin-${name}-prev`);
        const next = document.getElementById(`admin-${name}-next`);
        if (prev) prev.disabled = page <= 1;
        if (next) next.disabled = page >= pages;
    }

    function handleError(error) {
        if (error && (error.status === 401 || error.status === 403)) {
            showAuthState(error.message || 'Admin access required.');
            return;
        }
        toast(error?.message || 'Admin data could not be loaded', 'danger');
    }

    function renderTableError(tbody, colspan, error) {
        if (error && (error.status === 401 || error.status === 403)) {
            showAuthState(error.message || 'Admin access required.');
        }
        if (!tbody) return;
        tbody.innerHTML = `
            <tr>
                <td colspan="${colspan}">
                    <div class="admin-empty">
                        <i class="fas fa-triangle-exclamation"></i>
                        ${escapeHtml(error?.message || 'Could not load data')}
                    </div>
                </td>
            </tr>
        `;
    }

    function setLoading(tbody, colspan) {
        if (!tbody) return;
        tbody.innerHTML = `
            <tr>
                <td colspan="${colspan}">
                    <div class="admin-loading"><i class="fas fa-spinner fa-spin"></i>Loading</div>
                </td>
            </tr>
        `;
    }

    function rowEmpty(colspan, message) {
        return `
            <tr>
                <td colspan="${colspan}">
                    ${emptyState(message)}
                </td>
            </tr>
        `;
    }

    function emptyState(message) {
        return `<div class="admin-empty"><i class="fas fa-circle-info"></i>${escapeHtml(message)}</div>`;
    }

    function showAuthState(message) {
        const alert = document.getElementById('admin-auth-state');
        if (!alert) return;
        alert.classList.remove('d-none');
        alert.textContent = message;
    }

    function hideAuthState() {
        const alert = document.getElementById('admin-auth-state');
        if (!alert) return;
        alert.classList.add('d-none');
        alert.textContent = '';
    }

    function statusClass(status) {
        const normalized = String(status || '').toLowerCase();
        if (['healthy', 'active', 'completed'].includes(normalized)) return normalized;
        if (['running'].includes(normalized)) return 'running';
        if (['pending', 'warning', 'cancelled', 'unknown'].includes(normalized)) return 'warning';
        if (['unhealthy', 'failed', 'inactive', 'error', 'critical'].includes(normalized)) return 'unhealthy';
        return 'warning';
    }

    function severityClass(severity) {
        const normalized = String(severity || '').toLowerCase();
        if (['critical', 'error', 'warning', 'info'].includes(normalized)) return normalized;
        return 'info';
    }

    function allowedValue(value, allowed, fallback) {
        const normalized = String(value || '').toLowerCase();
        return allowed.includes(normalized) ? normalized : fallback;
    }

    function boundedInt(value, fallback, min, max) {
        const parsed = Number.parseInt(value, 10);
        if (!Number.isFinite(parsed)) return fallback;
        return Math.max(min, Math.min(max, parsed));
    }

    function cleanNumericId(value) {
        const trimmed = String(value || '').trim();
        return /^\d+$/.test(trimmed) ? trimmed : '';
    }

    function escapeClass(value) {
        return String(value || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
    }

    function escapeHtml(value) {
        const div = document.createElement('div');
        div.textContent = value === null || value === undefined ? '' : String(value);
        return div.innerHTML;
    }

    function formatDate(value) {
        if (!value) return '--';
        if (window.WebShield && typeof window.WebShield.formatDate === 'function') {
            return window.WebShield.formatDate(value, 'relative');
        }
        return new Date(value).toLocaleString();
    }

    function formatNumber(value) {
        return new Intl.NumberFormat().format(Number(value || 0));
    }

    function formatMoney(value, currency) {
        return new Intl.NumberFormat(undefined, {
            style: 'currency',
            currency: currency || 'USD'
        }).format(Number(value || 0));
    }

    function formatScore(value) {
        if (value === null || value === undefined || value === '') return '--';
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed.toFixed(1) : '--';
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    function setValue(id, value) {
        const element = document.getElementById(id);
        if (element) element.value = value;
    }

    function setChecked(id, value) {
        const element = document.getElementById(id);
        if (element) element.checked = value;
    }

    function setButtonBusy(button, busy) {
        if (!button) return;
        button.disabled = busy;
        if (busy) {
            button.dataset.originalHtml = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        } else if (button.dataset.originalHtml) {
            button.innerHTML = button.dataset.originalHtml;
            delete button.dataset.originalHtml;
        }
    }

    function toast(message, type) {
        if (window.WebShield && typeof window.WebShield.showToast === 'function') {
            window.WebShield.showToast(message, type);
        } else {
            console[type === 'danger' ? 'error' : 'log'](message);
        }
    }
})();
