/**
 * WebShield Scanner - Dashboard JavaScript
 * Handles dashboard statistics and recent scans.
 */

(function() {
    'use strict';

    window.loadDashboardStats = function() {
        if (!window.api || !window.api.isAuthenticated()) return;

        window.api.scan.stats()
            .then(data => {
                if (data.success) {
                    updateStats(data.stats || {});
                } else {
                    console.error('Failed to load stats:', data.message);
                }
            })
            .catch(error => {
                console.error('Error loading stats:', error);
            });
    };

    function updateStats(stats) {
        setText('stat-scans', stats.total_scans || 0);

        const scoreEl = document.getElementById('stat-score');
        if (scoreEl) {
            const score = normalizeScore(stats.average_score);
            scoreEl.textContent = score === null ? '--' : score;
            scoreEl.className = 'stat-number';
            if (score === null) {
                scoreEl.classList.add('text-muted');
            } else if (score >= 80) {
                scoreEl.classList.add('stat-score-good');
            } else if (score >= 60) {
                scoreEl.classList.add('stat-score-medium');
            } else {
                scoreEl.classList.add('stat-score-bad');
            }
        }

        const totalFindings = Object.values(stats.findings_by_severity || {})
            .reduce((sum, value) => sum + Number(value || 0), 0);
        setText('stat-findings', totalFindings);
        setText(
            'stat-remaining',
            stats.remaining_scans !== null && stats.remaining_scans !== undefined
                ? stats.remaining_scans
                : 'Unlimited'
        );
    }

    window.loadRecentScans = function() {
        if (!window.api || !window.api.isAuthenticated()) return;

        window.api.scan.history(1, 5)
            .then(data => {
                if (data.success && Array.isArray(data.scans) && data.scans.length > 0) {
                    renderRecentScans(data.scans);
                } else {
                    renderNoScans();
                }
            })
            .catch(error => {
                console.error('Error loading recent scans:', error);
                renderNoScans();
            });
    };

    function renderRecentScans(scans) {
        const container = document.getElementById('recent-scans-list');
        if (!container) return;

        container.innerHTML = scans.map(scan => {
            const status = safeStatus(scan.scan_status);
            const score = normalizeScore(scan.security_score);
            const scoreClass = scoreClassFor(score);
            const icon = statusIcon(status);
            const color = statusColor(status);

            return `
                <div class="scan-item">
                    <div class="scan-info">
                        <div class="scan-url">${escapeHtml(scan.target_url)}</div>
                        <div class="scan-date">
                            <i class="fas ${icon}" style="color:${color}"></i>
                            ${WebShield.formatDate(scan.created_at, 'relative')}
                            ${status === 'completed' ? ` - ${Number(scan.total_findings || 0)} findings` : ''}
                        </div>
                    </div>
                    ${status === 'completed' ? `
                        <div class="scan-score ${scoreClass}">${score === null ? '--' : score}</div>
                    ` : `
                        <div class="scan-score" style="color:${color};font-size:0.7rem;text-transform:uppercase;">
                            ${escapeHtml(status)}
                        </div>
                    `}
                </div>
            `;
        }).join('');
    }

    function renderNoScans() {
        const container = document.getElementById('recent-scans-list');
        if (!container) return;

        container.innerHTML = `
            <div class="no-scans">
                <i class="fas fa-search"></i>
                <p>No scans yet. Start your first scan!</p>
                <a href="/new-scan" class="btn btn-primary btn-sm mt-2">Start Scanning</a>
            </div>
        `;
    }

    function statusIcon(status) {
        return {
            completed: 'fa-check-circle',
            running: 'fa-spinner fa-spin',
            pending: 'fa-clock',
            failed: 'fa-exclamation-circle',
            cancelled: 'fa-ban'
        }[status] || 'fa-circle';
    }

    function statusColor(status) {
        return {
            completed: '#4caf50',
            running: '#00f0ff',
            pending: '#ff9800',
            failed: '#f44336',
            cancelled: '#8899aa'
        }[status] || '#667';
    }

    function safeStatus(status) {
        const normalized = String(status || 'unknown').toLowerCase();
        return ['completed', 'running', 'pending', 'failed', 'cancelled'].includes(normalized)
            ? normalized
            : 'unknown';
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    function normalizeScore(score) {
        if (score === null || score === undefined || score === '') return null;
        const parsed = Number(score);
        return Number.isFinite(parsed) ? parsed : null;
    }

    function scoreClassFor(score) {
        if (score === null) return 'text-muted';
        if (score >= 80) return 'score-good';
        if (score >= 60) return 'score-medium';
        return 'score-bad';
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text === null || text === undefined ? '' : String(text);
        return div.innerHTML;
    }

})();
