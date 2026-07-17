/**
 * WebShield Scanner - Attack Surface Map JavaScript
 * Handles attack surface visualization and data display.
 */

(function() {
    'use strict';

    const EMPTY_SURFACE = {
        target_url: '',
        total_pages: 0,
        endpoints: [],
        forms: [],
        login_pages: [],
        api_endpoints: [],
        admin_pages: [],
        technologies: [],
        file_types: {},
        directories: [],
        entry_points: [],
        exit_points: [],
        owasp_buckets: [],
        attack_paths: [],
        review_priorities: [],
        trust_boundaries: [],
        sensitive_data_signals: [],
        honeypot_assessment: null,
        risk_score: 0,
        risk_level: 'unknown',
        exposure_summary: ''
    };

    /**
     * Load attack surface data.
     */
    window.loadAttackSurface = function(scanId) {
        const normalizedScanId = Number(scanId);
        if (!Number.isInteger(normalizedScanId) || normalizedScanId <= 0) {
            showNoData('Invalid scan id');
            return;
        }

        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }

        setText('surface-url', 'Loading...');

        window.api.report.get(normalizedScanId)
        .then(data => {
            if (!data.success || !data.report || !data.report.scan) {
                WebShield.showToast(data.message || 'Failed to load attack surface data.', 'danger');
                showNoData();
                return;
            }

            const scan = data.report.scan;
            const surfaceData = normalizeSurfaceData(scan.attack_surface_data, scan.target_url);

            if (!hasSurfaceData(surfaceData)) {
                showNoData('No attack surface data available for this scan');
                return;
            }

            renderAttackSurface(surfaceData);
            renderNetwork(surfaceData);
        })
        .catch(error => {
            console.error('Error loading attack surface:', error);
            WebShield.showToast(error.message || 'An error occurred. Please try again.', 'danger');
            showNoData();
        });
    };

    function normalizeSurfaceData(data, targetUrl) {
        const source = data && typeof data === 'object' ? data : {};
        return {
            ...EMPTY_SURFACE,
            ...source,
            target_url: source.target_url || targetUrl || '',
            total_pages: Number(source.total_pages || 0),
            endpoints: asArray(source.endpoints),
            forms: asArray(source.forms),
            login_pages: asArray(source.login_pages),
            api_endpoints: asArray(source.api_endpoints),
            admin_pages: asArray(source.admin_pages),
            technologies: asArray(source.technologies),
            file_types: source.file_types && typeof source.file_types === 'object' ? source.file_types : {},
            directories: asArray(source.directories),
            entry_points: asArray(source.entry_points),
            exit_points: asArray(source.exit_points),
            owasp_buckets: asArray(source.owasp_buckets),
            attack_paths: asArray(source.attack_paths),
            review_priorities: asArray(source.review_priorities),
            trust_boundaries: asArray(source.trust_boundaries),
            sensitive_data_signals: asArray(source.sensitive_data_signals),
            honeypot_assessment: source.honeypot_assessment && typeof source.honeypot_assessment === 'object'
                ? source.honeypot_assessment
                : null,
            risk_score: Number(source.risk_score || 0),
            risk_level: source.risk_level || 'unknown',
            exposure_summary: source.exposure_summary || ''
        };
    }

    function hasSurfaceData(data) {
        return Boolean(
            data.total_pages ||
            data.endpoints.length ||
            data.forms.length ||
            data.login_pages.length ||
            data.api_endpoints.length ||
            data.admin_pages.length ||
            data.technologies.length ||
            Object.keys(data.file_types).length ||
            data.directories.length ||
            data.attack_paths.length ||
            data.owasp_buckets.length
        );
    }

    function renderNetwork(surfaceData) {
        const canvas = document.getElementById('surface-map-canvas');
        if (!canvas) return;

        if (typeof window.destroyNetworkMap === 'function') {
            window.destroyNetworkMap();
        }

        if (typeof window.initNetworkMap !== 'function') {
            canvas.innerHTML = '<div class="no-data">Network map renderer is unavailable</div>';
            return;
        }

        window.initNetworkMap('surface-map-canvas', surfaceData);
    }

    /**
     * Render attack surface data.
     */
    function renderAttackSurface(data) {
        setText('surface-url', data.target_url || 'Unknown target');
        setText('stat-pages', data.total_pages || 0);
        setText('stat-endpoints', data.endpoints.length);
        setText('stat-forms', data.forms.length);
        setText('stat-login', data.login_pages.length);
        setText('stat-api', data.api_endpoints.length);
        setText('stat-admin', data.admin_pages.length);
        renderPentestSummary(data);

        renderTechnologies(data.technologies);
        renderFileTypes(data.file_types);
        renderList('directories-list', data.directories, 'No directories detected');
        renderList('login-list', data.login_pages, 'No login pages detected');
        renderList('api-list', data.api_endpoints, 'No API endpoints detected');
        renderList('admin-list', data.admin_pages, 'No admin pages detected');
        renderOwaspBuckets(data.owasp_buckets);
        renderAttackPaths(data.attack_paths);
        renderSensitiveSignals(data.sensitive_data_signals);
        renderTrustBoundaries(data.trust_boundaries);
        renderReviewPriorities(data.review_priorities);
        renderEntryExitPoints(data.entry_points, data.exit_points);
    }

    function renderPentestSummary(data) {
        setText('surface-risk-score', data.risk_score || 0);
        setText('surface-exposure-summary', data.exposure_summary || 'No exposure summary available.');

        const level = document.getElementById('surface-risk-level');
        if (level) {
            const risk = String(data.risk_level || 'unknown').toLowerCase();
            level.textContent = risk;
            level.className = `risk-level ${risk}`;
        }

        const honeypot = data.honeypot_assessment || {};
        const container = document.getElementById('honeypot-summary');
        if (!container) return;

        const indicators = asArray(honeypot.indicators);
        const notes = asArray(honeypot.notes);
        container.innerHTML = `
            <div><span class="risk-level ${escapeAttribute(honeypot.likelihood || 'unknown')}">${escapeHtml(honeypot.likelihood || 'unknown')}</span></div>
            <div style="margin-top:8px;">${escapeHtml(notes[0] || 'No deception indicators available.')}</div>
            ${indicators.length ? `<div class="meta" style="margin-top:8px;">Signals: ${indicators.map(item => escapeHtml(item.type || 'indicator')).join(', ')}</div>` : ''}
        `;
    }

    function renderTechnologies(technologies) {
        const container = document.getElementById('tech-list');
        if (!container) return;

        if (!technologies.length) {
            container.innerHTML = '<div class="no-data">No technologies detected</div>';
            return;
        }

        container.innerHTML = technologies
            .slice(0, 60)
            .map(tech => `<span class="tech-tag">${escapeHtml(tech)}</span>`)
            .join('');
    }

    function renderFileTypes(fileTypes) {
        const container = document.getElementById('file-types-list');
        if (!container) return;

        const entries = Object.entries(fileTypes)
            .filter(([ext]) => ext)
            .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0));

        if (!entries.length) {
            container.innerHTML = '<div class="no-data">No files detected</div>';
            return;
        }

        container.innerHTML = entries.slice(0, 50).map(([ext, count]) => `
            <div class="item">
                <span>.<strong>${escapeHtml(ext)}</strong></span>
                <span class="badge-count">${Number(count || 0)}</span>
            </div>
        `).join('');
    }

    function renderList(containerId, items, emptyMessage) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!items.length) {
            container.innerHTML = `<div class="no-data">${escapeHtml(emptyMessage || 'None detected')}</div>`;
            return;
        }

        const displayItems = items.slice(0, 50);
        const hasMore = items.length > 50;

        container.innerHTML = displayItems.map(item => {
            const text = typeof item === 'string' ? item : JSON.stringify(item);
            return `<div class="item">${safeUrlOrText(text)}</div>`;
        }).join('');

        if (hasMore) {
            container.innerHTML += `<div class="item" style="color:var(--text-dim);font-style:italic;">+ ${items.length - 50} more...</div>`;
        }
    }

    function renderOwaspBuckets(buckets) {
        const container = document.getElementById('owasp-buckets-list');
        if (!container) return;

        if (!buckets.length) {
            container.innerHTML = '<div class="no-data">No review buckets available</div>';
            return;
        }

        container.innerHTML = buckets
            .filter(bucket => Number(bucket.count || 0) > 0)
            .slice(0, 12)
            .map(bucket => `
                <div class="analysis-card">
                    <div class="card-title">
                        <span>${escapeHtml(bucket.name)}</span>
                        <span class="severity-pill ${escapeAttribute(bucket.risk || 'medium')}">${escapeHtml(bucket.risk || 'medium')} · ${Number(bucket.count || 0)}</span>
                    </div>
                    <div>${escapeHtml(bucket.description || '')}</div>
                    ${renderMiniList('Test focus', bucket.testing_focus)}
                    ${renderMiniList('Examples', bucket.examples)}
                </div>
            `)
            .join('') || '<div class="no-data">No active review buckets detected</div>';
    }

    function renderAttackPaths(paths) {
        const container = document.getElementById('attack-paths-list');
        if (!container) return;

        if (!paths.length) {
            container.innerHTML = '<div class="no-data">No attack paths inferred</div>';
            return;
        }

        container.innerHTML = paths.slice(0, 10).map(path => `
            <div class="analysis-card">
                <div class="card-title">
                    <span>${escapeHtml(path.title)}</span>
                    <span class="severity-pill ${escapeAttribute(path.severity || 'medium')}">${escapeHtml(path.severity || 'medium')}</span>
                </div>
                <div>${escapeHtml(path.how_it_could_be_hacked || '')}</div>
                ${renderMiniList('Start with', path.entry)}
                ${renderMiniList('Pentest steps', path.pentest_steps)}
            </div>
        `).join('');
    }

    function renderSensitiveSignals(signals) {
        const container = document.getElementById('sensitive-data-list');
        if (!container) return;

        if (!signals.length) {
            container.innerHTML = '<div class="no-data">No sensitive data signals inferred</div>';
            return;
        }

        container.innerHTML = signals.slice(0, 10).map(signal => `
            <div class="analysis-card">
                <div class="card-title">
                    <span>${escapeHtml(signal.data_type)}</span>
                    <span class="severity-pill medium">${escapeHtml(signal.confidence || 'medium')}</span>
                </div>
                ${renderMiniList('Evidence', signal.evidence)}
                ${renderMiniList('Review focus', signal.review_focus)}
            </div>
        `).join('');
    }

    function renderTrustBoundaries(boundaries) {
        const container = document.getElementById('trust-boundaries-list');
        if (!container) return;

        if (!boundaries.length) {
            container.innerHTML = '<div class="no-data">No trust boundaries inferred</div>';
            return;
        }

        container.innerHTML = boundaries.slice(0, 10).map(boundary => `
            <div class="analysis-card">
                <div class="card-title">
                    <span>${escapeHtml(boundary.name)}</span>
                    <span class="severity-pill ${escapeAttribute(boundary.risk || 'medium')}">${escapeHtml(boundary.risk || 'medium')}</span>
                </div>
                <div>${escapeHtml(boundary.evidence || '')}</div>
                ${renderMiniList('Controls to verify', boundary.controls_to_verify)}
            </div>
        `).join('');
    }

    function renderReviewPriorities(priorities) {
        const container = document.getElementById('review-priorities-list');
        if (!container) return;

        if (!priorities.length) {
            container.innerHTML = '<div class="no-data">No priorities available</div>';
            return;
        }

        container.innerHTML = priorities.slice(0, 10).map(priority => `
            <div class="analysis-card">
                <div class="card-title">
                    <span>${escapeHtml(priority.area)}</span>
                    <span class="severity-pill ${escapeAttribute(priority.priority || 'medium')}">${escapeHtml(priority.priority || 'medium')}</span>
                </div>
                <div>${escapeHtml(priority.why || '')}</div>
                ${renderMiniList('Start with', priority.start_with)}
                ${renderMiniList('Test for', priority.test_for)}
            </div>
        `).join('');
    }

    function renderEntryExitPoints(entryPoints, exitPoints) {
        const container = document.getElementById('entry-exit-list');
        if (!container) return;

        const combined = [
            ...entryPoints.slice(0, 10).map(item => ({ ...item, direction: 'Entry' })),
            ...exitPoints.slice(0, 10).map(item => ({ ...item, direction: 'Exit' }))
        ];

        if (!combined.length) {
            container.innerHTML = '<div class="no-data">No entry or exit points available</div>';
            return;
        }

        container.innerHTML = combined.map(point => `
            <div class="analysis-card">
                <div class="card-title">
                    <span>${escapeHtml(point.direction)} · ${escapeHtml(point.type)}</span>
                    <span class="severity-pill ${escapeAttribute(point.risk || 'medium')}">${escapeHtml(point.risk || 'medium')}</span>
                </div>
                <div>${safeUrlOrText(point.value || '')}</div>
                <div class="meta">${escapeHtml(point.reason || '')}</div>
            </div>
        `).join('');
    }

    function renderMiniList(label, values) {
        const items = asArray(values).filter(Boolean).slice(0, 6);
        if (!items.length) return '';
        return `
            <div class="meta">
                <strong>${escapeHtml(label)}:</strong>
                ${items.map(item => `<span>${escapeHtml(typeof item === 'string' ? item : JSON.stringify(item))}</span>`).join(' · ')}
            </div>
        `;
    }

    function showNoData(message) {
        setText('surface-url', message || 'No attack surface data available');
        [
            'tech-list', 'file-types-list', 'directories-list', 'login-list', 'api-list', 'admin-list',
            'owasp-buckets-list', 'attack-paths-list', 'sensitive-data-list', 'trust-boundaries-list',
            'review-priorities-list', 'entry-exit-list'
        ].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = '<div class="no-data">No data available</div>';
        });

        ['stat-pages', 'stat-endpoints', 'stat-forms', 'stat-login', 'stat-api', 'stat-admin'].forEach(id => {
            setText(id, '0');
        });

        const canvas = document.getElementById('surface-map-canvas');
        if (canvas) {
            canvas.innerHTML = `<div class="no-data">${escapeHtml(message || 'No map data available')}</div>`;
        }
        setText('surface-risk-score', '0');
        setText('surface-exposure-summary', message || 'No attack surface data available');
        const level = document.getElementById('surface-risk-level');
        if (level) {
            level.textContent = 'unknown';
            level.className = 'risk-level minimal';
        }
        const honeypot = document.getElementById('honeypot-summary');
        if (honeypot) honeypot.innerHTML = '<div class="no-data">No deception analysis available</div>';
    }

    function asArray(value) {
        return Array.isArray(value) ? value.filter(item => item !== null && item !== undefined) : [];
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    }

    function safeUrlOrText(value) {
        const text = String(value || '');
        if (!/^https?:\/\//i.test(text)) {
            return escapeHtml(text);
        }

        try {
            const parsed = new URL(text);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return `<a href="${escapeAttribute(parsed.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
            }
        } catch (err) {
            // Fall through to plain text.
        }
        return escapeHtml(text);
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text === null || text === undefined ? '' : String(text);
        return div.innerHTML;
    }

    function escapeAttribute(text) {
        return escapeHtml(text).replace(/"/g, '&quot;');
    }
})();
