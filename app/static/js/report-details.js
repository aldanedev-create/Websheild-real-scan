/**
 * WebShield Scanner - Report Details JavaScript
 * Handles report viewing, filtering, triage, and export.
 */

(function() {
    'use strict';

    const severityOrder = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4
    };

    let currentReport = null;
    let controlsInitialized = false;
    const state = {
        severity: 'all',
        category: 'all',
        query: '',
        view: 'grouped'
    };

    /**
     * Load report data.
     */
    window.loadReport = function(scanId) {
        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }

        window.api.report.get(scanId)
        .then(data => {
            if (data.success) {
                currentReport = normalizeReport(data.report);
                renderReport(currentReport);
            } else {
                WebShield.showToast(data.message || 'Failed to load report.', 'danger');
                if (data.message === 'Scan not found') {
                    window.location.href = '/dashboard';
                }
            }
        })
        .catch(err => {
            console.error('Error loading report:', err);
            WebShield.showToast('An error occurred. Please try again.', 'danger');
        });
    };

    function normalizeReport(report) {
        const findings = Array.isArray(report.findings) ? report.findings : [];
        const triage = report.triage || {};
        triage.grouped_findings = Array.isArray(triage.grouped_findings)
            ? triage.grouped_findings
            : groupFindings(findings);
        triage.priority_findings = Array.isArray(triage.priority_findings)
            ? triage.priority_findings
            : triage.grouped_findings.filter(group => ['critical', 'high', 'medium'].includes(group.severity)).slice(0, 10);
        triage.category_overview = Array.isArray(triage.category_overview)
            ? triage.category_overview
            : buildCategoryOverview(triage.grouped_findings);
        triage.total_instances = triage.total_instances || findings.length;
        triage.total_groups = triage.total_groups || triage.grouped_findings.length;
        triage.duplicate_instances = triage.duplicate_instances || Math.max(0, findings.length - triage.grouped_findings.length);
        report.triage = triage;
        return report;
    }

    function renderReport(report) {
        const scan = report.scan;

        renderHeader(scan);
        renderSummaryStats(report.summary || {}, report.triage || {});
        renderTriagePanel(report.triage || {});
        renderCategoryOverview(report.triage || {});
        populateCategoryFilter(report.triage || {});
        setupControls();
        applyFilters();
    }

    function renderHeader(scan) {
        const scoreCircle = document.getElementById('score-circle');
        if (scoreCircle) {
            const score = normalizeScore(scan.security_score);
            scoreCircle.textContent = score === null ? '--' : score;
            scoreCircle.className = 'score-circle ' + scoreClassFor(score);
        }

        setText('report-url', scan.target_url || 'Unknown target');
        setText('report-date', 'Started: ' + WebShield.formatDate(scan.created_at, 'long'));
        setText('report-duration', 'Duration: ' + (scan.duration || 0) + 's');
        setText('report-pages', (scan.pages_crawled || 0) + ' pages');
    }

    function renderSummaryStats(summary, triage) {
        const container = document.getElementById('summary-stats');
        if (!container) return;

        const severities = summary.by_severity || {};
        const total = summary.total_findings || triage.total_instances || 0;

        container.innerHTML = [
            statHtml(total, 'Total'),
            statHtml(triage.total_groups || 0, 'Groups'),
            statHtml(triage.duplicate_instances || 0, 'Repeated'),
            statHtml(severities.critical || 0, 'Critical', '#f44336'),
            statHtml(severities.high || 0, 'High', '#ff6b6b'),
            statHtml(severities.medium || 0, 'Medium', '#ff9800'),
            statHtml(severities.low || 0, 'Low', '#4caf50'),
            statHtml(severities.info || 0, 'Info', '#8899aa')
        ].join('');
    }

    function renderTriagePanel(triage) {
        const container = document.getElementById('triage-panel');
        if (!container) return;

        const priority = triage.priority_findings || [];
        const priorityHtml = priority.length
            ? priority.slice(0, 6).map(group => `
                <div class="priority-item ${escapeHtml(group.severity || 'info')}">
                    <div class="meta">P${group.priority_rank || ''} / ${escapeHtml(group.category_label || formatCategory(group.category))}</div>
                    <div class="title">${escapeHtml(group.title)}</div>
                    <div class="reason">${escapeHtml(group.triage_reason || group.recommendation || '')}</div>
                </div>
            `).join('')
            : '<div class="no-findings"><p>No high-priority findings.</p></div>';

        container.innerHTML = `
            <div class="triage-section">
                <div class="triage-section-title"><i class="fas fa-bullseye"></i> Triage Snapshot</div>
                <div class="triage-metrics">
                    ${triageMetricHtml(triage.total_groups || 0, 'Unique Issues')}
                    ${triageMetricHtml(triage.total_instances || 0, 'Instances')}
                    ${triageMetricHtml(triage.affected_url_count || 0, 'Affected URLs')}
                    ${triageMetricHtml((triage.priority_findings || []).length, 'Priorities')}
                    ${triageMetricHtml((triage.quick_wins || []).length, 'Quick Wins')}
                    ${triageMetricHtml(triage.duplicate_instances || 0, 'Repeated')}
                </div>
            </div>
            <div class="triage-section">
                <div class="triage-section-title"><i class="fas fa-list-check"></i> Priority Queue</div>
                <div class="priority-list">${priorityHtml}</div>
            </div>
        `;
    }

    function renderCategoryOverview(triage) {
        const container = document.getElementById('category-overview');
        if (!container) return;

        const categories = triage.category_overview || [];
        if (!categories.length) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = `
            <div class="category-overview-title"><i class="fas fa-folder-tree"></i> Categories</div>
            ${categories.map(category => `
                <button class="category-chip ${escapeHtml(category.highest_severity || 'info')} ${state.category === category.category ? 'active' : ''}"
                        type="button"
                        data-category="${escapeAttribute(category.category)}">
                    <span class="name">${escapeHtml(category.label || formatCategory(category.category))}</span>
                    <span class="counts">${category.count || 0} findings / ${category.group_count || 0} groups</span>
                </button>
            `).join('')}
        `;

        container.querySelectorAll('.category-chip').forEach(button => {
            button.addEventListener('click', function() {
                state.category = this.dataset.category || 'all';
                const select = document.getElementById('category-filter');
                if (select) select.value = state.category;
                renderCategoryOverview(currentReport.triage);
                applyFilters();
            });
        });
    }

    function populateCategoryFilter(triage) {
        const select = document.getElementById('category-filter');
        if (!select) return;

        const categories = triage.category_overview || [];
        select.innerHTML = '<option value="all">All categories</option>' + categories.map(category => (
            `<option value="${escapeAttribute(category.category)}">${escapeHtml(category.label || formatCategory(category.category))}</option>`
        )).join('');
        select.value = state.category;
    }

    function setupControls() {
        if (controlsInitialized) return;
        controlsInitialized = true;

        const filterContainer = document.getElementById('finding-filters');
        if (filterContainer) {
            filterContainer.querySelectorAll('.filter-btn').forEach(button => {
                button.addEventListener('click', function() {
                    state.severity = this.dataset.severity || 'all';
                    filterContainer.querySelectorAll('.filter-btn').forEach(item => item.classList.remove('active'));
                    this.classList.add('active');
                    applyFilters();
                });
            });
        }

        const categorySelect = document.getElementById('category-filter');
        if (categorySelect) {
            categorySelect.addEventListener('change', function() {
                state.category = this.value || 'all';
                renderCategoryOverview(currentReport.triage);
                applyFilters();
            });
        }

        const search = document.getElementById('finding-search');
        if (search) {
            const debouncedSearch = WebShield.debounce(function(value) {
                state.query = (value || '').trim().toLowerCase();
                applyFilters();
            }, 150);

            search.addEventListener('input', function() {
                debouncedSearch(this.value);
            });
        }

        const viewToggle = document.getElementById('view-toggle');
        if (viewToggle) {
            viewToggle.querySelectorAll('.view-btn').forEach(button => {
                button.addEventListener('click', function() {
                    state.view = this.dataset.view || 'grouped';
                    viewToggle.querySelectorAll('.view-btn').forEach(item => item.classList.remove('active'));
                    this.classList.add('active');
                    applyFilters();
                });
            });
        }
    }

    function applyFilters() {
        if (!currentReport) return;

        const source = state.view === 'instances'
            ? currentReport.findings
            : currentReport.triage.grouped_findings;

        const filtered = source.filter(item => {
            const severity = item.severity || 'info';
            const category = item.category || 'uncategorized';
            if (state.severity !== 'all' && severity !== state.severity) return false;
            if (state.category !== 'all' && category !== state.category) return false;
            if (state.query && !searchCorpus(item).includes(state.query)) return false;
            return true;
        }).sort((a, b) => {
            return (severityOrder[a.severity] || 9) - (severityOrder[b.severity] || 9);
        });

        renderFindings(filtered, state.view);
        renderResultMeta(filtered.length, source.length);
    }

    function renderFindings(items, view) {
        const container = document.getElementById('finding-list');
        if (!container) return;

        if (!items || !items.length) {
            container.innerHTML = `
                <div class="no-findings">
                    <i class="fas fa-search"></i>
                    <p>No matching findings.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = items.map(item => {
            return view === 'instances' ? renderInstance(item) : renderGroup(item);
        }).join('');
    }

    function renderGroup(group) {
        const severity = group.severity || 'info';
        const urls = Array.isArray(group.affected_urls) ? group.affected_urls : [];
        const visibleUrls = urls.slice(0, 5);
        const hiddenCount = Math.max(0, urls.length - visibleUrls.length);
        const evidence = Array.isArray(group.evidence_samples) && group.evidence_samples.length
            ? group.evidence_samples[0]
            : '';

        return `
            <div class="finding-item ${safeClass(severity)}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">${escapeHtml(group.title)}</div>
                        <div class="finding-count">${group.count || 0} finding(s) / ${group.affected_url_count || urls.length} affected URL(s)</div>
                    </div>
                    <span class="finding-severity severity-${safeClass(severity)}">${escapeHtml(severity.toUpperCase())}</span>
                </div>
                <div class="finding-body">
                    ${group.description ? `<div><strong>Description:</strong> ${escapeHtml(group.description)}</div>` : ''}
                    ${evidence ? `<div class="evidence"><strong>Evidence:</strong> ${escapeHtml(evidence)}</div>` : ''}
                    ${group.recommendation ? `<div class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(group.recommendation)}</div>` : ''}
                    ${visibleUrls.length ? `
                        <div class="affected-url-list">
                            ${visibleUrls.map(url => safeUrlHtml(url)).join('')}
                            ${hiddenCount ? `<span>+${hiddenCount} more affected URL(s)</span>` : ''}
                        </div>
                    ` : ''}
                    ${metaTagsHtml(group)}
                </div>
            </div>
        `;
    }

    function renderInstance(finding) {
        const severity = finding.severity || 'info';
        return `
            <div class="finding-item ${safeClass(severity)}">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(finding.title)}</div>
                    <span class="finding-severity severity-${safeClass(severity)}">${escapeHtml(severity.toUpperCase())}</span>
                </div>
                <div class="finding-body">
                    ${finding.affected_url ? `<div><strong>URL:</strong> ${escapeHtml(finding.affected_url)}</div>` : ''}
                    ${finding.description ? `<div><strong>Description:</strong> ${escapeHtml(finding.description)}</div>` : ''}
                    ${finding.evidence ? `<div class="evidence"><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</div>` : ''}
                    ${finding.recommendation ? `<div class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</div>` : ''}
                    ${metaTagsHtml(finding)}
                </div>
            </div>
        `;
    }

    /**
     * Export report with the Authorization header preserved.
     */
    window.exportReport = function(format) {
        if (!currentReport || !currentReport.scan) return;

        const scanId = currentReport.scan.id;
        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }

        const exportFormat = ['html', 'pdf', 'json'].includes(format) ? format : 'json';
        const button = document.querySelector(`.report-actions button[onclick="exportReport('${exportFormat}')"]`);
        const originalHtml = button ? button.innerHTML : '';

        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Exporting';
        }

        if (exportFormat === 'json') {
            return window.api.get('/report/' + encodeURIComponent(scanId) + '/export/json')
                .then(payload => ({
                    blob: new Blob([JSON.stringify(payload.data || payload, null, 2)], { type: 'application/json' }),
                    filename: `webshield_report_${scanId}.json`
                }))
                .then(file => {
                    downloadBlob(file.blob, window.api.sanitizeFilename(file.filename));
                    WebShield.showToast('JSON report exported successfully.', 'success');
                })
                .catch(err => {
                    console.error('Export error:', err);
                    WebShield.showToast(err.message || 'Export failed.', 'danger');
                })
                .finally(() => {
                    if (button) {
                        button.disabled = false;
                        button.innerHTML = originalHtml;
                    }
                });
        }

        window.api.report.export(scanId, exportFormat)
        .then(file => {
            if (exportFormat === 'json') {
                return file;
            }
            downloadBlob(file.blob, file.filename);
            WebShield.showToast(exportFormat.toUpperCase() + ' report exported successfully.', 'success');
        })
        .catch(err => {
            console.error('Export error:', err);
            WebShield.showToast(err.message || 'Export failed.', 'danger');
        })
        .finally(() => {
            if (button) {
                button.disabled = false;
                button.innerHTML = originalHtml;
            }
        });
    };

    function renderResultMeta(count, total) {
        const meta = document.getElementById('report-result-meta');
        if (!meta) return;

        const label = state.view === 'instances' ? 'instances' : 'groups';
        meta.textContent = `${count} of ${total} ${label}`;
    }

    function groupFindings(findings) {
        const map = new Map();

        findings.forEach(finding => {
            const key = [
                finding.title,
                finding.severity,
                finding.category,
                finding.description,
                finding.recommendation,
                finding.cwe_id,
                finding.owasp_category
            ].join('|');

            if (!map.has(key)) {
                map.set(key, {
                    title: finding.title,
                    severity: finding.severity,
                    severity_label: (finding.severity || 'info').toUpperCase(),
                    category: finding.category,
                    category_label: formatCategory(finding.category),
                    description: finding.description,
                    recommendation: finding.recommendation,
                    cwe_id: finding.cwe_id,
                    owasp_category: finding.owasp_category,
                    count: 0,
                    affected_urls: [],
                    evidence_samples: [],
                    affected_url_count: 0
                });
            }

            const group = map.get(key);
            group.count += 1;
            if (finding.affected_url && !group.affected_urls.includes(finding.affected_url)) {
                group.affected_urls.push(finding.affected_url);
            }
            if (finding.evidence && !group.evidence_samples.includes(finding.evidence)) {
                group.evidence_samples.push(finding.evidence);
            }
            group.affected_url_count = group.affected_urls.length;
        });

        return Array.from(map.values());
    }

    function buildCategoryOverview(groups) {
        const map = new Map();
        groups.forEach(group => {
            const category = group.category || 'uncategorized';
            if (!map.has(category)) {
                map.set(category, {
                    category: category,
                    label: formatCategory(category),
                    count: 0,
                    group_count: 0,
                    highest_severity: group.severity || 'info'
                });
            }
            const item = map.get(category);
            item.count += group.count || 0;
            item.group_count += 1;
            if ((severityOrder[group.severity] || 9) < (severityOrder[item.highest_severity] || 9)) {
                item.highest_severity = group.severity;
            }
        });
        return Array.from(map.values());
    }

    function searchCorpus(item) {
        const parts = [
            item.title,
            item.category,
            item.category_label,
            item.severity,
            item.description,
            item.recommendation,
            item.evidence,
            item.affected_url,
            ...(item.affected_urls || []),
            ...(item.evidence_samples || [])
        ];

        return parts.filter(Boolean).join(' ').toLowerCase();
    }

    function metaTagsHtml(item) {
        const tags = [];
        if (item.cwe_id) tags.push(`CWE-${escapeHtml(item.cwe_id)}`);
        if (item.owasp_category) tags.push(`OWASP: ${escapeHtml(item.owasp_category)}`);
        if (item.category || item.category_label) {
            tags.push(`Category: ${escapeHtml(item.category_label || formatCategory(item.category))}`);
        }
        if (!tags.length) return '';
        return `<div class="meta-tags">${tags.map(tag => `<span>${tag}</span>`).join('')}</div>`;
    }

    function statHtml(number, label, color) {
        const style = color ? ` style="color:${color};"` : '';
        return `
            <div class="summary-stat">
                <div class="num"${style}>${number}</div>
                <div class="label">${escapeHtml(label)}</div>
            </div>
        `;
    }

    function triageMetricHtml(number, label) {
        return `
            <div class="triage-metric">
                <div class="num">${number}</div>
                <div class="label">${escapeHtml(label)}</div>
            </div>
        `;
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function formatCategory(category) {
        return (category || 'uncategorized')
            .replace(/[_-]+/g, ' ')
            .replace(/\b\w/g, letter => letter.toUpperCase());
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
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    function escapeAttribute(text) {
        return escapeHtml(text).replace(/"/g, '&quot;');
    }

    function safeClass(value) {
        return String(value || 'info').toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'info';
    }

    function safeUrlHtml(url) {
        const text = String(url || '');
        try {
            if (!/^https?:\/\//i.test(text)) return `<span>${escapeHtml(text)}</span>`;
            const parsed = new URL(text);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return `<a href="${escapeAttribute(parsed.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
            }
        } catch (err) {
            // Fall through to text rendering.
        }
        return `<span>${escapeHtml(text)}</span>`;
    }

})();
