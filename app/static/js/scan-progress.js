/**
 * WebShield Scanner - Scan Progress JavaScript
 * Handles real-time scan progress updates.
 */

(function() {
    'use strict';

    let scanInterval = null;
    let startTime = null;
    let timerInterval = null;
    let failureCount = 0;
    let cancelling = false;
    const maxFailures = 5;

    /**
     * Initialize scan progress tracking
     */
    window.initScanProgress = function(scanId) {
        if (!scanId) {
            console.error('No scan ID provided');
            return;
        }

        startTime = Date.now();
        updateTimer();

        // Start polling for progress
        fetchScanStatus(scanId);
        scanInterval = setInterval(function() {
            fetchScanStatus(scanId);
        }, 2000);

        // Timer update
        timerInterval = setInterval(updateTimer, 1000);

        // Cancel scan button
        const cancelBtn = document.getElementById('cancel-scan');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', function() {
                cancelScan(scanId);
            });
        }
    };

    /**
     * Fetch scan status from server
     */
    function fetchScanStatus(scanId) {
        if (!window.api || !window.api.isAuthenticated()) {
            stopPolling();
            window.location.href = '/login';
            return;
        }

        window.api.scan.status(scanId, { timeout: 10000 })
        .then(data => {
            if (data.success) {
                failureCount = 0;
                updateProgress(data.scan);
            } else {
                console.error('Failed to fetch scan status:', data.message);
            }
        })
        .catch(error => {
            console.error('Error fetching scan status:', error);
            failureCount += 1;
            if (error.status === 401) {
                stopPolling();
                WebShield.showToast('Your session expired. Please sign in again.', 'warning');
                window.location.href = '/login';
                return;
            }
            if (failureCount >= maxFailures) {
                stopPolling();
                WebShield.showToast('Lost connection to scan status updates. Refresh to try again.', 'warning');
            }
        });
    }

    /**
     * Update progress UI
     */
    function updateProgress(scan) {
        const statusText = document.getElementById('status-text');
        const progressFill = document.getElementById('progress-fill');
        const pagesCrawled = document.getElementById('pages-crawled');
        const findingsFound = document.getElementById('findings-found');
        const scanUrl = document.getElementById('scan-url-display');

        // Update URL
        if (scanUrl) {
            scanUrl.textContent = scan.target_url;
        }

        // Update status
        if (statusText) {
            const statusMap = {
                'pending': 'Initializing scan...',
                'running': 'Scanning in progress...',
                'completed': 'Scan complete!',
                'failed': 'Scan failed',
                'cancelled': 'Scan cancelled'
            };
            statusText.textContent = statusMap[scan.scan_status] || scan.scan_status;
        }

        // Update progress bar
        if (progressFill) {
            let progress = 0;
            if (scan.scan_status === 'completed') {
                progress = 100;
            } else if (scan.scan_status === 'running') {
                // Estimate progress based on pages crawled
                const maxPages = scan.max_pages || 100;
                progress = Math.min(95, (scan.pages_crawled || 0) / maxPages * 100);
            } else if (scan.scan_status === 'pending') {
                progress = 5;
            }
            progressFill.style.width = progress + '%';
        }

        // Update stats
        if (pagesCrawled) {
            pagesCrawled.textContent = scan.pages_crawled || 0;
        }
        if (findingsFound) {
            findingsFound.textContent = scan.total_findings || 0;
        }

        // Add log entries
        if (scan.scan_status === 'running' && scan.pages_crawled > 0) {
            addLogEntry('Crawled ' + scan.pages_crawled + ' pages so far...', 'info');
        }

        // Check if scan is complete
        if (scan.scan_status === 'completed') {
            completeScan(scan);
        } else if (scan.scan_status === 'failed') {
            failScan(scan);
        } else if (scan.scan_status === 'cancelled') {
            cancelScanUI(scan);
        }
    }

    /**
     * Update elapsed timer
     */
    function updateTimer() {
        const elapsedEl = document.getElementById('elapsed-time');
        if (!elapsedEl) return;

        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const minutes = String(Math.floor(elapsed / 60)).padStart(2, '0');
        const seconds = String(elapsed % 60).padStart(2, '0');
        elapsedEl.textContent = minutes + ':' + seconds;
    }

    /**
     * Add a log entry
     */
    function addLogEntry(message, type = 'info') {
        const logContainer = document.getElementById('scan-log');
        if (!logContainer) return;

        const time = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const timeEl = document.createElement('span');
        timeEl.className = 'time';
        timeEl.textContent = '[' + time + ']';
        const messageEl = document.createElement('span');
        messageEl.className = safeLogType(type);
        messageEl.textContent = message;
        entry.appendChild(timeEl);
        entry.appendChild(document.createTextNode(' '));
        entry.appendChild(messageEl);
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    /**
     * Complete the scan
     */
    function completeScan(scan) {
        // Stop polling
        stopPolling();

        // Update final score
        const finalScore = document.getElementById('final-score');
        if (finalScore) {
            const score = normalizeScore(scan.security_score);
            finalScore.textContent = score === null ? '--/100' : score + '/100';
            finalScore.className = 'score-display ' + scoreClassFor(score);
        }

        // Update risk level
        const riskEl = document.getElementById('final-risk');
        if (riskEl) {
            riskEl.textContent = 'Risk Level: ' + (scan.risk_level ? scan.risk_level.toUpperCase() : 'Unknown');
        }

        // Update findings count
        const findingsEl = document.getElementById('final-findings');
        if (findingsEl) {
            findingsEl.textContent = 'Findings: ' + (scan.total_findings || 0);
        }

        // Set report link
        const reportBtn = document.getElementById('view-report-btn');
        if (reportBtn) {
            reportBtn.href = '/report/' + scan.id;
        }

        // Show complete UI, hide progress UI
        document.getElementById('scan-status').style.display = 'none';
        document.getElementById('scan-complete').style.display = 'block';

        // Add final log entry
        addLogEntry('Scan completed successfully!', 'success');
    }

    /**
     * Fail the scan
     */
    function failScan(scan) {
        stopPolling();

        const statusText = document.getElementById('status-text');
        if (statusText) {
            statusText.textContent = 'Scan failed: ' + (scan.summary || 'Unknown error');
            statusText.style.color = '#f44336';
        }

        addLogEntry('Scan failed: ' + (scan.summary || 'Unknown error'), 'error');
    }

    /**
     * Cancel the scan
     */
    function cancelScan(scanId) {
        if (cancelling) return;
        if (!confirm('Are you sure you want to cancel this scan?')) return;

        cancelling = true;
        const cancelBtn = document.getElementById('cancel-scan');
        if (cancelBtn) {
            cancelBtn.disabled = true;
            cancelBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';
        }

        window.api.scan.cancel(scanId, { timeout: 10000 })
        .then(data => {
            if (data.success) {
                WebShield.showToast('Scan cancelled.', 'info');
                cancelScanUI();
            } else {
                cancelling = false;
                if (cancelBtn) cancelBtn.disabled = false;
                WebShield.showToast(data.message || 'Failed to cancel scan.', 'danger');
            }
        })
        .catch(error => {
            console.error('Cancel scan error:', error);
            cancelling = false;
            if (cancelBtn) cancelBtn.disabled = false;
            WebShield.showToast(error.message || 'An error occurred. Please try again.', 'danger');
        });
    }

    /**
     * Cancel scan UI
     */
    function cancelScanUI() {
        stopPolling();

        const statusText = document.getElementById('status-text');
        if (statusText) {
            statusText.textContent = 'Scan cancelled';
            statusText.style.color = '#ff9800';
        }

        const cancelBtn = document.getElementById('cancel-scan');
        if (cancelBtn) {
            cancelBtn.disabled = true;
            cancelBtn.innerHTML = '<i class="fas fa-ban"></i> Cancelled';
        }

        addLogEntry('Scan cancelled by user.', 'warning');

        // Redirect to dashboard after delay
        setTimeout(function() {
            window.location.href = '/dashboard';
        }, 3000);
    }

    function stopPolling() {
        if (scanInterval) {
            clearInterval(scanInterval);
            scanInterval = null;
        }
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }

    function safeLogType(type) {
        return ['info', 'success', 'warning', 'error'].includes(type) ? type : 'info';
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

})();
