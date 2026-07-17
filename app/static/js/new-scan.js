/**
 * WebShield Scanner - New Scan JavaScript
 * Handles scan form validation and submission.
 */

(function() {
    'use strict';

    let isSubmitting = false;
    let validateController = null;
    let validationSequence = 0;

    /**
     * Initialize scan form.
     */
    window.initScanForm = function() {
        const form = document.getElementById('scan-form');
        if (!form) return;

        const urlInput = document.getElementById('scan-url');
        const confirmCheck = document.getElementById('confirm-auth');

        if (!urlInput) return;

        const debouncedValidate = WebShield.debounce(function(value) {
            validateUrl(value);
        }, 500);

        // Clear stale validation immediately, then validate after typing settles.
        urlInput.addEventListener('input', function() {
            resetValidationState(this.value);
            debouncedValidate(this.value);
        });

        form.addEventListener('submit', function(e) {
            e.preventDefault();
            handleScanSubmit(this);
        });

        if (confirmCheck) {
            confirmCheck.addEventListener('change', function() {
                updateSubmitButton();
            });
        }

        updateSubmitButton();
    };

    /**
     * Normalize a raw URL string consistently for validation and submission.
     */
    function normalizeUrl(rawUrl) {
        const url = (rawUrl || '').trim();
        if (!url) return '';
        return /^https?:\/\//i.test(url) ? url : 'https://' + url;
    }

    /**
     * Reset cached validation as soon as the field changes.
     */
    function resetValidationState(rawUrl) {
        const preview = document.getElementById('url-preview');
        const errorEl = document.getElementById('url-error');
        const submitBtn = document.getElementById('scan-btn');

        validationSequence += 1;
        if (validateController) {
            validateController.abort();
            validateController = null;
        }

        if (submitBtn) {
            submitBtn.dataset.urlValid = 'false';
            submitBtn.dataset.normalizedUrl = '';
            submitBtn.dataset.validatedFor = '';
        }

        if (errorEl) {
            errorEl.style.display = 'none';
        }

        if (preview) {
            if ((rawUrl || '').trim().length >= 3) {
                preview.textContent = 'Validating...';
                preview.style.display = 'block';
                preview.style.color = '#8899aa';
            } else {
                preview.style.display = 'none';
            }
        }

        updateSubmitButton();
    }

    /**
     * Validate URL.
     */
    function validateUrl(rawUrl) {
        const preview = document.getElementById('url-preview');
        const errorEl = document.getElementById('url-error');
        const submitBtn = document.getElementById('scan-btn');
        const urlInput = document.getElementById('scan-url');
        const requestedFor = (rawUrl || '').trim();

        if (!preview || !errorEl || !submitBtn || !urlInput) return;

        if (validateController) {
            validateController.abort();
            validateController = null;
        }

        if (requestedFor.length < 3) {
            preview.style.display = 'none';
            errorEl.style.display = 'none';
            submitBtn.dataset.urlValid = 'false';
            submitBtn.dataset.normalizedUrl = '';
            submitBtn.dataset.validatedFor = '';
            updateSubmitButton();
            return;
        }

        const requestId = validationSequence + 1;
        validationSequence = requestId;
        const normalizedUrl = normalizeUrl(requestedFor);
        validateController = new AbortController();

        window.api.scan.validate(normalizedUrl, { signal: validateController.signal, timeout: 10000 })
        .then(data => {
            if (requestId !== validationSequence || urlInput.value.trim() !== requestedFor) {
                return;
            }

            if (data.success && data.valid) {
                preview.textContent = 'Valid: ' + data.normalized_url;
                preview.style.display = 'block';
                preview.style.color = '#4caf50';
                errorEl.style.display = 'none';
                submitBtn.dataset.urlValid = 'true';
                submitBtn.dataset.normalizedUrl = data.normalized_url;
                submitBtn.dataset.validatedFor = requestedFor;
                updateSubmitButton();
            } else {
                preview.textContent = 'Invalid: ' + (data.error || data.message || 'Invalid URL');
                preview.style.display = 'block';
                preview.style.color = '#f44336';
                errorEl.textContent = data.error || data.message || 'Invalid URL';
                errorEl.style.display = 'block';
                submitBtn.dataset.urlValid = 'false';
                submitBtn.dataset.normalizedUrl = '';
                submitBtn.dataset.validatedFor = '';
                updateSubmitButton();
            }
        })
        .catch(err => {
            if (err.name === 'AbortError') {
                return;
            }
            if (requestId !== validationSequence || urlInput.value.trim() !== requestedFor) {
                return;
            }

            console.error('URL validation error:', err);
            preview.textContent = 'Validation failed';
            preview.style.display = 'block';
            preview.style.color = '#f44336';
            errorEl.textContent = 'Could not validate URL';
            errorEl.style.display = 'block';
            submitBtn.dataset.urlValid = 'false';
            submitBtn.dataset.normalizedUrl = '';
            submitBtn.dataset.validatedFor = '';
            updateSubmitButton();
        });
    }

    /**
     * Update submit button state.
     */
    function updateSubmitButton() {
        const confirmCheck = document.getElementById('confirm-auth');
        const submitBtn = document.getElementById('scan-btn');
        const urlInput = document.getElementById('scan-url');

        if (!confirmCheck || !submitBtn || !urlInput) return;

        const currentRaw = urlInput.value.trim();
        const isCurrentUrlValid = (
            submitBtn.dataset.urlValid === 'true' &&
            submitBtn.dataset.validatedFor === currentRaw
        );

        submitBtn.disabled = !confirmCheck.checked || !isCurrentUrlValid;
    }

    /**
     * Handle scan form submission.
     */
    function handleScanSubmit() {
        if (isSubmitting) return;

        const urlInput = document.getElementById('scan-url');
        const confirmCheck = document.getElementById('confirm-auth');
        const submitBtn = document.getElementById('scan-btn');

        if (!urlInput || !confirmCheck || !submitBtn) return;

        const currentRaw = urlInput.value.trim();
        const isStillValid = (
            submitBtn.dataset.urlValid === 'true' &&
            submitBtn.dataset.validatedFor === currentRaw
        );
        const url = isStillValid && submitBtn.dataset.normalizedUrl
            ? submitBtn.dataset.normalizedUrl
            : normalizeUrl(currentRaw);

        const deepCrawlEl = document.getElementById('deep-crawl');
        const checkSensitiveEl = document.getElementById('check-sensitive');
        const checkComponentsEl = document.getElementById('check-components');
        const deepCrawl = deepCrawlEl ? deepCrawlEl.checked : false;
        const checkSensitive = checkSensitiveEl ? checkSensitiveEl.checked : false;
        const checkComponents = checkComponentsEl ? checkComponentsEl.checked : false;

        if (!currentRaw) {
            WebShield.showToast('Please enter a URL to scan.', 'warning');
            return;
        }

        if (!isStillValid) {
            WebShield.showToast('Please wait for URL validation to finish before submitting.', 'warning');
            return;
        }

        if (!confirmCheck.checked) {
            WebShield.showToast('You must confirm authorization to scan this website.', 'warning');
            return;
        }

        isSubmitting = true;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting scan...';

        window.api.scan.start(url, confirmCheck.checked, {
            crawlDepth: deepCrawl ? 3 : 1,
            maxPages: deepCrawl ? 100 : 20,
            checkSensitive: checkSensitive,
            checkComponents: checkComponents
        })
        .then(data => {
            if (data.success) {
                WebShield.showToast('Scan started successfully!', 'success');
                window.location.href = '/scan-progress/' + data.scan_id;
            } else {
                WebShield.showToast(data.message || 'Failed to start scan.', 'danger');
                isSubmitting = false;
                submitBtn.innerHTML = '<i class="fas fa-shield-halved"></i> Start Scan';
                updateSubmitButton();
            }
        })
        .catch(err => {
            console.error('Scan start error:', err);
            WebShield.showToast('An error occurred. Please try again.', 'danger');
            isSubmitting = false;
            submitBtn.innerHTML = '<i class="fas fa-shield-halved"></i> Start Scan';
            updateSubmitButton();
        });
    }

})();
