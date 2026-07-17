import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanApi } from '../api/scanApi.js';
import { getToken } from '../api/client.js';
import '../styles/global.css';

const normalizeUrl = (rawUrl) => {
  const value = (rawUrl || '').trim();
  if (!value) return '';
  return /^https?:\/\//i.test(value) ? value : `https://${value}`;
};

const NewScan = () => {
  const navigate = useNavigate();
  const validationRequestRef = useRef(0);
  const [url, setUrl] = useState('');
  const [confirmAuth, setConfirmAuth] = useState(false);
  const [deepCrawl, setDeepCrawl] = useState(false);
  const [checkSensitive, setCheckSensitive] = useState(false);
  const [checkComponents, setCheckComponents] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [validating, setValidating] = useState(false);
  const [isValid, setIsValid] = useState(null);
  const [normalizedUrl, setNormalizedUrl] = useState('');
  const [validatedFor, setValidatedFor] = useState('');

  useEffect(() => {
    const currentRaw = url.trim();
    const requestId = validationRequestRef.current + 1;
    validationRequestRef.current = requestId;

    setError('');
    setIsValid(null);
    setNormalizedUrl('');
    setValidatedFor('');
    setValidating(false);

    if (currentRaw.length <= 3) {
      return undefined;
    }

    const timeoutId = window.setTimeout(async () => {
      setValidating(true);

      try {
        const response = await scanApi.validateUrl(normalizeUrl(currentRaw));
        if (validationRequestRef.current !== requestId) {
          return;
        }

        if (response.success && response.valid) {
          setIsValid(true);
          setNormalizedUrl(response.normalized_url);
          setValidatedFor(currentRaw);
        } else {
          setIsValid(false);
          setError(response.error || response.message || 'Invalid URL');
        }
      } catch (err) {
        if (validationRequestRef.current !== requestId) {
          return;
        }
        setIsValid(false);
        setError(err.message || 'Could not validate URL');
      } finally {
        if (validationRequestRef.current === requestId) {
          setValidating(false);
        }
      }
    }, 500);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [url]);

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    const currentRaw = url.trim();
    const isStillValid = isValid === true && validatedFor === currentRaw;

    if (!currentRaw) {
      setError('Please enter a URL to scan.');
      return;
    }

    if (!confirmAuth) {
      setError('You must confirm authorization to scan this website.');
      return;
    }

    if (!isStillValid) {
      setError('Please wait for URL validation to finish before submitting.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await scanApi.startScan(
        normalizedUrl || normalizeUrl(currentRaw),
        confirmAuth,
        {
          crawlDepth: deepCrawl ? 3 : 1,
          maxPages: deepCrawl ? 100 : 20,
          checkSensitive,
          checkComponents
        }
      );

      if (response.success) {
        navigate(`/scan-progress/${response.scan_id}`);
      } else {
        setError(response.message || 'Failed to start scan.');
      }
    } catch (err) {
      console.error('Scan start error:', err);
      setError(err.message || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-radar"></i> New Scan
        </h1>
      </div>

      <div className="scan-form-container">
        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <label className="form-label">
              <i className="fas fa-link"></i> Target URL
            </label>
            <input
              type="url"
              className={`form-control ${isValid === true ? 'is-valid' : ''} ${isValid === false ? 'is-invalid' : ''}`}
              placeholder="https://example.com"
              value={url}
              onChange={handleUrlChange}
              required
              disabled={loading}
            />
            {validating && (
              <div className="url-preview" style={{ display: 'block', color: '#8899aa' }}>
                <i className="fas fa-spinner fa-spin"></i> Validating...
              </div>
            )}
            {isValid && normalizedUrl && (
              <div className="url-preview" style={{ display: 'block', color: '#4caf50' }}>
                <i className="fas fa-check-circle"></i> {normalizedUrl}
              </div>
            )}
            {isValid === false && (
              <div className="validation-error" style={{ display: 'block' }}>
                <i className="fas fa-exclamation-circle"></i> {error}
              </div>
            )}
          </div>

          <div className="scan-options">
            <label className="form-label">
              <i className="fas fa-sliders-h"></i> Scan Options
            </label>

            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="deep-crawl"
                checked={deepCrawl}
                onChange={(e) => setDeepCrawl(e.target.checked)}
                disabled={loading}
              />
              <label className="form-check-label" htmlFor="deep-crawl">
                Deep Crawl (up to 100 pages)
              </label>
            </div>

            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="check-sensitive"
                checked={checkSensitive}
                onChange={(e) => setCheckSensitive(e.target.checked)}
                disabled={loading}
              />
              <label className="form-check-label" htmlFor="check-sensitive">
                Check for Sensitive Files
              </label>
            </div>

            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="check-components"
                checked={checkComponents}
                onChange={(e) => setCheckComponents(e.target.checked)}
                disabled={loading}
              />
              <label className="form-check-label" htmlFor="check-components">
                Check Outdated Components
              </label>
            </div>
          </div>

          <div className="legal-warning">
            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="confirm-auth"
                checked={confirmAuth}
                onChange={(e) => setConfirmAuth(e.target.checked)}
                required
                disabled={loading}
              />
              <label className="form-check-label" htmlFor="confirm-auth">
                <i className="fas fa-gavel"></i>
                I confirm that <strong>I own this website</strong> or have <strong>written permission</strong> to test it.
              </label>
            </div>
          </div>

          {error && (
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-circle me-2"></i>
              {error}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-scan"
            disabled={loading || !confirmAuth || isValid !== true || validatedFor !== url.trim()}
          >
            {loading ? (
              <><i className="fas fa-spinner fa-spin"></i> Starting scan...</>
            ) : (
              <><i className="fas fa-shield-halved"></i> Start Scan</>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default NewScan;
