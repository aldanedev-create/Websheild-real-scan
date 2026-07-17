# -*- coding: utf-8 -*-

"""
WebShield Scanner - JavaScript Analyzer
Passively inspects same-origin client-side JavaScript for risky auth,
CSRF, and async validation patterns.
"""

import re
from urllib.parse import urljoin, urlparse

import requests
from flask import current_app, has_app_context
from app.scanner.url_validator import URLValidator


class JavaScriptAnalyzer:
    """Analyze browser-visible JavaScript without executing it."""

    TOKEN_KEY_PATTERN = re.compile(
        r"localStorage\s*\.\s*(?:getItem|setItem|removeItem)\s*\(\s*"
        r"(?P<quote>['\"`])(?P<key>[^'\"`]+)(?P=quote)",
        re.IGNORECASE,
    )
    FETCH_PATTERN = re.compile(r"\bfetch\s*\(", re.IGNORECASE)
    STATE_CHANGING_METHOD_PATTERN = re.compile(
        r"\bmethod\s*:\s*['\"`](POST|PUT|PATCH|DELETE)['\"`]",
        re.IGNORECASE,
    )
    CSRF_PATTERN = re.compile(r"csrf|xsrf|authenticity", re.IGNORECASE)
    API_ENDPOINT_PATTERN = re.compile(
        r"['\"](?P<endpoint>(?:https?://[^'\"]+|/)[^'\"]*"
        r"(?:/api/|/graphql|/auth|/login|/logout|/oauth|/token)[^'\"]*)['\"]",
        re.IGNORECASE,
    )
    URL_DATA_PATTERN = re.compile(
        r"location\.(?:hash|search|href)|document\.URL|document\.location|"
        r"URLSearchParams|\.searchParams\.get\s*\(",
        re.IGNORECASE,
    )
    HTML_SINK_PATTERN = re.compile(
        r"\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(",
        re.IGNORECASE,
    )
    REDIRECT_PARAM_PATTERN = re.compile(
        r"(?:next|redirect|redirect_uri|return|return_to|continue|url|target|destination)",
        re.IGNORECASE,
    )
    SECRET_PATTERNS = [
        (
            "Google or Firebase API Key Exposed in JavaScript",
            r"AIza[0-9A-Za-z\-_]{35}",
            "medium",
            "A Google/Firebase-style API key is present in browser-visible JavaScript. Public API keys should be tightly restricted by referrer, API, and quota.",
            "Restrict the key in the provider console, move privileged operations server-side, and rotate the key if it was unrestricted.",
            "CWE-798",
            "Sensitive Data Exposure",
        ),
        (
            "Stripe Secret Key Exposed in JavaScript",
            r"sk_(?:live|test)_[0-9A-Za-z]{16,}",
            "critical",
            "A Stripe secret key appears in browser-visible JavaScript. Secret keys can authorize privileged payment API actions.",
            "Revoke and rotate the key immediately. Use only publishable keys in client code and perform privileged payment actions server-side.",
            "CWE-798",
            "Sensitive Data Exposure",
        ),
        (
            "AWS Access Key ID Exposed in JavaScript",
            r"AKIA[0-9A-Z]{16}",
            "critical",
            "An AWS access key ID appears in browser-visible JavaScript. If paired with a secret, it can enable cloud account abuse.",
            "Remove the key from client code, rotate the IAM credentials, and use short-lived server-issued credentials with least privilege.",
            "CWE-798",
            "Sensitive Data Exposure",
        ),
        (
            "GitHub Token Exposed in JavaScript",
            r"gh[pousr]_[A-Za-z0-9_]{30,}",
            "critical",
            "A GitHub token appears in browser-visible JavaScript and may allow repository or account access.",
            "Revoke the token immediately, rotate affected credentials, and keep GitHub tokens server-side.",
            "CWE-798",
            "Sensitive Data Exposure",
        ),
        (
            "Slack Token Exposed in JavaScript",
            r"xox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,}",
            "critical",
            "A Slack token appears in browser-visible JavaScript and may allow workspace API access.",
            "Revoke the token immediately and move Slack API calls that require secrets to the server.",
            "CWE-798",
            "Sensitive Data Exposure",
        ),
    ]

    def __init__(self, session=None):
        """Initialize analyzer defaults."""
        self.session = session or requests.Session()
        config = current_app.config if has_app_context() else {}
        self.timeout = config.get("REQUEST_TIMEOUT", 30)
        self.max_scripts = config.get("MAX_JS_FILES_TO_SCAN", 25)
        self.max_bytes = config.get("MAX_JS_BYTES_TO_SCAN", 500_000)
        self.max_redirects = config.get("MAX_SCAN_REDIRECTS", 5)
        self.user_agent = config.get("USER_AGENT", "WebShield-Scanner/1.0")
        self.validator = URLValidator()
        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": (
                    "application/javascript,text/javascript,"
                    "application/x-javascript,text/plain,*/*;q=0.8"
                ),
            }
        )

    def scan(self, pages, target_url=None, auth_cookie=None):
        """
        Scan same-origin JavaScript assets and inline scripts.

        Args:
            pages: Crawled page data.
            target_url: Original scan target URL.
            auth_cookie: Optional simple auth cookie for authenticated scans.

        Returns:
            dict: Findings and JavaScript scan summary.
        """
        if not pages:
            return {"findings": [], "scripts": [], "summary": {"total_scripts": 0}}

        self._set_auth_cookie(auth_cookie)

        scripts = self._collect_scripts(pages, target_url)
        findings = []
        scanned_scripts = []
        api_endpoints = set()

        for script in scripts[: self.max_scripts]:
            content = script.get("content")
            source_url = script.get("url")

            if content is None:
                content = self._fetch_script(source_url)

            if not content:
                continue

            scanned_scripts.append(
                {
                    "url": source_url,
                    "inline": script.get("inline", False),
                    "bytes_scanned": min(len(content.encode("utf-8", "ignore")), self.max_bytes),
                }
            )
            api_endpoints.update(self._extract_api_endpoints(content))
            findings.extend(self._analyze_script(content, source_url))

        unique_findings = self._dedupe_findings(findings)

        return {
            "findings": unique_findings,
            "scripts": scanned_scripts,
            "api_endpoints": sorted(api_endpoints),
            "summary": {
                "total_scripts": len(scripts),
                "scripts_scanned": len(scanned_scripts),
                "scripts_skipped": max(0, len(scripts) - len(scanned_scripts)),
                "api_endpoints_found": len(api_endpoints),
                "total_findings": len(unique_findings),
                "severity_breakdown": self._get_severity_breakdown(unique_findings),
            },
        }

    def _set_auth_cookie(self, auth_cookie):
        if not auth_cookie:
            return
        try:
            cookie_name, cookie_value = auth_cookie.split("=", 1)
        except ValueError:
            return
        if cookie_name.strip() and cookie_value:
            self.session.cookies.set(cookie_name.strip(), cookie_value.strip())

    def _collect_scripts(self, pages, target_url):
        target_domain = self._domain(target_url or pages[0].get("url", ""))
        scripts = []
        seen_external = set()

        for page in pages:
            page_url = page.get("url", "")
            page_domain = self._domain(page_url) or target_domain

            for script_url in page.get("scripts", []):
                if not script_url or script_url in seen_external:
                    continue
                if not self._is_same_origin_script(script_url, page_domain, target_domain):
                    continue
                seen_external.add(script_url)
                scripts.append({"url": script_url, "inline": False})

            for index, inline_script in enumerate(page.get("inline_scripts", []), start=1):
                if isinstance(inline_script, dict):
                    content = inline_script.get("content", "")
                else:
                    content = str(inline_script or "")
                if content.strip():
                    scripts.append(
                        {
                            "url": f"{page_url}#inline-script-{index}",
                            "inline": True,
                            "content": content[: self.max_bytes],
                        }
                    )

        return scripts

    def _is_same_origin_script(self, script_url, page_domain, target_domain):
        script_domain = self._domain(script_url)
        allowed_domains = {domain for domain in (page_domain, target_domain) if domain}
        return script_domain in allowed_domains

    def _domain(self, url):
        if not url:
            return ""
        parsed = urlparse(url)
        return (parsed.netloc or "").lower()

    def _fetch_script(self, script_url):
        redirects = 0
        current_url = script_url

        try:
            while True:
                is_valid, error = self.validator.validate(current_url)
                if not is_valid:
                    if has_app_context():
                        current_app.logger.debug("Blocked script target %s: %s", current_url, error)
                    return None

                response = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                )

                if 300 <= response.status_code < 400:
                    if redirects >= self.max_redirects:
                        return None
                    location = response.headers.get("Location")
                    if not location:
                        return None
                    current_url = self.validator.normalize_url(urljoin(response.url or current_url, location))
                    redirects += 1
                    continue

                response.raise_for_status()
                break
        except requests.RequestException as exc:
            if has_app_context():
                current_app.logger.debug("Could not fetch script %s: %s", script_url, exc)
            return None

        content_type = response.headers.get("Content-Type", "").lower()
        path = urlparse(script_url).path.lower()
        if "javascript" not in content_type and "text/plain" not in content_type and not path.endswith(".js"):
            return None

        return response.content[: self.max_bytes].decode(
            response.encoding or "utf-8",
            errors="replace",
        )

    def _analyze_script(self, content, source_url):
        findings = []

        findings.extend(self._check_local_storage_tokens(content, source_url))
        findings.extend(self._check_bearer_from_local_storage(content, source_url))
        findings.extend(self._check_fetch_without_csrf(content, source_url))
        findings.extend(self._check_shadowed_catch_error(content, source_url))
        findings.extend(self._check_stale_async_validation(content, source_url))
        findings.extend(self._check_hardcoded_authorization_confirmation(content, source_url))
        findings.extend(self._check_insecure_api_calls(content, source_url))
        findings.extend(self._check_exposed_secrets(content, source_url))
        findings.extend(self._check_url_to_html_sinks(content, source_url))
        findings.extend(self._check_unsafe_postmessage(content, source_url))
        findings.extend(self._check_dangerous_code_execution(content, source_url))
        findings.extend(self._check_client_side_open_redirect(content, source_url))
        findings.extend(self._check_weak_client_crypto(content, source_url))
        findings.extend(self._check_jwt_decode_without_verify(content, source_url))
        findings.extend(self._check_sensitive_console_logging(content, source_url))
        findings.extend(self._check_sourcemap_reference(content, source_url))
        findings.extend(self._check_user_data_in_local_storage(content, source_url))

        return findings

    def _check_local_storage_tokens(self, content, source_url):
        findings = []
        for match in self.TOKEN_KEY_PATTERN.finditer(content):
            key = match.group("key")
            if not self._looks_like_auth_key(key):
                continue
            findings.append(
                self._finding(
                    title="Authentication Token Stored in localStorage",
                    severity="high",
                    url=source_url,
                    description=(
                        "Client-side JavaScript reads or writes an authentication-like "
                        "token in localStorage, which is accessible to any script that "
                        "runs on the page after an XSS bug."
                    ),
                    evidence=self._evidence(content, match.start()),
                    recommendation=(
                        "Prefer httpOnly, Secure, SameSite cookies for browser sessions. "
                        "If bearer tokens are required, keep them short-lived and rotate "
                        "refresh tokens."
                    ),
                    cwe_id="CWE-922",
                    owasp_category="Sensitive Data Exposure",
                )
            )
            break
        return findings

    def _check_bearer_from_local_storage(self, content, source_url):
        if not (
            re.search(r"Authorization", content, re.IGNORECASE)
            and re.search(r"Bearer", content, re.IGNORECASE)
            and re.search(r"localStorage", content, re.IGNORECASE)
        ):
            return []

        index = re.search(r"Authorization", content, re.IGNORECASE).start()
        return [
            self._finding(
                title="Bearer Authorization Header Built from Browser Storage",
                severity="high",
                url=source_url,
                description=(
                    "JavaScript appears to build a Bearer Authorization header from "
                    "browser storage. A successful XSS can steal or replay that token."
                ),
                evidence=self._evidence(content, index),
                recommendation=(
                    "Use httpOnly cookies for session credentials where possible, or "
                    "minimize token lifetime and enforce refresh-token rotation."
                ),
                cwe_id="CWE-922",
                owasp_category="Sensitive Data Exposure",
            )
        ]

    def _check_fetch_without_csrf(self, content, source_url):
        findings = []
        for match in self.FETCH_PATTERN.finditer(content):
            block = content[match.start() : match.start() + 2000]
            method_match = self.STATE_CHANGING_METHOD_PATTERN.search(block)
            if not method_match or self.CSRF_PATTERN.search(block):
                continue

            findings.append(
                self._finding(
                    title="State-Changing Fetch Without CSRF Token",
                    severity="medium",
                    url=source_url,
                    description=(
                        "A fetch call uses a state-changing HTTP method without an "
                        "obvious CSRF token or XSRF header in the request block."
                    ),
                    evidence=self._evidence(content, match.start()),
                    recommendation=(
                        "Require CSRF tokens for cookie-authenticated state changes. "
                        "For bearer-only APIs, keep SameSite cookies strict and document "
                        "why CSRF is not applicable."
                    ),
                    cwe_id="CWE-352",
                    owasp_category="Insecure Design",
                )
            )
            break
        return findings

    def _check_shadowed_catch_error(self, content, source_url):
        findings = []
        dom_error_names = {
            match.group("name")
            for match in re.finditer(
                r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
                r"document\.getElementById\(\s*['\"][^'\"]*error[^'\"]*['\"]",
                content,
                re.IGNORECASE,
            )
        }

        for name in dom_error_names:
            catch_pattern = re.compile(
                r"\.catch\s*\(\s*" + re.escape(name) + r"\s*=>",
                re.IGNORECASE,
            )
            catch_match = catch_pattern.search(content)
            if not catch_match:
                continue

            catch_block = content[catch_match.start() : catch_match.start() + 1200]
            if not re.search(
                r"\b" + re.escape(name) + r"\s*\.\s*(textContent|innerHTML|style)\b",
                catch_block,
            ):
                continue

            findings.append(
                self._finding(
                    title="Catch Handler Shadows Error DOM Element",
                    severity="medium",
                    url=source_url,
                    description=(
                        "A catch parameter uses the same name as an error display DOM "
                        "element, so UI error updates may target the thrown Error object "
                        "instead of the page element."
                    ),
                    evidence=self._evidence(content, catch_match.start()),
                    recommendation=(
                        "Use distinct names such as errorEl for DOM nodes and err for "
                        "caught exceptions."
                    ),
                    cwe_id="CWE-563",
                    owasp_category="Security Misconfiguration",
                )
            )
            break
        return findings

    def _check_stale_async_validation(self, content, source_url):
        has_validation_flow = re.search(
            r"validateUrl|validateURL|/validate|urlValid|normalizedUrl|setNormalizedUrl",
            content,
            re.IGNORECASE,
        )
        has_async_input = re.search(
            r"addEventListener\(\s*['\"]input|onChange|debounce|setTimeout",
            content,
            re.IGNORECASE,
        )
        has_fetch = self.FETCH_PATTERN.search(content)
        has_cancellation_or_sequence = re.search(
            r"AbortController|\.abort\s*\(|validatedFor|requestId|sequence|validationRequest",
            content,
            re.IGNORECASE,
        )

        findings = []
        if has_validation_flow and has_async_input and has_fetch and not has_cancellation_or_sequence:
            index = has_validation_flow.start()
            findings.append(
                self._finding(
                    title="Async Validation Lacks Stale Response Protection",
                    severity="medium",
                    url=source_url,
                    description=(
                        "Client-side validation appears to run asynchronously from user "
                        "input without AbortController, request sequencing, or an input "
                        "snapshot check. Slow earlier responses can overwrite newer UI state."
                    ),
                    evidence=self._evidence(content, index),
                    recommendation=(
                        "Abort superseded validation requests or tag each request with a "
                        "sequence/input value and ignore stale responses."
                    ),
                    cwe_id="CWE-362",
                    owasp_category="Insecure Design",
                )
            )

        has_cached_url = re.search(
            r"dataset\.normalizedUrl|setNormalizedUrl|normalizedUrl",
            content,
            re.IGNORECASE,
        )
        has_submit = re.search(r"handleScanSubmit|handleSubmit|submit", content, re.IGNORECASE)
        if has_cached_url and has_submit and not has_cancellation_or_sequence:
            findings.append(
                self._finding(
                    title="Cached URL Validation Can Become Stale",
                    severity="medium",
                    url=source_url,
                    description=(
                        "Submit logic appears to rely on a cached normalized URL or "
                        "validation flag without proving it still corresponds to the "
                        "current input value."
                    ),
                    evidence=self._evidence(content, has_cached_url.start()),
                    recommendation=(
                        "Store the raw input value that produced the successful validation "
                        "and compare it to the current field value at submit time."
                    ),
                    cwe_id="CWE-345",
                    owasp_category="Insecure Design",
                )
            )

        return findings

    def _check_hardcoded_authorization_confirmation(self, content, source_url):
        match = re.search(
            r"confirm[_A-Za-z]*authorization\s*:\s*true",
            content,
            re.IGNORECASE,
        )
        if not match:
            return []

        return [
            self._finding(
                title="Authorization Confirmation Hardcoded Client-Side",
                severity="medium",
                url=source_url,
                description=(
                    "JavaScript hardcodes an authorization-confirmation field to true. "
                    "A client-side checkbox alone does not enforce permission to scan or "
                    "modify a target."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation=(
                    "Send the live control value and enforce authorization policy on the "
                    "server with audit logging and abuse controls."
                ),
                cwe_id="CWE-602",
                owasp_category="Broken Access Control",
            )
        ]

    def _check_insecure_api_calls(self, content, source_url):
        match = re.search(
            r"fetch\s*\(\s*['\"]http://[^'\"]+['\"]",
            content,
            re.IGNORECASE,
        )
        if not match:
            return []

        return [
            self._finding(
                title="Insecure HTTP API Call in JavaScript",
                severity="high",
                url=source_url,
                description=(
                    "Client-side JavaScript calls an API over plain HTTP, exposing "
                    "requests and responses to interception or modification."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation="Use HTTPS for all API calls and redirect HTTP to HTTPS.",
                cwe_id="CWE-319",
                owasp_category="Cryptographic Failures",
            )
        ]

    def _check_exposed_secrets(self, content, source_url):
        findings = []
        for title, pattern, severity, description, recommendation, cwe_id, owasp_category in self.SECRET_PATTERNS:
            match = re.search(pattern, content)
            if not match:
                continue
            findings.append(
                self._finding(
                    title=title,
                    severity=severity,
                    url=source_url,
                    description=description,
                    evidence=self._evidence(content, match.start()),
                    recommendation=recommendation,
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                )
            )

        generic_secret = re.search(
            r"\b(?:api[_-]?secret|client[_-]?secret|private[_-]?key|secret[_-]?key)\b"
            r"\s*[:=]\s*['\"][^'\"]{20,}['\"]",
            content,
            re.IGNORECASE,
        )
        if generic_secret:
            findings.append(
                self._finding(
                    title="Secret-Like Value Hardcoded in JavaScript",
                    severity="high",
                    url=source_url,
                    description=(
                        "A variable or object property with a secret-like name is assigned "
                        "a long literal value in browser-visible JavaScript."
                    ),
                    evidence=self._evidence(content, generic_secret.start()),
                    recommendation=(
                        "Move secrets to server-side configuration, rotate any exposed "
                        "credentials, and only expose public identifiers to the browser."
                    ),
                    cwe_id="CWE-798",
                    owasp_category="Sensitive Data Exposure",
                )
            )

        return findings

    def _check_url_to_html_sinks(self, content, source_url):
        findings = []
        for source_match in self.URL_DATA_PATTERN.finditer(content):
            block_start = max(0, source_match.start() - 400)
            block_end = min(len(content), source_match.end() + 900)
            block = content[block_start:block_end]
            sink_match = self.HTML_SINK_PATTERN.search(block)
            if not sink_match:
                continue

            findings.append(
                self._finding(
                    title="URL-Derived Data Written to HTML Sink",
                    severity="high",
                    url=source_url,
                    description=(
                        "JavaScript appears to route URL-derived data into an HTML sink "
                        "such as innerHTML, outerHTML, insertAdjacentHTML, or document.write. "
                        "This is a common DOM XSS pattern."
                    ),
                    evidence=self._evidence(content, block_start + sink_match.start()),
                    recommendation=(
                        "Use textContent for plain text, sanitize trusted markup with a "
                        "maintained sanitizer, and avoid rendering location/search/hash data as HTML."
                    ),
                    cwe_id="CWE-79",
                    owasp_category="Injection",
                )
            )
            break
        return findings

    def _check_unsafe_postmessage(self, content, source_url):
        findings = []

        wildcard_target = re.search(
            r"\.postMessage\s*\([^)]*,\s*['\"]\*['\"]",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if wildcard_target:
            findings.append(
                self._finding(
                    title="postMessage Uses Wildcard Target Origin",
                    severity="medium",
                    url=source_url,
                    description=(
                        "postMessage sends data with targetOrigin '*', allowing any "
                        "recipient origin to receive the message if window references change."
                    ),
                    evidence=self._evidence(content, wildcard_target.start()),
                    recommendation=(
                        "Set targetOrigin to the exact expected origin and avoid sending "
                        "tokens or personal data through cross-window messages."
                    ),
                    cwe_id="CWE-346",
                    owasp_category="Security Misconfiguration",
                )
            )

        listener = re.search(
            r"addEventListener\s*\(\s*['\"]message['\"]",
            content,
            re.IGNORECASE,
        )
        if listener:
            block = content[listener.start() : listener.start() + 1800]
            if not re.search(r"\.origin\b|origin\s*[!=]==|allowedOrigins?|trustedOrigins?", block, re.IGNORECASE):
                findings.append(
                    self._finding(
                        title="message Event Listener Missing Origin Check",
                        severity="medium",
                        url=source_url,
                        description=(
                            "A message event listener does not appear to validate event.origin "
                            "before processing incoming data."
                        ),
                        evidence=self._evidence(content, listener.start()),
                        recommendation=(
                            "Check event.origin against an allowlist before trusting event.data, "
                            "and validate the message schema."
                        ),
                        cwe_id="CWE-346",
                        owasp_category="Security Misconfiguration",
                    )
                )

        return findings

    def _check_dangerous_code_execution(self, content, source_url):
        findings = []
        dangerous_call = re.search(
            r"\beval\s*\(|\bFunction\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['\"`]",
            content,
        )
        if not dangerous_call:
            return findings

        surrounding = content[max(0, dangerous_call.start() - 500) : dangerous_call.end() + 500]
        severity = "high" if self.URL_DATA_PATTERN.search(surrounding) else "medium"
        findings.append(
            self._finding(
                title="Dynamic Code Execution in Client JavaScript",
                severity=severity,
                url=source_url,
                description=(
                    "JavaScript uses eval, Function, or string-based timers. These APIs "
                    "increase XSS impact and are especially dangerous when influenced by URL or user data."
                ),
                evidence=self._evidence(content, dangerous_call.start()),
                recommendation=(
                    "Replace dynamic code execution with explicit function calls or a safe parser "
                    "for the expected data format."
                ),
                cwe_id="CWE-95",
                owasp_category="Injection",
            )
        )
        return findings

    def _check_client_side_open_redirect(self, content, source_url):
        redirect_source = re.search(
            r"(URLSearchParams|searchParams\.get|location\.search).*?"
            r"(next|redirect|redirect_uri|return|return_to|continue|url|target|destination)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        location_sink = re.search(
            r"(?:window\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()",
            content,
            re.IGNORECASE,
        )
        if not redirect_source or not location_sink:
            return []

        start = min(redirect_source.start(), location_sink.start())
        end = max(redirect_source.end(), location_sink.end())
        if end - start > 2500:
            return []

        return [
            self._finding(
                title="Client-Side Redirect Uses URL Parameter",
                severity="medium",
                url=source_url,
                description=(
                    "JavaScript appears to read a redirect-like URL parameter and assign it "
                    "to window.location. Without an allowlist, this can become an open redirect."
                ),
                evidence=self._evidence(content, location_sink.start()),
                recommendation=(
                    "Only redirect to relative paths or explicit allowlisted origins, and "
                    "validate redirects on the server as well."
                ),
                cwe_id="CWE-601",
                owasp_category="Broken Access Control",
            )
        ]

    def _check_weak_client_crypto(self, content, source_url):
        findings = []
        weak_random = re.search(
            r"Math\.random\s*\(\s*\).*?(token|secret|password|nonce|csrf|state|uuid|session|key)|"
            r"(token|secret|password|nonce|csrf|state|uuid|session|key).*?Math\.random\s*\(",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if weak_random and weak_random.end() - weak_random.start() < 800:
            findings.append(
                self._finding(
                    title="Security-Sensitive Value Uses Math.random",
                    severity="medium",
                    url=source_url,
                    description=(
                        "Math.random appears near generation of a security-sensitive value. "
                        "It is not cryptographically secure."
                    ),
                    evidence=self._evidence(content, weak_random.start()),
                    recommendation="Use crypto.getRandomValues or server-generated random values for tokens, nonces, and secrets.",
                    cwe_id="CWE-338",
                    owasp_category="Cryptographic Failures",
                )
            )

        weak_hash = re.search(
            r"crypto\.subtle\.digest\s*\(\s*['\"]SHA-?1['\"]|"
            r"\b(?:md5|sha1)\s*\(",
            content,
            re.IGNORECASE,
        )
        if weak_hash:
            findings.append(
                self._finding(
                    title="Weak Hash Algorithm Used in JavaScript",
                    severity="medium",
                    url=source_url,
                    description="JavaScript appears to use SHA-1 or MD5, which are weak for security-sensitive integrity or password use.",
                    evidence=self._evidence(content, weak_hash.start()),
                    recommendation="Use SHA-256 or stronger for integrity, and never hash passwords only in client-side JavaScript.",
                    cwe_id="CWE-327",
                    owasp_category="Cryptographic Failures",
                )
            )

        return findings

    def _check_jwt_decode_without_verify(self, content, source_url):
        match = re.search(
            r"atob\s*\(.*?\.split\s*\(\s*['\"]\.['\"]\s*\)\s*\[\s*1\s*\]|"
            r"\bjwt_decode\s*\(",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return []

        return [
            self._finding(
                title="JWT Decoded Client-Side Without Verification Context",
                severity="low",
                url=source_url,
                description=(
                    "JavaScript decodes JWT claims in the browser. This is acceptable for display, "
                    "but dangerous if authorization decisions rely on decoded client-side claims."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation=(
                    "Treat browser-decoded JWT claims as untrusted UI hints. Enforce authorization "
                    "server-side after signature, issuer, audience, and expiry validation."
                ),
                cwe_id="CWE-345",
                owasp_category="Identification and Authentication Failures",
            )
        ]

    def _check_sensitive_console_logging(self, content, source_url):
        match = re.search(
            r"console\.(?:log|debug|info|warn|error)\s*\([^)]*"
            r"(token|password|secret|authorization|api[_-]?key|credential)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return []

        return [
            self._finding(
                title="Sensitive Data May Be Logged to Browser Console",
                severity="low",
                url=source_url,
                description=(
                    "A console logging call references credential-like data. Browser logs can "
                    "persist, leak through support screenshots, or expose secrets during debugging."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation="Remove sensitive values from client-side logs and gate debug logging behind safe build-time flags.",
                cwe_id="CWE-532",
                owasp_category="Sensitive Data Exposure",
            )
        ]

    def _check_sourcemap_reference(self, content, source_url):
        match = re.search(r"sourceMappingURL\s*=\s*(?P<map>[^\s*]+)", content)
        if not match:
            return []

        return [
            self._finding(
                title="JavaScript Source Map Reference Exposed",
                severity="low",
                url=source_url,
                description=(
                    "A production JavaScript file references a source map. Public source maps "
                    "can expose original source code, comments, route names, and implementation details."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation="Do not publish production source maps unless you intentionally make source code public.",
                cwe_id="CWE-540",
                owasp_category="Security Misconfiguration",
            )
        ]

    def _check_user_data_in_local_storage(self, content, source_url):
        match = re.search(
            r"localStorage\s*\.\s*setItem\s*\(\s*['\"]([^'\"]*(?:user|profile|email|account)[^'\"]*)['\"]",
            content,
            re.IGNORECASE,
        )
        if not match:
            return []

        return [
            self._finding(
                title="User Data Stored in localStorage",
                severity="low",
                url=source_url,
                description=(
                    "JavaScript stores user/profile-like data in localStorage. Any XSS can read "
                    "this data, and it may persist longer than intended on shared devices."
                ),
                evidence=self._evidence(content, match.start()),
                recommendation="Store only non-sensitive UI preferences in localStorage. Keep personal or session data server-side when possible.",
                cwe_id="CWE-922",
                owasp_category="Sensitive Data Exposure",
            )
        ]

    def _extract_api_endpoints(self, content):
        return {
            match.group("endpoint")
            for match in self.API_ENDPOINT_PATTERN.finditer(content)
        }

    def _looks_like_auth_key(self, key):
        key_lower = key.lower()
        return any(
            marker in key_lower
            for marker in ("token", "jwt", "auth", "session", "access", "refresh")
        )

    def _finding(
        self,
        title,
        severity,
        url,
        description,
        evidence,
        recommendation,
        cwe_id,
        owasp_category,
    ):
        return {
            "title": title,
            "severity": severity,
            "url": url,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "category": "client_code",
        }

    def _evidence(self, content, index):
        line_number = content.count("\n", 0, index) + 1
        line_start = content.rfind("\n", 0, index) + 1
        line_end = content.find("\n", index)
        if line_end == -1:
            line_end = len(content)
        line = content[line_start:line_end].strip()
        if len(line) > 180:
            line = line[:177] + "..."
        return f"Line {line_number}: {line}"

    def _dedupe_findings(self, findings):
        unique_findings = []
        seen = set()
        for finding in findings:
            key = (finding.get("title"), finding.get("url"))
            if key in seen:
                continue
            seen.add(key)
            unique_findings.append(finding)
        return unique_findings

    def _get_severity_breakdown(self, findings):
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
