# -*- coding: utf-8 -*-

"""
Report triage helpers.

These helpers keep the API, HTML export, PDF export, and browser report view
aligned around the same grouped, prioritized finding model.
"""

from collections import defaultdict


SEVERITY_ORDER = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
    'info': 4,
}

SEVERITY_LABELS = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'info': 'Info',
}


def normalize_category(category):
    """Return a human-readable category label."""
    value = (category or 'uncategorized').replace('_', ' ').replace('-', ' ')
    return ' '.join(part.capitalize() for part in value.split())


def sort_findings(findings):
    """Sort findings by severity, category, title, and URL for stable reports."""
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get((finding.severity or '').lower(), 99),
            finding.category or '',
            finding.title or '',
            finding.affected_url or '',
        ),
    )


def build_summary_data(scan, findings):
    """Build severity and category counts from active findings."""
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    categories = {}

    for finding in findings:
        severity = (finding.severity or 'info').lower()
        category = (finding.category or 'uncategorized').lower()

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if category not in categories:
            categories[category] = {
                'count': 0,
                'label': normalize_category(category),
                'highest_severity': severity,
                'severities': {item: 0 for item in SEVERITY_ORDER},
            }

        categories[category]['count'] += 1
        categories[category]['severities'][severity] = (
            categories[category]['severities'].get(severity, 0) + 1
        )

        current_highest = categories[category]['highest_severity']
        if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(current_highest, 99):
            categories[category]['highest_severity'] = severity

    return {
        'total_findings': len(findings),
        'by_severity': severity_counts,
        'by_category': categories,
        'score': scan.security_score,
        'risk_level': scan.risk_level,
    }


def build_grouped_findings(findings):
    """Group repeated findings so large reports are easy to triage."""
    groups = {}

    for finding in sort_findings(findings):
        key = (
            finding.title or '',
            finding.severity or '',
            finding.category or '',
            finding.description or '',
            finding.recommendation or '',
            finding.cwe_id or '',
            finding.owasp_category or '',
        )

        if key not in groups:
            groups[key] = {
                'title': finding.title,
                'severity': finding.severity,
                'severity_label': SEVERITY_LABELS.get(finding.severity, finding.severity),
                'category': finding.category,
                'category_label': normalize_category(finding.category),
                'description': finding.description,
                'recommendation': finding.recommendation,
                'cwe_id': finding.cwe_id,
                'owasp_category': finding.owasp_category,
                'cvss_score': finding.cvss_score,
                'reference_urls': finding.reference_urls or [],
                'count': 0,
                'finding_ids': [],
                'affected_urls': [],
                'affected_parameters': [],
                'evidence_samples': [],
                'first_seen_url': finding.affected_url,
            }

        group = groups[key]
        group['count'] += 1
        group['finding_ids'].append(finding.id)

        if finding.affected_url and finding.affected_url not in group['affected_urls']:
            group['affected_urls'].append(finding.affected_url)
        if finding.affected_parameter and finding.affected_parameter not in group['affected_parameters']:
            group['affected_parameters'].append(finding.affected_parameter)
        if finding.evidence and finding.evidence not in group['evidence_samples']:
            group['evidence_samples'].append(finding.evidence)

    grouped = list(groups.values())
    for group in grouped:
        group['affected_url_count'] = len(group['affected_urls'])
        group['evidence_sample_count'] = len(group['evidence_samples'])
        group['evidence_samples'] = group['evidence_samples'][:5]

    return sorted(
        grouped,
        key=lambda group: (
            SEVERITY_ORDER.get((group['severity'] or '').lower(), 99),
            group['category'] or '',
            -group['count'],
            group['title'] or '',
        ),
    )


def build_category_overview(grouped_findings):
    """Build a category overview from grouped findings."""
    categories = defaultdict(lambda: {
        'category': '',
        'label': '',
        'count': 0,
        'group_count': 0,
        'highest_severity': 'info',
        'severities': {item: 0 for item in SEVERITY_ORDER},
    })

    for group in grouped_findings:
        category = group['category'] or 'uncategorized'
        severity = group['severity'] or 'info'
        item = categories[category]
        item['category'] = category
        item['label'] = normalize_category(category)
        item['count'] += group['count']
        item['group_count'] += 1
        item['severities'][severity] = item['severities'].get(severity, 0) + group['count']

        if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(item['highest_severity'], 99):
            item['highest_severity'] = severity

    return sorted(
        categories.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item['highest_severity'], 99),
            -item['count'],
            item['label'],
        ),
    )


def triage_reason(group):
    """Explain why a grouped finding should be looked at in its current order."""
    severity = group.get('severity') or 'info'
    count = group.get('count') or 0
    category = normalize_category(group.get('category'))

    if severity in ('critical', 'high'):
        return f"{SEVERITY_LABELS.get(severity, severity)} severity issue in {category}."
    if count > 1:
        return f"Repeated across {count} findings; fix once and verify broadly."
    return f"{category} issue queued by severity."


def build_triage_data(scan, findings):
    """Build the full triage model used by UI and exports."""
    sorted_items = sort_findings(findings)
    grouped = build_grouped_findings(sorted_items)
    category_overview = build_category_overview(grouped)
    unique_urls = sorted({
        finding.affected_url
        for finding in sorted_items
        if finding.affected_url
    })
    priority_groups = [
        group for group in grouped
        if (group.get('severity') or '').lower() in ('critical', 'high', 'medium')
    ][:10]

    for index, group in enumerate(priority_groups, start=1):
        group['priority_rank'] = index
        group['triage_reason'] = triage_reason(group)

    quick_wins = [
        group for group in grouped
        if group.get('count', 0) > 1
        and (group.get('severity') or '').lower() in ('medium', 'low', 'info')
    ][:8]

    remediation_plan = []
    for group in priority_groups[:8]:
        remediation_plan.append({
            'title': group.get('title'),
            'severity': group.get('severity'),
            'category': group.get('category'),
            'affected_count': group.get('count'),
            'first_url': group.get('first_seen_url'),
            'action': group.get('recommendation') or 'Review the evidence and apply the recommended control.',
        })

    return {
        'total_instances': len(sorted_items),
        'total_groups': len(grouped),
        'duplicate_instances': max(0, len(sorted_items) - len(grouped)),
        'affected_url_count': len(unique_urls),
        'affected_urls': unique_urls,
        'grouped_findings': grouped,
        'priority_findings': priority_groups,
        'category_overview': category_overview,
        'quick_wins': quick_wins,
        'remediation_plan': remediation_plan,
    }


def build_report_data(scan, findings, include_user=True):
    """Build a full report payload for API and JSON export."""
    scan_data = scan.to_dict()
    if not include_user:
        scan_data.pop('user_id', None)
    scan_data['attack_surface_data'] = scan.attack_surface_data or None

    sorted_items = sort_findings(findings)
    return {
        'scan': scan_data,
        'findings': [finding.to_dict() for finding in sorted_items],
        'summary': build_summary_data(scan, sorted_items),
        'triage': build_triage_data(scan, sorted_items),
    }
