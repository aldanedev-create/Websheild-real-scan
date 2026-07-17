# -*- coding: utf-8 -*-

"""
WebShield Scanner - Scanner Package
Contains all scanner modules for website security analysis.
"""

from app.scanner.url_validator import URLValidator
from app.scanner.crawler import Crawler
from app.scanner.attack_surface import AttackSurfaceMapper
from app.scanner.headers import HeaderChecker
from app.scanner.ssl_check import SSLChecker
from app.scanner.cookies import CookieChecker
from app.scanner.forms import FormAnalyzer
from app.scanner.sensitive_files import SensitiveFileDetector
from app.scanner.component_check import ComponentChecker
from app.scanner.javascript_analyzer import JavaScriptAnalyzer
from app.scanner.safe_vulnerability_checks import SafeVulnerabilityChecker
from app.scanner.score_engine import ScoreEngine
from app.scanner.report_builder import ReportBuilder

__all__ = [
    'URLValidator',
    'Crawler',
    'AttackSurfaceMapper',
    'HeaderChecker',
    'SSLChecker',
    'CookieChecker',
    'FormAnalyzer',
    'SensitiveFileDetector',
    'ComponentChecker',
    'JavaScriptAnalyzer',
    'SafeVulnerabilityChecker',
    'ScoreEngine',
    'ReportBuilder'
]
