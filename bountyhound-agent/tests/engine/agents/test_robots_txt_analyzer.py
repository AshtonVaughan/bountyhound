"""
Comprehensive tests for Robots.txt Analyzer Agent.

Tests cover:
- Initialization and configuration
- robots.txt fetching and parsing
- Path categorization and sensitivity detection
- Sitemap discovery and testing
- User-agent specific rules
- Finding generation for all categories
- Report generation
- Edge cases and error handling
- All parsing methods
- Pattern matching

Target: 95%+ code coverage with 30+ tests
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.robots_txt_analyzer import (
        RobotsTxtAnalyzer,
        DisallowedPath,
        SitemapEntry,
        RobotsFinding,
        RobotsSeverity,
        PathCategory,
        REQUESTS_AVAILABLE
    )
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Robots.txt Analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, content="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = content
        response.content = content.encode() if isinstance(content, str) else content
        response.headers = headers or {}
        return response
    return _create_response


@pytest.fixture
def analyzer():
    """Create an analyzer instance for testing."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("Analyzer not available")

    return RobotsTxtAnalyzer(
        target="https://example.com",
        timeout=5,
        verify_ssl=False,
        test_paths=False  # Disable path testing for faster tests
    )


@pytest.fixture
def sample_robots_txt():
    """Sample robots.txt content."""
    return """
# Comment line
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /private/
Disallow: /.git/
Disallow: /config/database.yml
Disallow: /uploads/
Sitemap: https://example.com/sitemap.xml

User-agent: Googlebot
Disallow: /staging/
Crawl-delay: 10

User-agent: Bingbot
Disallow: /test/
Crawl-delay: 5
Sitemap: https://example.com/sitemap-news.xml
"""


@pytest.fixture
def sensitive_robots_txt():
    """Robots.txt with highly sensitive paths."""
    return """
User-agent: *
Disallow: /phpmyadmin/
Disallow: /administrator/
Disallow: /wp-admin/
Disallow: /backup.sql
Disallow: /database.dump
Disallow: /.env
Disallow: /credentials.json
Disallow: /private.key
Disallow: /ssl/certificate.pem
Disallow: /api/internal/
"""


@pytest.fixture
def minimal_robots_txt():
    """Minimal robots.txt."""
    return """
User-agent: *
Disallow:
"""


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestInitialization:
    """Test analyzer initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        analyzer = RobotsTxtAnalyzer(target="https://example.com")

        assert analyzer.target == "https://example.com"
        assert analyzer.base_url == "https://example.com"
        assert analyzer.domain == "example.com"
        assert analyzer.timeout == 10
        assert analyzer.verify_ssl is True
        assert analyzer.test_paths is True

    def test_init_with_custom_settings(self):
        """Test initialization with custom settings."""
        analyzer = RobotsTxtAnalyzer(
            target="https://test.com",
            timeout=15,
            verify_ssl=False,
            test_paths=False
        )

        assert analyzer.timeout == 15
        assert analyzer.verify_ssl is False
        assert analyzer.test_paths is False

    def test_init_without_scheme(self):
        """Test initialization with URL without scheme."""
        analyzer = RobotsTxtAnalyzer(target="example.com")

        assert analyzer.base_url == "https://example.com"
        assert analyzer.domain == "example.com"

    def test_init_requires_requests(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            RobotsTxtAnalyzer(target="https://example.com")

    def test_init_with_port(self):
        """Test initialization with URL containing port."""
        analyzer = RobotsTxtAnalyzer(target="https://example.com:8443")

        assert analyzer.base_url == "https://example.com:8443"
        assert analyzer.domain == "example.com:8443"

    def test_init_with_path(self):
        """Test initialization with URL containing path."""
        analyzer = RobotsTxtAnalyzer(target="https://example.com/test/path")

        assert analyzer.base_url == "https://example.com"
        assert analyzer.domain == "example.com"


# ============================================================================
# Fetching Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestFetching:
    """Test robots.txt fetching."""

    @patch('requests.get')
    def test_fetch_robots_txt_success(self, mock_get, analyzer, mock_response, sample_robots_txt):
        """Test successful robots.txt fetch."""
        mock_get.return_value = mock_response(200, sample_robots_txt)

        result = analyzer._fetch_robots_txt()

        assert result is True
        assert analyzer.robots_content == sample_robots_txt
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_fetch_robots_txt_not_found(self, mock_get, analyzer, mock_response):
        """Test robots.txt not found (404)."""
        mock_get.return_value = mock_response(404)

        result = analyzer._fetch_robots_txt()

        assert result is False
        assert analyzer.robots_content == ""
        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].title == "No robots.txt File Found"

    @patch('requests.get')
    def test_fetch_robots_txt_server_error(self, mock_get, analyzer, mock_response):
        """Test server error when fetching."""
        mock_get.return_value = mock_response(500)

        result = analyzer._fetch_robots_txt()

        assert result is False

    @patch('requests.get')
    def test_fetch_robots_txt_timeout(self, mock_get, analyzer):
        """Test timeout when fetching."""
        mock_get.side_effect = Exception("Timeout")

        result = analyzer._fetch_robots_txt()

        assert result is False

    @patch('requests.get')
    def test_fetch_robots_txt_with_ssl_verify(self, mock_get, mock_response, sample_robots_txt):
        """Test SSL verification setting."""
        analyzer = RobotsTxtAnalyzer(target="https://example.com", verify_ssl=True)
        mock_get.return_value = mock_response(200, sample_robots_txt)

        analyzer._fetch_robots_txt()

        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['verify'] is True


# ============================================================================
# Parsing Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestParsing:
    """Test robots.txt parsing."""

    def test_parse_basic_disallow(self, analyzer, sample_robots_txt):
        """Test parsing basic disallow rules."""
        analyzer.robots_content = sample_robots_txt
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) > 0
        paths = [p.path for p in analyzer.disallowed_paths]
        assert '/admin/' in paths
        assert '/backup/' in paths
        assert '/private/' in paths

    def test_parse_user_agents(self, analyzer, sample_robots_txt):
        """Test parsing user-agent directives."""
        analyzer.robots_content = sample_robots_txt
        analyzer._parse_robots_txt()

        assert '*' in analyzer.user_agents
        assert 'Googlebot' in analyzer.user_agents
        assert 'Bingbot' in analyzer.user_agents
        assert len(analyzer.user_agents) == 3

    def test_parse_sitemaps(self, analyzer, sample_robots_txt):
        """Test parsing sitemap directives."""
        analyzer.robots_content = sample_robots_txt
        analyzer._parse_robots_txt()

        assert len(analyzer.sitemaps) == 2
        sitemap_urls = [s.url for s in analyzer.sitemaps]
        assert 'https://example.com/sitemap.xml' in sitemap_urls
        assert 'https://example.com/sitemap-news.xml' in sitemap_urls

    def test_parse_crawl_delay(self, analyzer, sample_robots_txt):
        """Test parsing crawl-delay directives."""
        analyzer.robots_content = sample_robots_txt
        analyzer._parse_robots_txt()

        assert 'Googlebot' in analyzer.crawl_delays
        assert analyzer.crawl_delays['Googlebot'] == 10
        assert 'Bingbot' in analyzer.crawl_delays
        assert analyzer.crawl_delays['Bingbot'] == 5

    def test_parse_empty_content(self, analyzer):
        """Test parsing empty content."""
        analyzer.robots_content = ""
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) == 0
        assert len(analyzer.sitemaps) == 0

    def test_parse_comments_ignored(self, analyzer):
        """Test that comments are ignored."""
        analyzer.robots_content = """
# This is a comment
User-agent: *
# Another comment
Disallow: /test/
"""
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) == 1

    def test_parse_empty_disallow(self, analyzer, minimal_robots_txt):
        """Test parsing empty disallow directive."""
        analyzer.robots_content = minimal_robots_txt
        analyzer._parse_robots_txt()

        # Empty disallow should be ignored
        assert len(analyzer.disallowed_paths) == 0

    def test_parse_malformed_lines(self, analyzer):
        """Test parsing malformed lines."""
        analyzer.robots_content = """
User-agent: *
Disallow /test
InvalidLine
: NoDirective
Disallow: /valid/
"""
        analyzer._parse_robots_txt()

        # Should parse valid lines only
        assert len(analyzer.disallowed_paths) == 1
        assert analyzer.disallowed_paths[0].path == '/valid/'


# ============================================================================
# Categorization Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestCategorization:
    """Test path categorization."""

    def test_categorize_admin_paths(self, analyzer):
        """Test categorization of admin paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/admin/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/administrator/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/wp-admin/', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.ADMIN
            assert path.sensitivity == "high"

    def test_categorize_backup_paths(self, analyzer):
        """Test categorization of backup paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/backup/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/file.bak', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/database.sql', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.BACKUP
            assert path.sensitivity == "high"

    def test_categorize_config_paths(self, analyzer):
        """Test categorization of config paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/config/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/.env', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/settings.yml', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.CONFIG
            assert path.sensitivity == "medium"

    def test_categorize_credentials_paths(self, analyzer):
        """Test categorization of credential paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/credentials.json', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/private.key', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/ssl/cert.pem', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.CREDENTIALS
            assert path.sensitivity == "high"

    def test_categorize_database_paths(self, analyzer):
        """Test categorization of database paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/database/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/mysql/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/data.sqlite', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.DATABASE
            assert path.sensitivity == "high"

    def test_categorize_api_paths(self, analyzer):
        """Test categorization of API paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/api/internal/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/api/admin/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/graphql', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.API

    def test_categorize_development_paths(self, analyzer):
        """Test categorization of development paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/.git/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/debug/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/node_modules/', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.DEVELOPMENT

    def test_categorize_staging_paths(self, analyzer):
        """Test categorization of staging paths."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/staging/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/dev/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/test/', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.STAGING
            assert path.sensitivity == "medium"

    def test_categorize_unknown_paths(self, analyzer):
        """Test that unknown paths remain uncategorized."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/random/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/unknown/', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.UNKNOWN


# ============================================================================
# Sitemap Testing Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSitemapTesting:
    """Test sitemap accessibility testing."""

    @patch('requests.get')
    def test_test_sitemap_accessible(self, mock_get, analyzer, mock_response):
        """Test accessible sitemap."""
        sitemap_content = b'<?xml version="1.0"?><urlset></urlset>'
        mock_get.return_value = mock_response(200, sitemap_content)

        sitemap = SitemapEntry(url="https://example.com/sitemap.xml")
        result = analyzer._test_sitemap(sitemap)

        assert result is not None
        assert result[0] is True  # accessible
        assert result[1] == 200   # status_code
        assert result[2] > 0      # size_bytes

    @patch('requests.get')
    def test_test_sitemap_not_found(self, mock_get, analyzer, mock_response):
        """Test sitemap not found."""
        mock_get.return_value = mock_response(404)

        sitemap = SitemapEntry(url="https://example.com/sitemap.xml")
        result = analyzer._test_sitemap(sitemap)

        assert result is not None
        assert result[0] is False
        assert result[1] == 404

    @patch('requests.get')
    def test_test_sitemap_timeout(self, mock_get, analyzer):
        """Test sitemap timeout."""
        mock_get.side_effect = Exception("Timeout")

        sitemap = SitemapEntry(url="https://example.com/sitemap.xml")
        result = analyzer._test_sitemap(sitemap)

        assert result is None

    @patch('requests.get')
    def test_test_sitemaps_multiple(self, mock_get, analyzer, mock_response):
        """Test testing multiple sitemaps."""
        mock_get.return_value = mock_response(200, b'<urlset></urlset>')

        analyzer.sitemaps = [
            SitemapEntry(url="https://example.com/sitemap1.xml"),
            SitemapEntry(url="https://example.com/sitemap2.xml"),
        ]

        analyzer._test_sitemaps()

        assert all(s.accessible for s in analyzer.sitemaps)
        assert all(s.status_code == 200 for s in analyzer.sitemaps)


# ============================================================================
# Finding Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestFindingGeneration:
    """Test finding generation."""

    def test_generate_admin_finding(self, analyzer):
        """Test generation of admin path finding."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/admin/', category=PathCategory.ADMIN, sensitivity="high"),
            DisallowedPath(path='/wp-admin/', category=PathCategory.ADMIN, sensitivity="high"),
        ]

        analyzer._generate_findings()

        admin_findings = [f for f in analyzer.findings if 'Admin' in f.title]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity == RobotsSeverity.HIGH
        assert len(admin_findings[0].paths) == 2

    def test_generate_backup_finding(self, analyzer):
        """Test generation of backup path finding."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/backup/', category=PathCategory.BACKUP, sensitivity="high"),
            DisallowedPath(path='/file.bak', category=PathCategory.BACKUP, sensitivity="high"),
        ]

        analyzer._generate_findings()

        backup_findings = [f for f in analyzer.findings if 'Backup' in f.title]
        assert len(backup_findings) == 1
        assert backup_findings[0].severity == RobotsSeverity.HIGH

    def test_generate_credentials_finding(self, analyzer):
        """Test generation of credentials finding."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/credentials.json', category=PathCategory.CREDENTIALS, sensitivity="high"),
        ]

        analyzer._generate_findings()

        cred_findings = [f for f in analyzer.findings if 'Credentials' in f.title]
        assert len(cred_findings) == 1
        assert cred_findings[0].severity == RobotsSeverity.CRITICAL

    def test_generate_sitemap_finding(self, analyzer):
        """Test generation of sitemap finding."""
        analyzer.sitemaps = [
            SitemapEntry(url="https://example.com/sitemap.xml", accessible=True),
        ]

        analyzer._generate_findings()

        sitemap_findings = [f for f in analyzer.findings if 'Sitemap' in f.title]
        assert len(sitemap_findings) == 1
        assert sitemap_findings[0].severity in [RobotsSeverity.LOW, RobotsSeverity.INFO]

    def test_generate_user_agent_finding(self, analyzer):
        """Test generation of user-agent finding."""
        analyzer.user_agents = {'Googlebot', 'Bingbot', 'CustomBot'}

        analyzer._generate_findings()

        ua_findings = [f for f in analyzer.findings if 'User-Agent' in f.title]
        assert len(ua_findings) == 1
        assert ua_findings[0].severity == RobotsSeverity.INFO

    def test_generate_info_disclosure_finding(self, analyzer):
        """Test generation of info disclosure finding."""
        # Create many high-value paths
        analyzer.disallowed_paths = [
            DisallowedPath(path=f'/admin{i}/', category=PathCategory.ADMIN, sensitivity="high")
            for i in range(15)
        ]

        analyzer._generate_findings()

        info_findings = [f for f in analyzer.findings if 'Extensive Information' in f.title]
        assert len(info_findings) == 1

    def test_no_findings_for_empty_data(self, analyzer):
        """Test no findings generated for empty data."""
        analyzer.disallowed_paths = []
        analyzer.sitemaps = []
        analyzer.user_agents = {'*'}

        analyzer._generate_findings()

        assert len(analyzer.findings) == 0

    def test_generate_multiple_category_findings(self, analyzer):
        """Test generation of findings for multiple categories."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/admin/', category=PathCategory.ADMIN, sensitivity="high"),
            DisallowedPath(path='/backup/', category=PathCategory.BACKUP, sensitivity="high"),
            DisallowedPath(path='/config/', category=PathCategory.CONFIG, sensitivity="medium"),
        ]

        analyzer._generate_findings()

        # Should have 3 findings (one per category)
        assert len(analyzer.findings) >= 3


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestIntegration:
    """Test full analysis workflow."""

    @patch('requests.get')
    def test_full_analysis(self, mock_get, mock_response, sensitive_robots_txt):
        """Test complete analysis workflow."""
        mock_get.return_value = mock_response(200, sensitive_robots_txt)

        analyzer = RobotsTxtAnalyzer(target="https://example.com", test_paths=False)
        findings = analyzer.analyze()

        assert len(findings) > 0
        assert analyzer.robots_content == sensitive_robots_txt
        assert len(analyzer.disallowed_paths) > 0

        # Should have high severity findings
        high_severity = [f for f in findings if f.severity in [RobotsSeverity.HIGH, RobotsSeverity.CRITICAL]]
        assert len(high_severity) > 0

    @patch('requests.get')
    def test_analyze_no_robots_txt(self, mock_get, mock_response):
        """Test analysis when no robots.txt exists."""
        mock_get.return_value = mock_response(404)

        analyzer = RobotsTxtAnalyzer(target="https://example.com")
        findings = analyzer.analyze()

        assert len(findings) == 1
        assert findings[0].title == "No robots.txt File Found"
        assert findings[0].severity == RobotsSeverity.INFO

    @patch('requests.get')
    def test_generate_report(self, mock_get, mock_response, sample_robots_txt):
        """Test report generation."""
        mock_get.return_value = mock_response(200, sample_robots_txt)

        analyzer = RobotsTxtAnalyzer(target="https://example.com", test_paths=False)
        analyzer.analyze()

        report = analyzer.generate_report()

        assert 'target' in report
        assert 'domain' in report
        assert 'scan_date' in report
        assert 'robots_txt_exists' in report
        assert 'total_disallowed_paths' in report
        assert 'total_sitemaps' in report
        assert 'findings' in report
        assert 'raw_robots_txt' in report

        assert report['robots_txt_exists'] is True
        assert report['target'] == "https://example.com"

    @patch('requests.get')
    def test_analyze_with_path_testing(self, mock_get, mock_response, sample_robots_txt):
        """Test analysis with sitemap testing enabled."""
        def response_handler(url, **kwargs):
            if 'robots.txt' in url:
                return mock_response(200, sample_robots_txt)
            else:
                return mock_response(200, b'<urlset></urlset>')

        mock_get.side_effect = response_handler

        analyzer = RobotsTxtAnalyzer(target="https://example.com", test_paths=True)
        findings = analyzer.analyze()

        # Sitemaps should be tested
        assert any(s.accessible for s in analyzer.sitemaps)


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_unicode_content(self, analyzer):
        """Test parsing robots.txt with unicode characters."""
        analyzer.robots_content = """
User-agent: *
Disallow: /über/
Disallow: /café/
"""
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) == 2

    def test_parse_very_long_path(self, analyzer):
        """Test parsing very long paths."""
        long_path = '/very/' + 'long/' * 100 + 'path/'
        analyzer.robots_content = f"User-agent: *\nDisallow: {long_path}"
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) == 1
        assert analyzer.disallowed_paths[0].path == long_path

    def test_parse_special_characters(self, analyzer):
        """Test parsing paths with special characters."""
        analyzer.robots_content = """
User-agent: *
Disallow: /test?query=1
Disallow: /path#anchor
Disallow: /file%20name/
"""
        analyzer._parse_robots_txt()

        assert len(analyzer.disallowed_paths) == 3

    def test_categorize_case_insensitive(self, analyzer):
        """Test case-insensitive categorization."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/ADMIN/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/Admin/', category=PathCategory.UNKNOWN),
            DisallowedPath(path='/aDmIn/', category=PathCategory.UNKNOWN),
        ]
        analyzer._categorize_paths()

        for path in analyzer.disallowed_paths:
            assert path.category == PathCategory.ADMIN

    def test_finding_poc_truncation(self, analyzer):
        """Test POC truncation for many paths."""
        # Create 20 paths
        analyzer.disallowed_paths = [
            DisallowedPath(path=f'/admin{i}/', category=PathCategory.ADMIN, sensitivity="high")
            for i in range(20)
        ]

        analyzer._generate_findings()

        admin_finding = [f for f in analyzer.findings if 'Admin' in f.title][0]
        # POC should limit examples
        assert len(admin_finding.poc) < 5000

    def test_empty_user_agents_no_finding(self, analyzer):
        """Test no user-agent finding for single wildcard."""
        analyzer.user_agents = {'*'}
        analyzer._generate_findings()

        ua_findings = [f for f in analyzer.findings if 'User-Agent' in f.title]
        assert len(ua_findings) == 0

    def test_dataclass_to_dict_conversions(self):
        """Test dataclass to dict conversions."""
        path = DisallowedPath(path='/test/', category=PathCategory.ADMIN)
        path_dict = path.to_dict()
        assert path_dict['category'] == 'admin'

        sitemap = SitemapEntry(url='https://example.com/sitemap.xml', accessible=True)
        sitemap_dict = sitemap.to_dict()
        assert sitemap_dict['accessible'] is True

        finding = RobotsFinding(
            title="Test",
            severity=RobotsSeverity.HIGH,
            description="Test finding"
        )
        finding_dict = finding.to_dict()
        assert finding_dict['severity'] == 'HIGH'


# ============================================================================
# Main Function Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestMainFunction:
    """Test main execution function."""

    @patch('sys.argv', ['script.py', 'https://example.com'])
    @patch('requests.get')
    @patch('builtins.open', create=True)
    @patch('json.dump')
    def test_main_execution(self, mock_json_dump, mock_open, mock_get, mock_response, sample_robots_txt):
        """Test main function execution."""
        from engine.agents.robots_txt_analyzer import main

        mock_get.return_value = mock_response(200, sample_robots_txt)

        # Should not raise exception
        try:
            main()
        except SystemExit:
            pass  # Expected from sys.exit(1) on error

    @patch('sys.argv', ['script.py'])
    def test_main_no_arguments(self):
        """Test main function with no arguments."""
        from engine.agents.robots_txt_analyzer import main

        with pytest.raises(SystemExit):
            main()


# ============================================================================
# Pattern Matching Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPatternMatching:
    """Test pattern matching for path categorization."""

    def test_match_all_admin_patterns(self, analyzer):
        """Test matching all admin patterns."""
        admin_paths = [
            '/admin/', '/administrator/', '/wp-admin/', '/cpanel/',
            '/phpmyadmin/', '/adminer/', '/admin_area/', '/admincp/',
            '/manage/', '/manager/', '/control/', '/backend/', '/dashboard/'
        ]

        for path in admin_paths:
            analyzer.disallowed_paths = [DisallowedPath(path=path, category=PathCategory.UNKNOWN)]
            analyzer._categorize_paths()
            assert analyzer.disallowed_paths[0].category == PathCategory.ADMIN, f"Failed for {path}"

    def test_match_all_backup_patterns(self, analyzer):
        """Test matching all backup patterns."""
        backup_paths = [
            '/backup/', '/backups/', '/file.bak', '/file.old',
            '/file.backup', '/old/', '/file.sql', '/dump.sql',
            '/archive.tar.gz', '/data.zip'
        ]

        for path in backup_paths:
            analyzer.disallowed_paths = [DisallowedPath(path=path, category=PathCategory.UNKNOWN)]
            analyzer._categorize_paths()
            assert analyzer.disallowed_paths[0].category == PathCategory.BACKUP, f"Failed for {path}"

    def test_match_development_patterns(self, analyzer):
        """Test matching development patterns."""
        dev_paths = [
            '/.git/', '/.svn/', '/debug/', '/debugger/',
            '/node_modules/', '/vendor/', '/error.log'
        ]

        for path in dev_paths:
            analyzer.disallowed_paths = [DisallowedPath(path=path, category=PathCategory.UNKNOWN)]
            analyzer._categorize_paths()
            assert analyzer.disallowed_paths[0].category == PathCategory.DEVELOPMENT, f"Failed for {path}"


# ============================================================================
# Coverage Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestCoverage:
    """Additional tests to ensure 95%+ coverage."""

    def test_all_severity_levels_used(self, analyzer):
        """Test that all severity levels are used."""
        # CRITICAL
        analyzer.disallowed_paths = [
            DisallowedPath(path='/credentials.json', category=PathCategory.CREDENTIALS, sensitivity="high")
        ]
        analyzer._generate_findings()
        assert any(f.severity == RobotsSeverity.CRITICAL for f in analyzer.findings)

        analyzer.findings.clear()

        # HIGH
        analyzer.disallowed_paths = [
            DisallowedPath(path='/admin/', category=PathCategory.ADMIN, sensitivity="high")
        ]
        analyzer._generate_findings()
        assert any(f.severity == RobotsSeverity.HIGH for f in analyzer.findings)

    def test_all_path_categories_covered(self, analyzer):
        """Test all path categories can be detected."""
        test_cases = {
            PathCategory.ADMIN: '/admin/',
            PathCategory.BACKUP: '/backup/',
            PathCategory.PRIVATE: '/private/',
            PathCategory.STAGING: '/staging/',
            PathCategory.CONFIG: '/config/',
            PathCategory.DATABASE: '/database/',
            PathCategory.API: '/api/internal/',
            PathCategory.INTERNAL: '/internal/',
            PathCategory.DEVELOPMENT: '/.git/',
            PathCategory.CREDENTIALS: '/credentials/',
            PathCategory.UPLOADS: '/uploads/',
            PathCategory.LOGS: '/logs/',
        }

        for category, path in test_cases.items():
            analyzer.disallowed_paths = [DisallowedPath(path=path, category=PathCategory.UNKNOWN)]
            analyzer._categorize_paths()
            assert analyzer.disallowed_paths[0].category == category

    def test_high_value_keywords_detection(self, analyzer):
        """Test high-value keyword detection."""
        paths_with_keywords = [
            '/admin/panel/', '/backup.sql', '/config.yml',
            '/password.txt', '/secret.key', '/.env'
        ]

        for path in paths_with_keywords:
            path_lower = path.lower()
            has_keyword = any(keyword in path_lower for keyword in analyzer.HIGH_VALUE_KEYWORDS)
            assert has_keyword, f"High-value keyword not found in {path}"

    def test_report_includes_all_fields(self, analyzer, sample_robots_txt):
        """Test that report includes all required fields."""
        analyzer.robots_content = sample_robots_txt
        analyzer._parse_robots_txt()
        analyzer._categorize_paths()
        analyzer._generate_findings()

        report = analyzer.generate_report()

        required_fields = [
            'target', 'domain', 'scan_date', 'robots_txt_exists',
            'total_disallowed_paths', 'total_sitemaps', 'user_agents',
            'crawl_delays', 'findings', 'disallowed_paths', 'sitemaps',
            'raw_robots_txt'
        ]

        for field in required_fields:
            assert field in report, f"Missing field: {field}"

    def test_finding_includes_all_fields(self, analyzer):
        """Test that findings include all required fields."""
        analyzer.disallowed_paths = [
            DisallowedPath(path='/admin/', category=PathCategory.ADMIN, sensitivity="high")
        ]
        analyzer._generate_findings()

        finding = analyzer.findings[0]
        finding_dict = finding.to_dict()

        required_fields = [
            'title', 'severity', 'description', 'paths', 'poc',
            'impact', 'recommendation', 'cwe_id', 'discovered_date',
            'category', 'raw_data'
        ]

        for field in required_fields:
            assert field in finding_dict, f"Missing field: {field}"
