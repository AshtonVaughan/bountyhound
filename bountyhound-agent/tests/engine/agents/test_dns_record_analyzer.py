"""
Comprehensive tests for DNS Record Analyzer Agent.

Tests cover:
- Initialization and configuration
- SPF record analysis (permissive, missing, lookup limits)
- DMARC policy validation (none, quarantine, reject, partial enforcement)
- DKIM selector enumeration (missing, weak keys)
- CAA record validation (missing, wildcard)
- MX record enumeration (unreachable hosts, providers)
- Finding generation and classification
- Report generation
- Edge cases and error handling
- Database integration

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.dns_record_analyzer import (
        DNSRecordAnalyzer,
        DNSRecordFinding,
        SPFAnalysis,
        DMARCAnalysis,
        DKIMAnalysis,
        CAAAnalysis,
        MXAnalysis,
        DNSRecordSeverity,
        DNSRecordVulnType,
        DNS_AVAILABLE
    )
    DNS_ANALYZER_AVAILABLE = True
except ImportError:
    DNS_ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="DNS record analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_resolver():
    """Create a mock DNS resolver."""
    resolver = Mock()
    resolver.timeout = 10
    resolver.lifetime = 10
    return resolver


@pytest.fixture
def analyzer(mock_resolver):
    """Create a DNSRecordAnalyzer instance for testing."""
    if not DNS_ANALYZER_AVAILABLE:
        pytest.skip("DNS record analyzer not available")

    with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
        return DNSRecordAnalyzer(domain="example.com", timeout=10)


@pytest.fixture
def mock_txt_response():
    """Create mock TXT record response."""
    def _create(records):
        answers = []
        for record in records:
            rdata = Mock()
            rdata.__str__ = Mock(return_value=f'"{record}"')
            answers.append(rdata)
        return answers
    return _create


@pytest.fixture
def mock_mx_response():
    """Create mock MX record response."""
    def _create(mx_records):
        answers = []
        for priority, hostname in mx_records:
            rdata = Mock()
            rdata.preference = priority
            rdata.exchange = Mock()
            rdata.exchange.__str__ = Mock(return_value=hostname)
            answers.append(rdata)
        return answers
    return _create


@pytest.fixture
def mock_caa_response():
    """Create mock CAA record response."""
    def _create(caa_records):
        answers = []
        for record in caa_records:
            rdata = Mock()
            rdata.__str__ = Mock(return_value=record)
            answers.append(rdata)
        return answers
    return _create


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestInitialization:
    """Test DNSRecordAnalyzer initialization."""

    def test_init_with_basic_domain(self, mock_resolver):
        """Test initialization with basic domain."""
        with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
            analyzer = DNSRecordAnalyzer(domain="example.com")

            assert analyzer.domain == "example.com"
            assert analyzer.timeout == 10
            assert analyzer.spf_analysis is None
            assert analyzer.dmarc_analysis is None
            assert len(analyzer.findings) == 0

    def test_init_with_uppercase_domain(self, mock_resolver):
        """Test that domain is lowercased."""
        with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
            analyzer = DNSRecordAnalyzer(domain="EXAMPLE.COM")

            assert analyzer.domain == "example.com"

    def test_init_with_whitespace(self, mock_resolver):
        """Test that domain whitespace is stripped."""
        with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
            analyzer = DNSRecordAnalyzer(domain="  example.com  ")

            assert analyzer.domain == "example.com"

    def test_init_with_custom_timeout(self, mock_resolver):
        """Test initialization with custom timeout."""
        with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
            analyzer = DNSRecordAnalyzer(domain="example.com", timeout=30)

            assert analyzer.timeout == 30
            assert mock_resolver.timeout == 30
            assert mock_resolver.lifetime == 30

    def test_init_requires_dns_library(self):
        """Test that initialization fails without dnspython."""
        if DNS_AVAILABLE:
            pytest.skip("dnspython is available")

        with pytest.raises(ImportError, match="dnspython library is required"):
            DNSRecordAnalyzer(domain="example.com")


# ============================================================================
# SPF Analysis Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestSPFAnalysis:
    """Test SPF record analysis."""

    def test_spf_missing(self, analyzer, mock_txt_response):
        """Test detection of missing SPF record."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response([]))

        result = analyzer.analyze_spf()

        assert not result.exists
        assert result.record is None
        assert "No SPF record found" in result.issues
        assert result.severity == DNSRecordSeverity.HIGH

    def test_spf_permissive_plus_all(self, analyzer, mock_txt_response):
        """Test detection of permissive SPF (+all)."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 +all"]
        ))

        result = analyzer.analyze_spf()

        assert result.exists
        assert result.all_qualifier == '+'
        assert "allows any sender" in result.issues[0]
        assert result.severity == DNSRecordSeverity.CRITICAL

    def test_spf_softfail(self, analyzer, mock_txt_response):
        """Test detection of soft fail SPF (~all)."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 include:_spf.google.com ~all"]
        ))

        result = analyzer.analyze_spf()

        assert result.exists
        assert result.all_qualifier == '~'
        assert "soft fail" in result.issues[0]
        assert result.severity == DNSRecordSeverity.HIGH

    def test_spf_neutral(self, analyzer, mock_txt_response):
        """Test detection of neutral SPF (?all)."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 ?all"]
        ))

        result = analyzer.analyze_spf()

        assert result.exists
        assert result.all_qualifier == '?'
        assert "neutral" in result.issues[0]
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_spf_secure(self, analyzer, mock_txt_response):
        """Test secure SPF record (-all)."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 include:_spf.google.com -all"]
        ))

        result = analyzer.analyze_spf()

        assert result.exists
        assert result.all_qualifier == '-'
        assert "SPF record looks secure" in result.issues[0]
        assert result.severity == DNSRecordSeverity.INFO

    def test_spf_too_many_lookups(self, analyzer, mock_txt_response):
        """Test detection of SPF records exceeding lookup limit."""
        includes = " ".join([f"include:spf{i}.example.com" for i in range(12)])
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            [f"v=spf1 {includes} -all"]
        ))

        result = analyzer.analyze_spf()

        assert result.lookup_count > 10
        assert any("exceeds RFC limit" in issue for issue in result.issues)
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_spf_approaching_lookup_limit(self, analyzer, mock_txt_response):
        """Test warning for SPF records approaching lookup limit."""
        includes = " ".join([f"include:spf{i}.example.com" for i in range(7)])
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            [f"v=spf1 {includes} -all"]
        ))

        result = analyzer.analyze_spf()

        assert result.lookup_count == 7
        assert any("approaching limit" in issue for issue in result.issues)

    def test_spf_broad_ip_range(self, analyzer, mock_txt_response):
        """Test detection of broad IP ranges in SPF."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 ip4:10.0.0.0/8 -all"]
        ))

        result = analyzer.analyze_spf()

        assert any("Broad IP4 range" in issue for issue in result.issues)

    def test_spf_parse_includes(self, analyzer, mock_txt_response):
        """Test parsing of include mechanisms."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 include:_spf.google.com include:sendgrid.net -all"]
        ))

        result = analyzer.analyze_spf()

        assert "_spf.google.com" in result.includes
        assert "sendgrid.net" in result.includes
        assert result.lookup_count == 2


# ============================================================================
# DMARC Analysis Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestDMARCAnalysis:
    """Test DMARC policy analysis."""

    def test_dmarc_missing(self, analyzer, mock_txt_response):
        """Test detection of missing DMARC record."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

        result = analyzer.analyze_dmarc()

        assert not result.exists
        assert result.record is None
        assert "No DMARC record found" in result.issues
        assert result.severity == DNSRecordSeverity.HIGH

    def test_dmarc_policy_none(self, analyzer, mock_txt_response):
        """Test detection of DMARC policy=none."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.exists
        assert result.policy == "none"
        assert "monitoring only" in result.issues[0]
        assert result.severity == DNSRecordSeverity.HIGH

    def test_dmarc_policy_quarantine(self, analyzer, mock_txt_response):
        """Test DMARC policy=quarantine."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.exists
        assert result.policy == "quarantine"
        assert "moderate protection" in result.issues[0]
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_dmarc_policy_reject(self, analyzer, mock_txt_response):
        """Test DMARC policy=reject."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.exists
        assert result.policy == "reject"
        assert "strong protection" in result.issues[0]
        assert result.severity == DNSRecordSeverity.INFO

    def test_dmarc_partial_enforcement(self, analyzer, mock_txt_response):
        """Test detection of partial DMARC enforcement (pct<100)."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.percentage == 50
        assert "50% of messages" in result.issues[1]
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_dmarc_subdomain_policy(self, analyzer, mock_txt_response):
        """Test parsing of subdomain policy."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=reject; sp=quarantine"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.subdomain_policy == "quarantine"

    def test_dmarc_alignment_modes(self, analyzer, mock_txt_response):
        """Test parsing of alignment modes."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=reject; aspf=s; adkim=s"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.alignment_spf == "s"
        assert result.alignment_dkim == "s"

    def test_dmarc_reporting_addresses(self, analyzer, mock_txt_response):
        """Test parsing of reporting addresses."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=DMARC1; p=reject; rua=mailto:agg@example.com; ruf=mailto:forensic@example.com"]
        ))

        result = analyzer.analyze_dmarc()

        assert result.aggregate_reports == "mailto:agg@example.com"
        assert result.forensic_reports == "mailto:forensic@example.com"


# ============================================================================
# DKIM Analysis Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestDKIMAnalysis:
    """Test DKIM selector analysis."""

    def test_dkim_no_selectors_found(self, analyzer):
        """Test when no DKIM selectors are found."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())

        result = analyzer.analyze_dkim()

        assert len(result.selectors_found) == 0
        assert result.selectors_tested > 0
        assert "No DKIM selectors found" in result.issues[0]
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_dkim_selector_found(self, analyzer, mock_txt_response):
        """Test successful DKIM selector discovery."""
        def mock_resolve(domain, record_type):
            if 'google._domainkey' in domain:
                return mock_txt_response(['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ=='])
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_dkim()

        assert 'google' in result.selectors_found
        assert 'google' in result.key_details
        assert result.severity == DNSRecordSeverity.INFO

    def test_dkim_weak_key(self, analyzer, mock_txt_response):
        """Test detection of weak DKIM key."""
        # Short base64 key = weak key
        weak_key = "MIGfMA0GCSqGSIb3DQEBAQUAA=="

        def mock_resolve(domain, record_type):
            if 'default._domainkey' in domain:
                return mock_txt_response([f'v=DKIM1; k=rsa; p={weak_key}'])
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_dkim()

        assert 'default' in result.selectors_found
        assert any("weak key" in issue for issue in result.issues)

    def test_dkim_parse_key_details(self, analyzer):
        """Test parsing of DKIM key details."""
        record = "v=DKIM1; k=rsa; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ=="
        key_info = analyzer._parse_dkim_record(record)

        assert 'public_key_b64' in key_info
        assert 'key_length' in key_info


# ============================================================================
# CAA Analysis Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestCAAAnalysis:
    """Test CAA record analysis."""

    def test_caa_missing(self, analyzer):
        """Test detection of missing CAA records."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NoAnswer())

        result = analyzer.analyze_caa()

        assert not result.exists
        assert "No CAA records found" in result.issues[0]
        assert result.severity == DNSRecordSeverity.LOW

    def test_caa_records_present(self, analyzer, mock_caa_response):
        """Test parsing of CAA records."""
        analyzer.resolver.resolve = Mock(return_value=mock_caa_response([
            '0 issue "letsencrypt.org"',
            '0 issuewild ";"'
        ]))

        result = analyzer.analyze_caa()

        assert result.exists
        assert 'letsencrypt.org' in result.issuers
        assert len(result.records) == 2

    def test_caa_wildcard_allowed(self, analyzer, mock_caa_response):
        """Test detection of wildcard CAA policy."""
        analyzer.resolver.resolve = Mock(return_value=mock_caa_response([
            '0 issue "letsencrypt.org"',
            '0 issuewild "letsencrypt.org"'
        ]))

        result = analyzer.analyze_caa()

        assert result.wildcard_allowed
        assert 'letsencrypt.org' in result.issue_wild

    def test_caa_iodef(self, analyzer, mock_caa_response):
        """Test parsing of CAA iodef tag."""
        analyzer.resolver.resolve = Mock(return_value=mock_caa_response([
            '0 issue "letsencrypt.org"',
            '0 iodef "mailto:security@example.com"'
        ]))

        result = analyzer.analyze_caa()

        assert result.iodef == "mailto:security@example.com"


# ============================================================================
# MX Analysis Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestMXAnalysis:
    """Test MX record analysis."""

    def test_mx_missing(self, analyzer):
        """Test detection of missing MX records."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NoAnswer())

        result = analyzer.analyze_mx()

        assert not result.exists
        assert "No MX records found" in result.issues[0]
        assert result.severity == DNSRecordSeverity.MEDIUM

    def test_mx_records_present(self, analyzer, mock_mx_response):
        """Test parsing of MX records."""
        call_count = [0]

        def mock_resolve(domain, record_type):
            if record_type == 'MX':
                return mock_mx_response([
                    (10, "mail.example.com"),
                    (20, "backup.example.com")
                ])
            elif record_type == 'A':
                # Simulate successful A record lookup for MX hosts
                return Mock()
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_mx()

        assert result.exists
        assert len(result.records) == 2
        assert result.records[0] == (10, "mail.example.com")
        assert result.records[1] == (20, "backup.example.com")

    def test_mx_unreachable_host(self, analyzer, mock_mx_response):
        """Test detection of unreachable MX hosts."""
        def mock_resolve(domain, record_type):
            if record_type == 'MX':
                return mock_mx_response([(10, "nonexistent.example.com")])
            # Simulate NXDOMAIN for A record lookup
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_mx()

        assert "nonexistent.example.com" in result.unreachable_hosts
        assert any("does not resolve" in issue for issue in result.issues)
        assert result.severity == DNSRecordSeverity.CRITICAL

    def test_mx_provider_detection(self, analyzer, mock_mx_response):
        """Test email provider detection."""
        def mock_resolve(domain, record_type):
            if record_type == 'MX':
                return mock_mx_response([
                    (10, "aspmx.l.google.com"),
                    (20, "alt1.aspmx.l.google.com")
                ])
            elif record_type == 'A':
                return Mock()
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_mx()

        assert "Google Workspace" in result.providers

    def test_mx_single_record_warning(self, analyzer, mock_mx_response):
        """Test warning for single MX record (no failover)."""
        def mock_resolve(domain, record_type):
            if record_type == 'MX':
                return mock_mx_response([(10, "mail.example.com")])
            elif record_type == 'A':
                return Mock()
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve

        result = analyzer.analyze_mx()

        assert any("Single MX record" in issue for issue in result.issues)


# ============================================================================
# Finding Generation Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestFindingGeneration:
    """Test security finding generation."""

    def test_generate_spf_missing_finding(self, analyzer, mock_txt_response):
        """Test generation of SPF missing finding."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response([]))
        analyzer.analyze_spf()
        analyzer._generate_findings()

        spf_findings = [f for f in analyzer.findings if f.record_type == "SPF"]
        assert len(spf_findings) == 1
        assert spf_findings[0].vuln_type == DNSRecordVulnType.SPF_MISSING
        assert spf_findings[0].severity == DNSRecordSeverity.HIGH

    def test_generate_spf_permissive_finding(self, analyzer, mock_txt_response):
        """Test generation of permissive SPF finding."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(["v=spf1 +all"]))
        analyzer.analyze_spf()
        analyzer._generate_findings()

        spf_findings = [f for f in analyzer.findings if f.vuln_type == DNSRecordVulnType.SPF_PERMISSIVE]
        assert len(spf_findings) == 1
        assert spf_findings[0].severity == DNSRecordSeverity.CRITICAL

    def test_generate_dmarc_missing_finding(self, analyzer):
        """Test generation of DMARC missing finding."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NXDOMAIN())
        analyzer.analyze_dmarc()
        analyzer._generate_findings()

        dmarc_findings = [f for f in analyzer.findings if f.record_type == "DMARC"]
        assert len(dmarc_findings) == 1
        assert dmarc_findings[0].vuln_type == DNSRecordVulnType.DMARC_MISSING

    def test_generate_mx_unreachable_finding(self, analyzer, mock_mx_response):
        """Test generation of MX unreachable finding."""
        def mock_resolve(domain, record_type):
            if record_type == 'MX':
                return mock_mx_response([(10, "unreachable.example.com")])
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NXDOMAIN()

        analyzer.resolver.resolve = mock_resolve
        analyzer.analyze_mx()
        analyzer._generate_findings()

        mx_findings = [f for f in analyzer.findings if f.vuln_type == DNSRecordVulnType.MX_UNREACHABLE]
        assert len(mx_findings) == 1
        assert mx_findings[0].severity == DNSRecordSeverity.CRITICAL


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_structure(self, analyzer):
        """Test report structure."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NoAnswer())

        report = analyzer.analyze_all()

        assert 'domain' in report
        assert 'timestamp' in report
        assert 'summary' in report
        assert 'analyses' in report
        assert 'findings' in report
        assert 'recommendations' in report

    def test_report_summary_counts(self, analyzer, mock_txt_response):
        """Test summary finding counts."""
        # Set up critical SPF issue
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(["v=spf1 +all"]))

        report = analyzer.analyze_all()

        assert report['summary']['total_findings'] > 0
        assert report['summary']['critical'] >= 1

    def test_report_includes_all_analyses(self, analyzer):
        """Test that report includes all analysis types."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.resolver.NoAnswer())

        report = analyzer.analyze_all()

        assert 'spf' in report['analyses']
        assert 'dmarc' in report['analyses']
        assert 'dkim' in report['analyses']
        assert 'caa' in report['analyses']
        assert 'mx' in report['analyses']

    def test_recommendations_for_critical_issues(self, analyzer, mock_txt_response):
        """Test that critical issues generate urgent recommendations."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(["v=spf1 +all"]))

        report = analyzer.analyze_all()

        assert any("URGENT" in rec for rec in report['recommendations'])


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_multiple_spf_records(self, analyzer, mock_txt_response):
        """Test handling of multiple SPF records."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response([
            "v=spf1 include:_spf.google.com -all",
            "v=spf1 ip4:192.0.2.0/24 -all"
        ]))

        result = analyzer.analyze_spf()

        # Should only analyze first record
        assert result.exists
        assert result.record == "v=spf1 include:_spf.google.com -all"

    def test_dns_timeout(self, analyzer):
        """Test handling of DNS timeout."""
        from engine.agents.dns_record_analyzer import dns
        analyzer.resolver.resolve = Mock(side_effect=dns.exception.Timeout())

        result = analyzer.analyze_spf()

        assert "Error querying SPF" in result.issues[0]

    def test_malformed_spf_record(self, analyzer, mock_txt_response):
        """Test handling of malformed SPF record."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response(
            ["v=spf1 malformed data here"]
        ))

        result = analyzer.analyze_spf()

        # Should still parse without crashing
        assert result.exists

    def test_empty_domain(self, mock_resolver):
        """Test handling of empty domain."""
        with patch('engine.agents.dns_record_analyzer.dns.resolver.Resolver', return_value=mock_resolver):
            analyzer = DNSRecordAnalyzer(domain="")

            assert analyzer.domain == ""

    def test_finding_to_dict_conversion(self):
        """Test finding conversion to dictionary."""
        finding = DNSRecordFinding(
            title="Test Finding",
            severity=DNSRecordSeverity.HIGH,
            vuln_type=DNSRecordVulnType.SPF_MISSING,
            description="Test description",
            domain="example.com",
            record_type="SPF"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "SPF_MISSING"
        assert finding_dict['title'] == "Test Finding"


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestIntegration:
    """Test full integration scenarios."""

    def test_analyze_all_creates_findings(self, analyzer, mock_txt_response):
        """Test that analyze_all generates findings."""
        analyzer.resolver.resolve = Mock(return_value=mock_txt_response([]))

        report = analyzer.analyze_all()

        assert len(analyzer.findings) > 0
        assert report['summary']['total_findings'] > 0

    def test_secure_configuration(self, analyzer, mock_txt_response, mock_mx_response):
        """Test analysis of secure DNS configuration."""
        def mock_resolve(domain, record_type):
            if record_type == 'TXT':
                if '_dmarc' in domain:
                    return mock_txt_response(["v=DMARC1; p=reject; pct=100"])
                else:
                    return mock_txt_response(["v=spf1 include:_spf.google.com -all"])
            elif record_type == 'MX':
                return mock_mx_response([(10, "mail.google.com")])
            elif record_type == 'A':
                return Mock()
            from engine.agents.dns_record_analyzer import dns
            raise dns.resolver.NoAnswer()

        analyzer.resolver.resolve = mock_resolve

        report = analyzer.analyze_all()

        # Should have minimal high-severity findings
        assert report['summary']['critical'] == 0

    def test_vulnerable_configuration(self, analyzer, mock_txt_response):
        """Test analysis of vulnerable DNS configuration."""
        from engine.agents.dns_record_analyzer import dns

        def mock_resolve(domain, record_type):
            if record_type == 'TXT' and '_dmarc' not in domain:
                return mock_txt_response(["v=spf1 +all"])
            raise dns.resolver.NoAnswer()

        analyzer.resolver.resolve = mock_resolve

        report = analyzer.analyze_all()

        # Should have critical findings
        assert report['summary']['critical'] >= 1
        assert report['summary']['high'] >= 1


# ============================================================================
# Database Integration Tests
# ============================================================================

@pytest.mark.skipif(not DNS_ANALYZER_AVAILABLE, reason="DNS analyzer not available")
class TestDatabaseIntegration:
    """Test database integration."""

    @patch('engine.agents.dns_record_analyzer.DatabaseHooks')
    def test_before_test_check(self, mock_db_hooks, analyzer):
        """Test database check before testing."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested before',
            'previous_findings': [],
            'recommendations': ['Full test recommended']
        }

        # Simulate calling before_test
        from engine.core.db_hooks import DatabaseHooks
        context = DatabaseHooks.before_test('example.com', 'dns_record_analyzer')

        assert not context['should_skip']

    @patch('engine.agents.dns_record_analyzer.BountyHoundDB')
    def test_record_tool_run(self, mock_db, analyzer):
        """Test recording tool run to database."""
        from engine.core.database import BountyHoundDB

        db = BountyHoundDB()
        db.record_tool_run('example.com', 'dns_record_analyzer', findings_count=5, duration_seconds=30)

        # Verify database method was called
        assert mock_db.called


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=engine.agents.dns_record_analyzer', '--cov-report=term-missing'])
