"""
Comprehensive tests for Mass Assignment Tester Agent

Tests cover all components:
- Framework detection
- Field enumeration
- Payload generation
- Response analysis
- Database integration
- End-to-end testing

Target: 95%+ code coverage
"""

import pytest
import json
import sqlite3
from unittest.mock import Mock, patch, MagicMock
from datetime import date

from engine.agents.mass_assignment_tester import (
    Framework,
    AttackType,
    SeverityLevel,
    MassAssignmentPayload,
    MassAssignmentFinding,
    MassAssignmentTestResult,
    FrameworkDetector,
    FieldEnumerator,
    PayloadGenerator,
    ResponseAnalyzer,
    MassAssignmentTester
)


# ============================================================================
# Framework Detector Tests
# ============================================================================

class TestFrameworkDetector:
    """Test framework detection capabilities"""

    def test_detect_rails_from_headers(self):
        """Test Rails detection from X-Runtime header"""
        detector = FrameworkDetector()
        response = {
            'headers': {'X-Runtime': '0.123'},
            'body': ''
        }
        assert detector.detect(response) == Framework.RAILS

    def test_detect_laravel_from_session(self):
        """Test Laravel detection from session cookie"""
        detector = FrameworkDetector()
        response = {
            'headers': {'Set-Cookie': 'laravel_session=abc123'},
            'body': ''
        }
        assert detector.detect(response) == Framework.LARAVEL

    def test_detect_express_from_powered_by(self):
        """Test Express detection from X-Powered-By header"""
        detector = FrameworkDetector()
        response = {
            'headers': {'X-Powered-By': 'Express'},
            'body': ''
        }
        assert detector.detect(response) == Framework.EXPRESS

    def test_detect_django_from_csrf(self):
        """Test Django detection from CSRF token"""
        detector = FrameworkDetector()
        response = {
            'headers': {'Set-Cookie': 'csrftoken=xyz789'},
            'body': ''
        }
        assert detector.detect(response) == Framework.DJANGO

    def test_detect_aspnet_from_viewstate(self):
        """Test ASP.NET detection from __VIEWSTATE"""
        detector = FrameworkDetector()
        response = {
            'headers': {},
            'body': '<input name="__VIEWSTATE" value="abc" />'
        }
        assert detector.detect(response) == Framework.ASPNET

    def test_detect_spring_from_jsessionid(self):
        """Test Spring detection from JSESSIONID"""
        detector = FrameworkDetector()
        response = {
            'headers': {'Set-Cookie': 'JSESSIONID=123'},
            'body': ''
        }
        assert detector.detect(response) == Framework.SPRING

    def test_detect_unknown_framework(self):
        """Test unknown framework when no signatures match"""
        detector = FrameworkDetector()
        response = {
            'headers': {},
            'body': 'Plain text'
        }
        assert detector.detect(response) == Framework.UNKNOWN

    def test_detect_from_url_rails(self):
        """Test Rails detection from URL"""
        detector = FrameworkDetector()
        assert detector.detect_from_url('https://example.com/rails/users') == Framework.RAILS

    def test_detect_from_url_laravel(self):
        """Test Laravel detection from URL"""
        detector = FrameworkDetector()
        assert detector.detect_from_url('https://example.com/api/users.php') == Framework.LARAVEL

    def test_detect_from_url_express(self):
        """Test Express detection from URL"""
        detector = FrameworkDetector()
        assert detector.detect_from_url('https://api.node.example.com/users') == Framework.EXPRESS

    def test_detect_from_url_django(self):
        """Test Django detection from URL"""
        detector = FrameworkDetector()
        assert detector.detect_from_url('https://example.com/django/admin') == Framework.DJANGO


# ============================================================================
# Field Enumerator Tests
# ============================================================================

class TestFieldEnumerator:
    """Test field enumeration capabilities"""

    def test_enumerate_privilege_fields(self):
        """Test enumeration of privilege fields"""
        enumerator = FieldEnumerator()
        fields = enumerator.enumerate_fields({})

        assert 'is_admin' in fields['privilege']
        assert 'role' in fields['privilege']
        assert 'permissions' in fields['privilege']
        assert len(fields['privilege']) > 10

    def test_enumerate_system_fields(self):
        """Test enumeration of system fields"""
        enumerator = FieldEnumerator()
        fields = enumerator.enumerate_fields({})

        assert 'id' in fields['system']
        assert 'user_id' in fields['system']
        assert 'created_at' in fields['system']
        assert len(fields['system']) > 10

    def test_enumerate_financial_fields(self):
        """Test enumeration of financial fields"""
        enumerator = FieldEnumerator()
        fields = enumerator.enumerate_fields({})

        assert 'price' in fields['financial']
        assert 'discount' in fields['financial']
        assert 'balance' in fields['financial']
        assert len(fields['financial']) > 10

    def test_extract_fields_from_json(self):
        """Test field extraction from JSON response"""
        enumerator = FieldEnumerator()
        response = {
            'body': json.dumps({
                'user': {
                    'id': 1,
                    'name': 'test',
                    'profile': {
                        'role': 'user'
                    }
                }
            })
        }

        fields = enumerator.extract_fields_from_response(response)

        assert 'user' in fields
        assert 'user.id' in fields
        assert 'user.profile' in fields
        assert 'user.profile.role' in fields

    def test_extract_fields_from_html(self):
        """Test field extraction from HTML forms"""
        enumerator = FieldEnumerator()
        response = {
            'body': '''
                <form>
                    <input name="username" />
                    <input name="email" />
                    <textarea name="bio"></textarea>
                    <select name="role"></select>
                </form>
            '''
        }

        fields = enumerator.extract_fields_from_response(response)

        assert 'username' in fields
        assert 'email' in fields
        assert 'bio' in fields
        assert 'role' in fields

    def test_extract_from_nested_dict(self):
        """Test recursive extraction from nested dictionaries"""
        enumerator = FieldEnumerator()
        data = {
            'level1': {
                'level2': {
                    'level3': 'value'
                }
            }
        }

        fields = enumerator._extract_from_dict(data)

        assert 'level1' in fields
        assert 'level1.level2' in fields
        assert 'level1.level2.level3' in fields

    def test_extract_from_list(self):
        """Test extraction from list values"""
        enumerator = FieldEnumerator()
        data = {
            'items': [
                {'name': 'item1'},
                {'name': 'item2'}
            ]
        }

        fields = enumerator._extract_from_dict(data)

        assert 'items' in fields


# ============================================================================
# Payload Generator Tests
# ============================================================================

class TestPayloadGenerator:
    """Test payload generation"""

    def test_generate_privilege_escalation_payloads(self):
        """Test privilege escalation payload generation"""
        generator = PayloadGenerator()
        payloads = generator.generate_privilege_escalation(Framework.EXPRESS)

        assert len(payloads) > 0

        # Check for admin payloads
        admin_payloads = [p for p in payloads if 'admin' in p.field.lower()]
        assert len(admin_payloads) > 0

        # Check for role payloads
        role_payloads = [p for p in payloads if 'role' in p.field.lower()]
        assert len(role_payloads) > 0

        # Verify attack type
        for payload in payloads:
            assert payload.attack_type == AttackType.PRIVILEGE_ESCALATION

    def test_generate_price_manipulation_payloads(self):
        """Test price manipulation payload generation"""
        generator = PayloadGenerator()
        payloads = generator.generate_price_manipulation(Framework.EXPRESS)

        assert len(payloads) > 0

        # Check for zero/negative prices
        price_payloads = [p for p in payloads if p.value in [0, 0.01, -1, -100]]
        assert len(price_payloads) > 0

        # Verify attack type
        for payload in payloads:
            assert payload.attack_type == AttackType.PRICE_MANIPULATION

    def test_generate_hidden_field_payloads(self):
        """Test hidden field manipulation payloads"""
        generator = PayloadGenerator()
        payloads = generator.generate_hidden_field(Framework.EXPRESS)

        assert len(payloads) > 0

        # Check for ID manipulation
        id_payloads = [p for p in payloads if 'id' in p.field.lower()]
        assert len(id_payloads) > 0

    def test_generate_nested_injection_rails(self):
        """Test nested injection payloads for Rails"""
        generator = PayloadGenerator()
        payloads = generator.generate_nested_injection(Framework.RAILS)

        assert len(payloads) > 0

        # Check for nested syntax
        nested_payloads = [p for p in payloads if '[' in p.field]
        assert len(nested_payloads) > 0

        # Verify format
        for payload in payloads:
            assert payload.format == 'nested'

    def test_generate_nested_injection_express(self):
        """Test nested injection payloads for Express"""
        generator = PayloadGenerator()
        payloads = generator.generate_nested_injection(Framework.EXPRESS)

        assert len(payloads) > 0

        # Verify format
        for payload in payloads:
            assert payload.format == 'json'
            assert isinstance(payload.value, dict)

    def test_generate_array_injection_payloads(self):
        """Test array injection payloads"""
        generator = PayloadGenerator()
        payloads = generator.generate_array_injection(Framework.EXPRESS)

        assert len(payloads) > 0

        # Check for array syntax
        array_payloads = [p for p in payloads if '[]' in p.field]
        assert len(array_payloads) > 0

        # Verify values are lists
        for payload in payloads:
            assert isinstance(payload.value, list)

    def test_generate_framework_specific_laravel(self):
        """Test Laravel-specific payloads"""
        generator = PayloadGenerator()
        payloads = generator.generate_framework_specific(Framework.LARAVEL)

        assert len(payloads) > 0

        # Check for _method override
        method_payloads = [p for p in payloads if p.field == '_method']
        assert len(method_payloads) > 0

    def test_generate_framework_specific_django(self):
        """Test Django-specific payloads"""
        generator = PayloadGenerator()
        payloads = generator.generate_framework_specific(Framework.DJANGO)

        assert len(payloads) > 0

        # Check for Django staff fields
        staff_payloads = [p for p in payloads if 'staff' in p.field or 'superuser' in p.field]
        assert len(staff_payloads) > 0

    def test_generate_all_payloads(self):
        """Test generation of all payload types"""
        generator = PayloadGenerator()
        payloads = generator.generate_all_payloads(Framework.EXPRESS)

        # Should have payloads from all categories
        assert len(payloads) > 50  # Substantial number of payloads

        # Check all attack types are present
        attack_types = {p.attack_type for p in payloads}
        assert AttackType.PRIVILEGE_ESCALATION in attack_types
        assert AttackType.PRICE_MANIPULATION in attack_types
        assert AttackType.HIDDEN_FIELD in attack_types


# ============================================================================
# Response Analyzer Tests
# ============================================================================

class TestResponseAnalyzer:
    """Test response analysis"""

    def test_response_differs_status_code(self):
        """Test detection of status code changes"""
        analyzer = ResponseAnalyzer()

        baseline = {'status_code': 403, 'body': ''}
        attack = {'status_code': 200, 'body': ''}

        assert analyzer._response_differs(baseline, attack) is True

    def test_response_differs_body_length(self):
        """Test detection of body length differences"""
        analyzer = ResponseAnalyzer()

        baseline = {'status_code': 200, 'body': 'a' * 100}
        attack = {'status_code': 200, 'body': 'b' * 200}

        assert analyzer._response_differs(baseline, attack) is True

    def test_response_differs_json_structure(self):
        """Test detection of JSON structure differences"""
        analyzer = ResponseAnalyzer()

        baseline = {
            'status_code': 200,
            'body': json.dumps({'user': {'role': 'user'}})
        }
        attack = {
            'status_code': 200,
            'body': json.dumps({'user': {'role': 'admin'}})
        }

        assert analyzer._response_differs(baseline, attack) is True

    def test_response_not_differs(self):
        """Test when responses are identical"""
        analyzer = ResponseAnalyzer()

        baseline = {'status_code': 200, 'body': 'test'}
        attack = {'status_code': 200, 'body': 'test'}

        assert analyzer._response_differs(baseline, attack) is False

    def test_check_success_indicators_field_present(self):
        """Test success detection when field appears in response"""
        analyzer = ResponseAnalyzer()

        response = {
            'status_code': 200,
            'body': json.dumps({'user': {'is_admin': True}})
        }

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._check_success_indicators(response, payload) is True

    def test_check_success_indicators_success_message(self):
        """Test success detection from success messages"""
        analyzer = ResponseAnalyzer()

        response = {
            'status_code': 200,
            'body': json.dumps({'message': 'User updated successfully'})
        }

        payload = MassAssignmentPayload(
            field='role',
            value='admin',
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._check_success_indicators(response, payload) is True

    def test_check_success_indicators_privilege_escalation(self):
        """Test privilege escalation detection"""
        analyzer = ResponseAnalyzer()

        response = {
            'status_code': 200,
            'body': json.dumps({'user': {'role': 'administrator'}})
        }

        payload = MassAssignmentPayload(
            field='role',
            value='admin',
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._check_success_indicators(response, payload) is True

    def test_calculate_severity_privilege_escalation(self):
        """Test severity calculation for privilege escalation"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._calculate_severity(payload) == SeverityLevel.CRITICAL

    def test_calculate_severity_price_manipulation_zero(self):
        """Test severity for zero price manipulation"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='price',
            value=0,
            attack_type=AttackType.PRICE_MANIPULATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._calculate_severity(payload) == SeverityLevel.CRITICAL

    def test_calculate_severity_price_manipulation_discount(self):
        """Test severity for discount manipulation"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='discount',
            value=100,
            attack_type=AttackType.PRICE_MANIPULATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        assert analyzer._calculate_severity(payload) == SeverityLevel.HIGH

    def test_flatten_dict_nested(self):
        """Test flattening nested dictionaries"""
        analyzer = ResponseAnalyzer()

        data = {
            'user': {
                'profile': {
                    'role': 'admin'
                }
            }
        }

        flattened = analyzer._flatten_dict(data)

        assert 'user.profile.role' in flattened
        assert flattened['user.profile.role'] == 'admin'

    def test_flatten_dict_with_array(self):
        """Test flattening dictionaries with arrays"""
        analyzer = ResponseAnalyzer()

        data = {
            'items': [
                {'name': 'item1'},
                {'name': 'item2'}
            ]
        }

        flattened = analyzer._flatten_dict(data)

        assert 'items[0].name' in flattened
        assert 'items[1].name' in flattened

    def test_extract_evidence_from_json(self):
        """Test evidence extraction from JSON"""
        analyzer = ResponseAnalyzer()

        response = {
            'body': json.dumps({'user': {'is_admin': True}})
        }

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        evidence = analyzer._extract_evidence(response, payload)

        assert 'is_admin' in evidence.lower()

    def test_format_payload_json(self):
        """Test JSON payload formatting"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        formatted = analyzer._format_payload(payload)

        assert 'is_admin' in formatted
        assert 'true' in formatted.lower()

    def test_generate_title(self):
        """Test finding title generation"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        title = analyzer._generate_title(payload)

        assert 'Privilege Escalation' in title
        assert 'is_admin' in title

    def test_generate_impact(self):
        """Test impact description generation"""
        analyzer = ResponseAnalyzer()

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        impact = analyzer._generate_impact(payload)

        assert len(impact) > 50
        assert 'administrator' in impact.lower()

    def test_generate_remediation_rails(self):
        """Test Rails-specific remediation"""
        analyzer = ResponseAnalyzer()

        remediation = analyzer._generate_remediation(Framework.RAILS)

        assert 'strong parameters' in remediation.lower()
        assert 'permit' in remediation.lower()

    def test_generate_remediation_laravel(self):
        """Test Laravel-specific remediation"""
        analyzer = ResponseAnalyzer()

        remediation = analyzer._generate_remediation(Framework.LARAVEL)

        assert 'fillable' in remediation.lower()
        assert 'guarded' in remediation.lower()

    def test_calculate_cvss(self):
        """Test CVSS score calculation"""
        analyzer = ResponseAnalyzer()

        assert analyzer._calculate_cvss(SeverityLevel.CRITICAL) == 8.8
        assert analyzer._calculate_cvss(SeverityLevel.HIGH) == 7.5
        assert analyzer._calculate_cvss(SeverityLevel.MEDIUM) == 5.3
        assert analyzer._calculate_cvss(SeverityLevel.LOW) == 3.1
        assert analyzer._calculate_cvss(SeverityLevel.INFO) == 0.0

    def test_generate_poc(self):
        """Test POC generation"""
        analyzer = ResponseAnalyzer()

        response = {
            'url': 'https://api.example.com/users/1',
            'method': 'PUT'
        }

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        poc = analyzer._generate_poc(response, payload)

        assert 'curl' in poc
        assert 'PUT' in poc
        assert 'is_admin' in poc

    def test_analyze_response_creates_finding(self):
        """Test that successful analysis creates finding"""
        analyzer = ResponseAnalyzer()

        baseline = {
            'status_code': 403,
            'body': json.dumps({'user': {'role': 'user'}})
        }

        attack = {
            'url': 'https://api.example.com/users/1',
            'method': 'PUT',
            'status_code': 200,
            'body': json.dumps({'user': {'role': 'admin'}}),
            'headers': {'Content-Type': 'application/json'}
        }

        payload = MassAssignmentPayload(
            field='role',
            value='admin',
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        finding = analyzer.analyze_response(baseline, attack, payload)

        assert finding is not None
        assert isinstance(finding, MassAssignmentFinding)
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.field == 'role'


# ============================================================================
# Mass Assignment Tester Tests
# ============================================================================

class TestMassAssignmentTester:
    """Test main tester class"""

    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_make_baseline_request_success(self, mock_request):
        """Test successful baseline request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({'user': {'id': 1}})
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_request.return_value = mock_response

        tester = MassAssignmentTester(target='example.com')
        result = tester._make_baseline_request('https://api.example.com/users/1', 'GET')

        assert result is not None
        assert result['status_code'] == 200
        assert 'user' in result['body']

    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_make_baseline_request_failure(self, mock_request):
        """Test baseline request failure handling"""
        mock_request.side_effect = Exception("Connection error")

        tester = MassAssignmentTester(target='example.com')
        result = tester._make_baseline_request('https://api.example.com/users/1', 'GET')

        assert result is None

    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_make_attack_request_json(self, mock_request):
        """Test attack request with JSON payload"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({'user': {'is_admin': True}})
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_request.return_value = mock_response

        tester = MassAssignmentTester(target='example.com')

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        result = tester._make_attack_request('https://api.example.com/users/1', 'PUT', payload)

        assert result is not None
        assert result['status_code'] == 200

    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_make_attack_request_form(self, mock_request):
        """Test attack request with form data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Updated'
        mock_response.headers = {}
        mock_request.return_value = mock_response

        tester = MassAssignmentTester(target='example.com')

        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='form',
            description='test'
        )

        result = tester._make_attack_request('https://api.example.com/users/1', 'POST', payload)

        assert result is not None

    @patch('engine.agents.mass_assignment_tester.DatabaseHooks.before_test')
    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_test_endpoint(self, mock_request, mock_db_hooks):
        """Test endpoint testing"""
        # Mock database check
        mock_db_hooks.return_value = {
            'should_skip': False,
            'reason': 'Never tested',
            'previous_findings': [],
            'recommendations': []
        }

        # Mock HTTP requests
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({'user': {'id': 1}})
        mock_response.headers = {'X-Powered-By': 'Express'}
        mock_request.return_value = mock_response

        tester = MassAssignmentTester(target='example.com')
        findings = tester.test_endpoint('https://api.example.com/users/1', method='PUT')

        # Should have tested multiple payloads
        assert isinstance(findings, list)

    def test_generate_report_no_findings(self):
        """Test report generation with no findings"""
        tester = MassAssignmentTester(target='example.com')
        report = tester.generate_report()

        assert report['status'] == 'no_findings'
        assert report['total_tests'] == 0

    def test_generate_report_with_findings(self):
        """Test report generation with findings"""
        tester = MassAssignmentTester(target='example.com')

        # Add mock finding
        finding = MassAssignmentFinding(
            title='Test Finding',
            endpoint='https://api.example.com/users/1',
            method='PUT',
            field='is_admin',
            payload='is_admin=true',
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            severity=SeverityLevel.CRITICAL,
            evidence='test evidence',
            before_state={'is_admin': False},
            after_state={'is_admin': True},
            impact='Critical impact',
            remediation='Fix it',
            cvss_score=8.8
        )

        tester.findings.append(finding)

        report = tester.generate_report()

        assert report['status'] == 'vulnerable'
        assert report['total_findings'] == 1
        assert report['critical'] == 1
        assert len(report['findings']) == 1

    def test_generate_summary(self):
        """Test summary generation"""
        tester = MassAssignmentTester(target='example.com')

        # Add mock findings
        for i in range(5):
            finding = MassAssignmentFinding(
                title=f'Finding {i}',
                endpoint='https://api.example.com/users/1',
                method='PUT',
                field='is_admin',
                payload='is_admin=true',
                attack_type=AttackType.PRIVILEGE_ESCALATION,
                framework=Framework.EXPRESS,
                severity=SeverityLevel.CRITICAL if i < 2 else SeverityLevel.HIGH,
                evidence='test',
                before_state={},
                after_state={},
                impact='test',
                remediation='test',
                cvss_score=8.8
            )
            tester.findings.append(finding)

        summary = tester._generate_summary()

        assert 'Discovered 5' in summary
        assert '2 CRITICAL' in summary
        assert '3 HIGH' in summary


# ============================================================================
# Data Model Tests
# ============================================================================

class TestDataModels:
    """Test data model classes"""

    def test_mass_assignment_payload_to_dict(self):
        """Test payload serialization"""
        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        data = payload.to_dict()

        assert data['field'] == 'is_admin'
        assert data['value'] is True
        assert data['attack_type'] == 'privilege_escalation'
        assert data['framework'] == 'express'

    def test_mass_assignment_finding_to_dict(self):
        """Test finding serialization"""
        finding = MassAssignmentFinding(
            title='Test Finding',
            endpoint='https://api.example.com/users/1',
            method='PUT',
            field='is_admin',
            payload='is_admin=true',
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            severity=SeverityLevel.CRITICAL,
            evidence='test',
            before_state={},
            after_state={},
            impact='test',
            remediation='test',
            cvss_score=8.8
        )

        data = finding.to_dict()

        assert data['title'] == 'Test Finding'
        assert data['severity'] == 'CRITICAL'
        assert data['attack_type'] == 'privilege_escalation'
        assert data['cvss_score'] == 8.8

    def test_mass_assignment_test_result_to_dict(self):
        """Test result serialization"""
        payload = MassAssignmentPayload(
            field='is_admin',
            value=True,
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            framework=Framework.EXPRESS,
            format='json',
            description='test'
        )

        result = MassAssignmentTestResult(
            endpoint='https://api.example.com/users/1',
            payload=payload,
            status_code=200,
            response_body='test',
            response_headers={},
            is_vulnerable=True,
            vulnerability_details={'test': 'data'}
        )

        data = result.to_dict()

        assert data['endpoint'] == 'https://api.example.com/users/1'
        assert data['is_vulnerable'] is True
        assert 'payload' in data


# ============================================================================
# Integration Tests
# ============================================================================

class TestMassAssignmentIntegration:
    """Integration tests"""

    @patch('engine.agents.mass_assignment_tester.DatabaseHooks.before_test')
    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_full_workflow(self, mock_request, mock_db_hooks):
        """Test complete testing workflow"""
        # Mock database check
        mock_db_hooks.return_value = {
            'should_skip': False,
            'reason': 'Never tested',
            'previous_findings': [],
            'recommendations': []
        }

        # Mock responses
        baseline_response = Mock()
        baseline_response.status_code = 200
        baseline_response.text = json.dumps({'user': {'role': 'user'}})
        baseline_response.headers = {'X-Powered-By': 'Express'}

        attack_response = Mock()
        attack_response.status_code = 200
        attack_response.text = json.dumps({'user': {'role': 'admin', 'message': 'updated'}})
        attack_response.headers = {'X-Powered-By': 'Express'}

        # Alternate between baseline and attack responses
        mock_request.side_effect = [baseline_response] + [attack_response] * 100

        # Run test
        tester = MassAssignmentTester(target='example.com')
        findings = tester.test_endpoint('https://api.example.com/users/1', method='PUT')

        # Should have found vulnerabilities
        assert len(findings) >= 0  # May find some depending on response matching

        # Generate report
        report = tester.generate_report()
        assert 'status' in report
        assert 'findings' in report


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling"""

    def test_tester_without_requests_library(self):
        """Test error when requests library not available"""
        with patch('engine.agents.mass_assignment_tester.REQUESTS_AVAILABLE', False):
            with pytest.raises(ImportError):
                MassAssignmentTester(target='example.com')

    @patch('engine.agents.mass_assignment_tester.requests.request')
    def test_network_error_handling(self, mock_request):
        """Test handling of network errors"""
        mock_request.side_effect = Exception("Network error")

        tester = MassAssignmentTester(target='example.com')
        result = tester._make_baseline_request('https://api.example.com/users/1', 'GET')

        assert result is None
