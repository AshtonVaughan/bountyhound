"""
Tests for Firestore Tester
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError

from engine.cloud.gcp.firestore_tester import FirestoreTester


class TestFirestoreTester:
    """Test suite for Firestore Tester"""

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_init_with_credentials(self, mock_client, mock_default):
        """Test initialization with valid credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = FirestoreTester(rate_limit=0.1, project_id='test-project')

        assert tester.rate_limit == 0.1
        assert tester.project_id == 'test-project'
        assert tester.findings == []

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    @patch('engine.cloud.gcp.firestore_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.firestore_tester.BountyHoundDB')
    def test_test_collections_skip(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test when database says to skip"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = FirestoreTester()
        results = tester.test_collections()

        assert results == []

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    @patch('engine.cloud.gcp.firestore_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.firestore_tester.BountyHoundDB')
    def test_test_collections_proceed(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test when database check passes"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test'
        }

        tester = FirestoreTester(rate_limit=0)
        tester.test_collection_access = Mock(return_value=None)

        results = tester.test_collections(['users', 'products'])

        assert tester.test_collection_access.call_count == 2

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_test_collection_access_accessible(self, mock_client, mock_default):
        """Test detecting accessible collection"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_doc = Mock()
        mock_doc.to_dict.return_value = {
            'email': 'test@example.com',
            'name': 'Test User'
        }

        mock_collection = Mock()
        mock_collection.limit.return_value.get.return_value = [mock_doc]

        mock_db = Mock()
        mock_db.collection.return_value = mock_collection
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        tester.check_sensitive_fields = Mock()

        result = tester.test_collection_access('users')

        assert result is not None
        assert result['severity'] == 'HIGH'
        assert result['status'] == 'accessible'

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_test_collection_access_protected(self, mock_client, mock_default):
        """Test protected collection"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_collection = Mock()
        mock_collection.limit.return_value.get.side_effect = gcp_exceptions.PermissionDenied('Access denied')

        mock_db = Mock()
        mock_db.collection.return_value = mock_collection
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        result = tester.test_collection_access('users')

        assert result is None

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_check_sensitive_fields_pii(self, mock_client, mock_default):
        """Test detecting PII in fields"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = FirestoreTester(rate_limit=0)

        fields = ['user_email', 'phone_number', 'ssn', 'address']
        result = tester.check_sensitive_fields('users', fields)

        assert result is not None
        assert len(result) >= 4
        assert any(f['type'] == 'PII' for f in result)

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_check_sensitive_fields_credentials(self, mock_client, mock_default):
        """Test detecting credentials in fields"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = FirestoreTester(rate_limit=0)

        fields = ['api_key', 'password_hash', 'secret_token']
        result = tester.check_sensitive_fields('config', fields)

        assert result is not None
        assert any(f['type'] == 'CREDENTIAL' for f in result)

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_check_sensitive_fields_payment(self, mock_client, mock_default):
        """Test detecting payment data in fields"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = FirestoreTester(rate_limit=0)

        fields = ['credit_card_number', 'cvv_code', 'card_number']
        result = tester.check_sensitive_fields('payments', fields)

        assert result is not None
        assert any(f['type'] == 'PAYMENT' for f in result)

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    @patch('engine.cloud.gcp.firestore_tester.firestore.SERVER_TIMESTAMP', 'SERVER_TIMESTAMP')
    def test_test_document_write_allowed(self, mock_client, mock_default):
        """Test detecting unauthorized write access"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_doc = Mock()
        mock_doc.set.return_value = None
        mock_doc.delete.return_value = None

        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc

        mock_db = Mock()
        mock_db.collection.return_value = mock_collection
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        result = tester.test_document_write('users')

        assert result is not None
        assert result['severity'] == 'CRITICAL'
        assert result['issue'] == 'unauthorized_write'

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_test_document_write_forbidden(self, mock_client, mock_default):
        """Test write blocked by permissions"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_doc = Mock()
        mock_doc.set.side_effect = gcp_exceptions.PermissionDenied('Access denied')

        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc

        mock_db = Mock()
        mock_db.collection.return_value = mock_collection
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        result = tester.test_document_write('users')

        assert result is None

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    @patch('engine.cloud.gcp.firestore_tester.firestore.SERVER_TIMESTAMP', 'SERVER_TIMESTAMP')
    def test_test_document_delete_allowed(self, mock_client, mock_default):
        """Test detecting unauthorized delete access"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_doc = Mock()
        mock_doc.set.return_value = None
        mock_doc.delete.return_value = None

        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc

        mock_db = Mock()
        mock_db.collection.return_value = mock_collection
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        result = tester.test_document_delete('users')

        assert result is not None
        assert result['severity'] == 'CRITICAL'
        assert result['issue'] == 'unauthorized_delete'

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_enumerate_collections(self, mock_client, mock_default):
        """Test enumerating collections"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_col1 = Mock()
        mock_col1.id = 'users'
        mock_col2 = Mock()
        mock_col2.id = 'products'

        mock_db = Mock()
        mock_db.collections.return_value = [mock_col1, mock_col2]
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        collections = tester.enumerate_collections()

        assert len(collections) == 2
        assert 'users' in collections
        assert 'products' in collections

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_enumerate_collections_forbidden(self, mock_client, mock_default):
        """Test enumeration blocked by permissions"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_db = Mock()
        mock_db.collections.side_effect = gcp_exceptions.PermissionDenied('Access denied')
        mock_client.return_value = mock_db

        tester = FirestoreTester(rate_limit=0)
        collections = tester.enumerate_collections()

        assert collections == []


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
