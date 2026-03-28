"""
Google Cloud Platform Security Testing Module
"""

__all__ = [
    'GCSScanner',
    'GCPIAMTester',
    'CloudFunctionsTester',
    'FirestoreTester',
    'SecretManagerTester'
]


def __getattr__(name):
    """Lazy loading of GCP modules to avoid import errors when dependencies aren't installed"""
    if name == 'GCSScanner':
        from .gcs_scanner import GCSScanner
        return GCSScanner
    elif name == 'GCPIAMTester':
        from .iam_tester import GCPIAMTester
        return GCPIAMTester
    elif name == 'CloudFunctionsTester':
        from .functions_tester import CloudFunctionsTester
        return CloudFunctionsTester
    elif name == 'FirestoreTester':
        from .firestore_tester import FirestoreTester
        return FirestoreTester
    elif name == 'SecretManagerTester':
        from .secret_manager import SecretManagerTester
        return SecretManagerTester
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
