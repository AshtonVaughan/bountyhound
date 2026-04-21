"""
Google Cloud Firestore Security Tester
Test Firestore for security rule misconfigurations and unauthorized access
"""

from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError
from google.auth import default
from typing import List, Dict, Optional
from colorama import Fore, Style
import time

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class FirestoreTester:
    """
    Test Google Cloud Firestore for security vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, project_id: Optional[str] = None):
        """
        Initialize Firestore tester with rate limiting.

        Args:
            rate_limit: Seconds to wait between requests (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            project_id: GCP project ID (optional, detected from credentials)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.project_id = project_id
        self._last_request_time = None
        self.findings = []

        try:
            # Use default credentials
            self.credentials, self.default_project = default()

            if not self.project_id:
                self.project_id = self.default_project

            print(f"{Fore.GREEN}[+] Firestore client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
            if self.project_id:
                print(f"{Fore.CYAN}[*] Project ID: {self.project_id}{Style.RESET_ALL}")

            # Initialize Firestore client
            self.db = firestore.Client(project=self.project_id)

        except DefaultCredentialsError:
            print(f"{Fore.RED}[!] Failed to load GCP credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please configure credentials using gcloud auth{Style.RESET_ALL}")
            raise
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize Firestore client: {e}{Style.RESET_ALL}")
            raise

    def _rate_limited_call(self, func, *args, **kwargs):
        """
        Execute a function with rate limiting and exponential backoff.

        Args:
            func: Function to call
            *args, **kwargs: Arguments to pass to function

        Returns:
            Function result or None on failure
        """
        for attempt in range(self.max_retries):
            try:
                # Add delay before request (except first call)
                if attempt > 0:
                    backoff_time = min(2 ** attempt, 30)  # Max 30s
                    print(f"{Fore.YELLOW}[*] Retry {attempt}, waiting {backoff_time}s...{Style.RESET_ALL}")
                    time.sleep(backoff_time)
                elif self._last_request_time is not None:
                    # Rate limit between normal requests
                    elapsed = time.time() - self._last_request_time
                    if elapsed < self.rate_limit:
                        time.sleep(self.rate_limit - elapsed)

                # Make the request
                result = func(*args, **kwargs)
                self._last_request_time = time.time()
                return result

            except gcp_exceptions.TooManyRequests:
                if attempt < self.max_retries - 1:
                    print(f"{Fore.YELLOW}[!] Rate limited, retrying...{Style.RESET_ALL}")
                    continue
                else:
                    print(f"{Fore.RED}[!] Max retries reached{Style.RESET_ALL}")
                    return None

            except (gcp_exceptions.PermissionDenied, gcp_exceptions.Forbidden):
                return None

            except Exception as e:
                print(f"{Fore.YELLOW}[*] Error: {e}{Style.RESET_ALL}")
                return None

        return None

    def test_collections(self, test_collections: Optional[List[str]] = None) -> List[Dict]:
        """
        Test Firestore collections for unauthorized access

        Args:
            test_collections: List of collection names to test (default: common patterns)

        Returns:
            List of findings
        """
        if not self.project_id:
            print(f"{Fore.YELLOW}[!] No project ID specified{Style.RESET_ALL}")
            return []

        target = f"gcp-{self.project_id}"

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(target, 'firestore_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Testing Firestore collections...{Style.RESET_ALL}")

        # Default collections to test
        if test_collections is None:
            test_collections = [
                'users',
                'profiles',
                'accounts',
                'admin',
                'config',
                'settings',
                'data',
                'logs',
                'messages',
                'notifications',
                'orders',
                'products',
                'customers',
                'transactions'
            ]

        results = []

        for collection_name in test_collections:
            finding = self.test_collection_access(collection_name)
            if finding:
                results.append(finding)

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            target,
            'firestore_tester',
            findings_count=len(self.findings),
            success=True
        )

        return results

    def test_collection_access(self, collection_name: str) -> Optional[Dict]:
        """
        Test access to a specific collection

        Args:
            collection_name: Collection name to test

        Returns:
            Finding dict if accessible, None otherwise
        """
        try:
            collection_ref = self.db.collection(collection_name)

            # Try to list documents with rate limiting
            docs_result = self._rate_limited_call(
                collection_ref.limit(5).get
            )

            if docs_result is None:
                return None

            docs = list(docs_result)

            if docs:
                # Collection is accessible!
                print(f"{Fore.RED}[!] Collection '{collection_name}' is ACCESSIBLE!{Style.RESET_ALL}")
                print(f"    Documents: {len(docs)}")

                finding = {
                    "collection": collection_name,
                    "severity": "HIGH",
                    "status": "accessible",
                    "document_count": len(docs),
                    "description": f"Firestore collection '{collection_name}' is accessible without proper authorization"
                }

                # Extract some field names (not values for privacy)
                if docs:
                    sample_fields = list(docs[0].to_dict().keys()) if docs[0].to_dict() else []
                    finding['sample_fields'] = sample_fields
                    print(f"    Sample fields: {sample_fields}")

                    # Check for sensitive data
                    sensitive_finding = self.check_sensitive_fields(collection_name, sample_fields)
                    if sensitive_finding:
                        finding['sensitive_data'] = sensitive_finding

                self.add_finding(
                    "HIGH",
                    f"Unauthorized Firestore Access: {collection_name}",
                    f"Collection '{collection_name}' can be read without authorization"
                )

                return finding

            else:
                # Collection exists but is empty
                print(f"{Fore.CYAN}[*] Collection '{collection_name}' exists but is empty{Style.RESET_ALL}")
                return None

        except gcp_exceptions.PermissionDenied:
            # Expected - collection is protected
            print(f"{Fore.GREEN}[+] Collection '{collection_name}' is protected{Style.RESET_ALL}")
            return None

        except gcp_exceptions.NotFound:
            # Collection doesn't exist
            return None

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error testing '{collection_name}': {e}{Style.RESET_ALL}")
            return None

    def check_sensitive_fields(self, collection_name: str, fields: List[str]) -> Optional[Dict]:
        """
        Check if fields contain sensitive data

        Args:
            collection_name: Collection name
            fields: List of field names

        Returns:
            Dict of sensitive data findings or None
        """
        sensitive_patterns = {
            'email': 'PII',
            'phone': 'PII',
            'ssn': 'PII',
            'password': 'CREDENTIAL',
            'token': 'CREDENTIAL',
            'api_key': 'CREDENTIAL',
            'secret': 'CREDENTIAL',
            'credit_card': 'PAYMENT',
            'card_number': 'PAYMENT',
            'cvv': 'PAYMENT',
            'address': 'PII',
            'dob': 'PII',
            'birth': 'PII'
        }

        sensitive_found = []

        for field in fields:
            field_lower = field.lower()
            for pattern, data_type in sensitive_patterns.items():
                if pattern in field_lower:
                    sensitive_found.append({
                        "field": field,
                        "type": data_type,
                        "pattern": pattern
                    })
                    print(f"{Fore.RED}[!] Sensitive field detected: {field} ({data_type}){Style.RESET_ALL}")

                    self.add_finding(
                        "CRITICAL",
                        f"Sensitive Data Exposure: {collection_name}",
                        f"Collection contains sensitive field '{field}' ({data_type}) and is readable"
                    )

        return sensitive_found if sensitive_found else None

    def test_document_write(self, collection_name: str) -> Optional[Dict]:
        """
        Test if we can write to a collection

        Args:
            collection_name: Collection name to test

        Returns:
            Finding dict if writable, None otherwise
        """
        try:
            collection_ref = self.db.collection(collection_name)

            # Try to create a test document
            test_doc_ref = collection_ref.document('bountyhound-test')
            test_data = {
                'test': 'BountyHound security test',
                'timestamp': firestore.SERVER_TIMESTAMP
            }

            result = self._rate_limited_call(
                test_doc_ref.set,
                test_data
            )

            if result is not None:
                print(f"{Fore.RED}[!] CRITICAL: Can write to '{collection_name}'!{Style.RESET_ALL}")

                # Clean up - try to delete
                try:
                    test_doc_ref.delete()
                    print(f"{Fore.GREEN}[+] Cleaned up test document{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[!] Failed to clean up test document{Style.RESET_ALL}")

                self.add_finding(
                    "CRITICAL",
                    f"Unauthorized Write Access: {collection_name}",
                    f"Can create/modify documents in collection '{collection_name}' without authorization"
                )

                return {
                    "collection": collection_name,
                    "severity": "CRITICAL",
                    "issue": "unauthorized_write",
                    "description": f"Can write to Firestore collection '{collection_name}'"
                }

            return None

        except gcp_exceptions.PermissionDenied:
            # Expected - write is protected
            print(f"{Fore.GREEN}[+] Write to '{collection_name}' is protected{Style.RESET_ALL}")
            return None

        except Exception as e:
            return None

    def test_document_delete(self, collection_name: str) -> Optional[Dict]:
        """
        Test if we can delete documents

        Args:
            collection_name: Collection name to test

        Returns:
            Finding dict if deletable, None otherwise
        """
        try:
            # First, try to create a test document
            collection_ref = self.db.collection(collection_name)
            test_doc_ref = collection_ref.document('bountyhound-delete-test')

            # Try to write first
            write_result = self._rate_limited_call(
                test_doc_ref.set,
                {'test': 'delete test'}
            )

            if write_result is None:
                # Can't write, so can't test delete
                return None

            # Now try to delete
            delete_result = self._rate_limited_call(test_doc_ref.delete)

            if delete_result is not None:
                print(f"{Fore.RED}[!] CRITICAL: Can delete from '{collection_name}'!{Style.RESET_ALL}")

                self.add_finding(
                    "CRITICAL",
                    f"Unauthorized Delete Access: {collection_name}",
                    f"Can delete documents from collection '{collection_name}' without authorization"
                )

                return {
                    "collection": collection_name,
                    "severity": "CRITICAL",
                    "issue": "unauthorized_delete",
                    "description": f"Can delete from Firestore collection '{collection_name}'"
                }

            return None

        except gcp_exceptions.PermissionDenied:
            # Expected - delete is protected
            return None

        except Exception as e:
            return None

    def enumerate_collections(self) -> List[str]:
        """
        Attempt to enumerate all collections

        Returns:
            List of collection names
        """
        try:
            # Note: collections() requires specific permissions
            collections_result = self._rate_limited_call(self.db.collections)

            if collections_result is None:
                print(f"{Fore.YELLOW}[!] Cannot enumerate collections{Style.RESET_ALL}")
                return []

            collections = [col.id for col in collections_result]

            print(f"{Fore.GREEN}[+] Found {len(collections)} collection(s){Style.RESET_ALL}")
            for col in collections:
                print(f"    - {col}")

            return collections

        except gcp_exceptions.PermissionDenied:
            print(f"{Fore.YELLOW}[!] Permission denied to enumerate collections{Style.RESET_ALL}")
            return []

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to enumerate collections: {e}{Style.RESET_ALL}")
            return []

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='GCP Firestore Security Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between requests (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--project-id', required=True, help='GCP project ID')
    parser.add_argument('--collections', nargs='+', help='Collections to test')

    args = parser.parse_args()

    tester = FirestoreTester(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        project_id=args.project_id
    )

    # Enumerate collections if possible
    all_collections = tester.enumerate_collections()

    # Test specified or default collections
    results = tester.test_collections(test_collections=args.collections)

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Collections tested: {len(results)}")
    print(f"Findings: {len(tester.findings)}")


if __name__ == "__main__":
    main()
