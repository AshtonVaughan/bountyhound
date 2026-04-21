"""Mock implementations for integration testing"""

import json
from typing import Any, Dict, List, Optional


class MockGraphQLTarget:
    """Mock GraphQL API with known vulnerabilities"""

    def __init__(self):
        self.users = {
            "user-1": {"id": "user-1", "email": "alice@test.com", "privateData": "secret"},
            "user-2": {"id": "user-2", "email": "bob@test.com", "privateData": "secret2"},
        }

    @staticmethod
    def get_schema():
        return {
            "types": [
                {"name": "User", "fields": ["id", "email", "privateData"]},
                {"name": "Query", "fields": ["user", "users"]},
                {"name": "Mutation", "fields": ["updateUser", "deleteUser"]}
            ]
        }

    @staticmethod
    def introspection_enabled():
        return True

    @staticmethod
    def mutation_requires_auth(mutation_name):
        # Vulnerability: deleteUser doesn't require auth
        return mutation_name != "deleteUser"

    def execute_query(self, query: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        if "user(" in query or "users" in query:
            return {
                "data": {
                    "users": [
                        {"id": "user-1", "email": "alice@test.com"},
                        {"id": "user-2", "email": "bob@test.com"}
                    ]
                },
                "errors": None
            }
        return {"data": None, "errors": [{"message": "Unknown query"}]}

    def execute_mutation(self, mutation_name: str, user_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Execute a GraphQL mutation"""
        if mutation_name == "deleteUser":
            # Vulnerability: No auth check!
            if user_id in self.users:
                deleted = self.users.pop(user_id)
                return {
                    "data": {"deleteUser": {"success": True, "id": user_id}},
                    "errors": None
                }
            else:
                return {
                    "data": None,
                    "errors": [{"message": "User not found"}]
                }
        elif token is None:
            return {
                "data": None,
                "errors": [{"message": "Unauthenticated", "extensions": {"code": "UNAUTHENTICATED"}}]
            }
        else:
            return {
                "data": {mutation_name: {"success": True}},
                "errors": None
            }

    def get_user_count(self) -> int:
        """Get current number of users (for state verification)"""
        return len(self.users)


class MockReconTool:
    """Mock reconnaissance tool output"""

    @staticmethod
    def get_recon_data(target: str) -> Dict[str, Any]:
        """Return mock recon data for a target"""
        return {
            "target": target,
            "subdomains": [
                f"api.{target}",
                f"www.{target}",
                f"admin.{target}",
            ],
            "tech_stack": ["graphql", "react", "nginx"],
            "endpoints": [
                f"https://api.{target}/graphql",
                f"https://api.{target}/v1/users",
                f"https://www.{target}/login",
            ],
            "ports": [80, 443, 8080],
        }


class MockDiscoveryEngine:
    """Mock LLM-based discovery engine"""

    @staticmethod
    def generate_hypotheses(recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate vulnerability hypotheses from recon data"""
        hypotheses = []

        # If GraphQL detected, generate GraphQL-specific hypotheses
        if "graphql" in recon_data.get("tech_stack", []):
            hypotheses.append({
                "id": "hypothesis-1",
                "title": "GraphQL mutation lacks authorization",
                "confidence": "HIGH",
                "vuln_type": "BOLA",
                "test_method": "graphql",
                "payload": "",
                "mutation": "mutation { deleteUser(id: \"user-2\") { success id } }",
                "state_query": "query { users { id email } }",
                "endpoints": [f"https://api.{recon_data['target']}/graphql"],
                "success_indicator": "data.deleteUser.success == true",
                "reasoning_track": [
                    "GraphQL endpoint detected at /graphql",
                    "Mutations found: deleteUser, updateUser",
                    "Testing if deleteUser requires authorization",
                ]
            })

            hypotheses.append({
                "id": "hypothesis-2",
                "title": "GraphQL introspection enabled",
                "confidence": "MEDIUM",
                "vuln_type": "INFO_DISCLOSURE",
                "test_method": "graphql",
                "payload": "",
                "query": "query { __schema { types { name } } }",
                "endpoints": [f"https://api.{recon_data['target']}/graphql"],
                "success_indicator": "__schema in response",
                "reasoning_track": [
                    "GraphQL endpoint detected",
                    "Testing if introspection is enabled",
                ]
            })

        return hypotheses


class MockHTTPClient:
    """Mock HTTP client for testing"""

    def __init__(self, target: MockGraphQLTarget):
        self.target = target

    def post(self, url: str, data: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Mock POST request"""
        query = data.get("query", "")

        # Extract mutation name if present
        if "mutation" in query:
            if "deleteUser" in query:
                # Extract user ID from query
                import re
                match = re.search(r'id:\s*"([^"]+)"', query)
                user_id = match.group(1) if match else "unknown"
                token = headers.get("Authorization") if headers else None
                return self.target.execute_mutation("deleteUser", user_id, token)

        # Otherwise treat as query
        token = headers.get("Authorization") if headers else None
        return self.target.execute_query(query, token)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Mock GET request"""
        return {"status": 200, "body": "OK"}
