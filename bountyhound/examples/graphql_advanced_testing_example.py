#!/usr/bin/env python3
"""
GraphQL Advanced Tester - Usage Example

Demonstrates advanced GraphQL security testing capabilities.
"""

from engine.agents.graphql_advanced_tester import GraphQLAdvancedTester
import json


def main():
    """Run GraphQL advanced security testing example."""

    # Initialize tester
    graphql_url = "https://api.example.com/graphql"

    print("=" * 70)
    print("GraphQL Advanced Tester - Example Usage")
    print("=" * 70)

    # Create tester instance
    tester = GraphQLAdvancedTester(
        url=graphql_url,
        timeout=10,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'BountyHound/5.0'
        }
    )

    print(f"\nTarget: {graphql_url}")
    print("\n" + "=" * 70)

    # Example 1: Quick scan (introspection + batching only)
    print("\n[Example 1] Quick Scan")
    print("-" * 70)
    findings = tester.test_graphql_endpoint(full_scan=False)
    print(f"Quick scan complete: {len(findings)} findings")

    # Example 2: Full scan (all tests)
    print("\n[Example 2] Full Scan")
    print("-" * 70)
    tester_full = GraphQLAdvancedTester(url=graphql_url)
    findings_full = tester_full.test_graphql_endpoint(full_scan=True)
    print(f"Full scan complete: {len(findings_full)} findings")

    # Example 3: Test specific attack vectors
    print("\n[Example 3] Specific Attack Tests")
    print("-" * 70)

    tester_specific = GraphQLAdvancedTester(url=graphql_url)

    # DoS attacks
    print("\nTesting DoS attacks:")
    tester_specific.test_circular_query_dos()
    tester_specific.test_field_duplication_dos()
    tester_specific.test_fragment_recursion()

    # Batching abuse
    print("\nTesting batch abuse:")
    tester_specific.test_batch_query_abuse()
    tester_specific.test_mutation_batching()

    # Directive abuse
    print("\nTesting directive abuse:")
    tester_specific.test_directive_abuse()

    # Schema discovery
    print("\nTesting introspection bypass:")
    tester_specific.test_introspection_bypass()

    # Example 4: Extract schema
    print("\n[Example 4] Schema Extraction")
    print("-" * 70)

    schema = tester.extract_schema(graphql_url)
    print(f"Schema extracted: {len(schema.get('types', []))} types found")

    # Example 5: Test mutations
    print("\n[Example 5] Mutation Testing")
    print("-" * 70)

    mutations = [
        'createUser',
        'updateUser',
        'deleteUser',
        'createPost',
        'deletePost'
    ]

    mutation_findings = tester.test_mutations(graphql_url, mutations)
    print(f"Mutation testing complete: {len(mutation_findings)} vulnerable mutations")

    # Example 6: Find sensitive fields
    print("\n[Example 6] Sensitive Field Detection")
    print("-" * 70)

    sample_schema = {
        'types': [
            {
                'name': 'User',
                'fields': [
                    {'name': 'id'},
                    {'name': 'email'},
                    {'name': 'password'},
                    {'name': 'apiKey'},
                    {'name': 'accessToken'},
                    {'name': 'name'}
                ]
            }
        ]
    }

    sensitive = tester.find_sensitive_fields(sample_schema)
    print(f"Sensitive fields found: {', '.join(sensitive)}")

    # Example 7: Get findings summary
    print("\n[Example 7] Findings Summary")
    print("-" * 70)

    summary = tester_specific.get_findings_summary()
    print(f"Total findings: {summary['total_findings']}")
    print("\nBreakdown by severity:")
    for severity, count in summary['severity_counts'].items():
        if count > 0:
            print(f"  {severity}: {count}")

    # Example 8: Export findings as JSON
    print("\n[Example 8] Export Findings")
    print("-" * 70)

    findings_json = json.dumps(summary['findings'], indent=2)
    print(f"Findings exported as JSON ({len(findings_json)} bytes)")

    # Save to file (optional)
    # with open('graphql_findings.json', 'w') as f:
    #     f.write(findings_json)

    print("\n" + "=" * 70)
    print("GraphQL Advanced Testing Complete!")
    print("=" * 70)

    # Return summary for programmatic use
    return summary


if __name__ == '__main__':
    # Run example
    summary = main()

    # Print final statistics
    print(f"\nFinal Statistics:")
    print(f"  Total vulnerabilities: {summary['total_findings']}")
    print(f"  Critical: {summary['severity_counts']['CRITICAL']}")
    print(f"  High: {summary['severity_counts']['HIGH']}")
    print(f"  Medium: {summary['severity_counts']['MEDIUM']}")
    print(f"  Low: {summary['severity_counts']['LOW']}")
    print(f"  Info: {summary['severity_counts']['INFO']}")
