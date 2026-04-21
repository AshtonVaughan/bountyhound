"""
AI Hunt Example - Demonstrates AI-powered continuous learning hunt

This example shows how to use the AIPoweredHunter programmatically with
various configurations and workflows.

Prerequisites:
    - Set ANTHROPIC_API_KEY environment variable
    - BountyHound database initialized
    - Target in scope for testing

Usage:
    python examples/ai_hunt_example.py
"""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.core.ai_hunter import AIPoweredHunter
from engine.core.database import BountyHoundDB


async def example_1_basic_hunt():
    """
    Example 1: Basic AI-powered hunt

    Demonstrates the simplest usage - run a full autonomous hunt
    on a target with default settings.
    """
    print("=" * 60)
    print("EXAMPLE 1: Basic AI Hunt")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠  Set ANTHROPIC_API_KEY environment variable")
        print("   Example: export ANTHROPIC_API_KEY='your-key-here'")
        return None

    # Initialize hunter
    hunter = AIPoweredHunter(
        target="testphp.vulnweb.com",  # Test target
        api_key=api_key,
        max_iterations=5  # Limit for example
    )

    print(f"\n🎯 Starting hunt on {hunter.target}")
    print(f"   Max iterations: {hunter.max_iterations}")
    print(f"   Model: claude-opus-4-6\n")

    # Run the hunt
    result = await hunter.hunt()

    # Display results
    print(f"\n{'=' * 60}")
    print("RESULTS")
    print("=" * 60)
    print(f"✓ Hunt complete!")
    print(f"  Iterations: {result['iterations']}")
    print(f"  Findings: {len(result['findings'])}")
    print(f"  Patterns Learned: {len(result['patterns'])}")
    print(f"  Exploit Chains: {len(result['exploit_chains'])}")

    if result['findings']:
        print(f"\n📋 Findings Summary:")
        for i, finding in enumerate(result['findings'], 1):
            print(f"  {i}. {finding.get('title', 'Untitled')}")
            print(f"     Severity: {finding.get('severity', 'UNKNOWN')}")
            print(f"     Endpoint: {finding.get('endpoint', 'N/A')}")

    if result['patterns']:
        print(f"\n🧠 Patterns Learned:")
        for i, pattern in enumerate(result['patterns'], 1):
            print(f"  {i}. {pattern.get('name', 'Unnamed pattern')}")
            print(f"     Tech: {', '.join(pattern.get('tech', []))}")

    return result


async def example_2_command_routing():
    """
    Example 2: Command routing simulation

    Shows how commands would be routed to the AI hunter.
    Note: Requires command_router.py implementation.
    """
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Command Routing (Simulation)")
    print("=" * 60)

    # Simulated command routing
    commands = [
        "/hunt example.com",
        "/test api.example.com --context 'GraphQL API'",
        "/learn",
        "/chain",
        "/report example.com"
    ]

    print("\nCommand routing examples:")
    for cmd in commands:
        print(f"\n  Command: {cmd}")

        # Route logic (simplified)
        if cmd.startswith("/hunt"):
            target = cmd.split()[1]
            print(f"  → Type: ai_hunt")
            print(f"  → Agent: AIPoweredHunter")
            print(f"  → Target: {target}")
        elif cmd.startswith("/test"):
            parts = cmd.split()
            target = parts[1]
            context = cmd.split("'")[1] if "'" in cmd else None
            print(f"  → Type: targeted_test")
            print(f"  → Target: {target}")
            if context:
                print(f"  → Context: {context}")
                if "graphql" in context.lower():
                    print(f"  → Agents: graphql_tester")
        elif cmd.startswith("/learn"):
            print(f"  → Type: extract_patterns")
            print(f"  → Agent: PatternExtractor")
        elif cmd.startswith("/chain"):
            print(f"  → Type: find_chains")
            print(f"  → Agent: ExploitChainer")
        elif cmd.startswith("/report"):
            target = cmd.split()[1] if len(cmd.split()) > 1 else "all"
            print(f"  → Type: generate_report")
            print(f"  → Agent: ReportGenerator")
            print(f"  → Target: {target}")


async def example_3_pattern_extraction():
    """
    Example 3: Pattern extraction and application

    Demonstrates how the AI extracts reusable patterns from findings
    and applies them to similar endpoints.
    """
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Pattern Extraction and Application")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠  Set ANTHROPIC_API_KEY environment variable")
        return

    hunter = AIPoweredHunter(
        target="example.com",
        api_key=api_key,
        max_iterations=1  # Not running full hunt
    )

    # Simulate a successful finding
    finding = {
        "title": "IDOR in getUserProfile mutation",
        "endpoint": "/api/graphql",
        "method": "POST",
        "payload": 'mutation { user(id: "victim-uuid") { email privateData } }',
        "response": '{"data": {"user": {"email": "victim@example.com"}}}',
        "tech": "GraphQL",
        "verified": True
    }

    print("\n📌 Simulated Finding:")
    print(f"   Title: {finding['title']}")
    print(f"   Endpoint: {finding['endpoint']}")
    print(f"   Tech: {finding['tech']}")

    print("\n🧠 Extracting reusable pattern...")
    pattern = await hunter._extract_pattern(finding)

    print(f"\n✓ Pattern Extracted:")
    print(f"   Name: {pattern.get('name', 'N/A')}")
    print(f"   Tech: {', '.join(pattern.get('tech', []))}")
    print(f"   Confidence: {pattern.get('confidence', 'N/A')}")
    print(f"   Template: {pattern.get('exploit_template', 'N/A')}")

    if pattern.get('indicators'):
        print(f"\n   Indicators:")
        for indicator in pattern['indicators']:
            print(f"     • {indicator}")

    if pattern.get('variations'):
        print(f"\n   Variations to test:")
        for variation in pattern['variations']:
            print(f"     • {variation}")

    # Find similar endpoints
    print("\n🔍 Finding similar endpoints to test...")
    all_endpoints = [
        "/api/graphql",
        "/api/v2/graphql",
        "/graphql",
        "/api/rest/users",  # Different, won't match
        "/api/gql"
    ]

    similar = hunter._find_similar_endpoints("/api/graphql", all_endpoints)

    print(f"\n✓ Similar endpoints found: {len(similar)}")
    for endpoint in similar:
        print(f"   • {endpoint}")
        print(f"     (Will test with pattern automatically)")


async def example_4_hypothesis_testing():
    """
    Example 4: Custom hypothesis testing

    Shows how to test a specific hypothesis manually.
    """
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Custom Hypothesis Testing")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠  Set ANTHROPIC_API_KEY environment variable")
        return

    hunter = AIPoweredHunter(
        target="example.com",
        api_key=api_key
    )

    # Custom hypothesis
    hypothesis = {
        "title": "Horizontal privilege escalation in user API",
        "test": "Send GET /api/user/{victim_id} with attacker JWT token",
        "rationale": "Testing if authorization checks validate user ownership",
        "confidence": "MEDIUM"
    }

    print("\n📋 Testing Custom Hypothesis:")
    print(f"   Title: {hypothesis['title']}")
    print(f"   Test: {hypothesis['test']}")
    print(f"   Rationale: {hypothesis['rationale']}")
    print(f"   Confidence: {hypothesis['confidence']}")

    print("\n⚙  Executing test...")
    print("   (Note: This example uses mock - real implementation routes to agents)")

    # In real usage, this would route to appropriate agent
    # For example:
    # result = await hunter._test_hypothesis(hypothesis)

    # Simulated result
    result = {
        "success": True,
        "finding": {
            "title": "Horizontal Privilege Escalation - IDOR",
            "severity": "HIGH",
            "endpoint": "/api/user/victim123",
            "verified": True
        }
    }

    if result["success"]:
        print(f"\n✓ Vulnerability Found!")
        print(f"   Title: {result['finding']['title']}")
        print(f"   Severity: {result['finding']['severity']}")
        print(f"   Endpoint: {result['finding']['endpoint']}")

        print("\n🧠 Extracting pattern for reuse...")
        # pattern = await hunter._extract_pattern(result['finding'])
        print("   Pattern would be saved to database for future hunts")
    else:
        print("\n✗ No vulnerability found")


async def example_5_database_queries():
    """
    Example 5: Database queries and analytics

    Shows how to query the learning database for insights.
    """
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Database Analytics")
    print("=" * 60)

    db = BountyHoundDB()

    # Query 1: Pattern success rates
    print("\n📊 Pattern Success Rates:")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, success_count, failure_count, success_rate,
                   json_extract(tech, '$[0]') as primary_tech
            FROM learned_patterns
            WHERE success_count + failure_count >= 3
            ORDER BY success_rate DESC
            LIMIT 5
        """)

        patterns = cursor.fetchall()
        if patterns:
            for row in patterns:
                name, success, failure, rate, tech = row
                print(f"\n   • {name}")
                print(f"     Tech: {tech}")
                print(f"     Success: {success}/{success + failure} ({rate:.1%})")
        else:
            print("   No patterns with sufficient data yet")
            print("   (Run more hunts to build pattern database)")

    # Query 2: Hypothesis test results
    print("\n\n📊 Hypothesis Test Results (Last 30 days):")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) as total_tests,
                SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as successes,
                SUM(CASE WHEN result='failure' THEN 1 ELSE 0 END) as failures,
                COUNT(DISTINCT target) as targets_tested
            FROM hypothesis_tests
            WHERE tested_at >= date('now', '-30 days')
        """)

        row = cursor.fetchone()
        if row and row[0] > 0:
            total, success, failure, targets = row
            success_rate = (success / total) * 100 if total > 0 else 0
            print(f"\n   Total Tests: {total}")
            print(f"   Successes: {success} ({success_rate:.1f}%)")
            print(f"   Failures: {failure}")
            print(f"   Targets Tested: {targets}")
        else:
            print("   No hypothesis tests recorded yet")
            print("   (Run /hunt to start testing)")

    # Query 3: Exploit chains
    print("\n\n📊 Exploit Chains Discovered:")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT target, chain_title, impact, verified
            FROM exploit_chains
            ORDER BY
                CASE impact
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                created_at DESC
            LIMIT 5
        """)

        chains = cursor.fetchall()
        if chains:
            for row in chains:
                target, title, impact, verified = row
                status = "✓ Verified" if verified else "⚠ Unverified"
                print(f"\n   • {title}")
                print(f"     Target: {target}")
                print(f"     Impact: {impact}")
                print(f"     Status: {status}")
        else:
            print("   No exploit chains discovered yet")
            print("   (Run /chain after finding multiple vulnerabilities)")


async def example_6_learning_progress():
    """
    Example 6: Track learning progress over time

    Shows how AI hunter improves with more hunts.
    """
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Learning Progress Tracking")
    print("=" * 60)

    db = BountyHoundDB()

    print("\n📈 Success Rate Trends:")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                DATE(tested_at) as date,
                COUNT(*) as tests,
                SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as successes,
                ROUND(
                    SUM(CASE WHEN result='success' THEN 1.0 ELSE 0.0 END) / COUNT(*) * 100,
                    1
                ) as success_rate
            FROM hypothesis_tests
            WHERE tested_at >= date('now', '-14 days')
            GROUP BY DATE(tested_at)
            ORDER BY date DESC
            LIMIT 7
        """)

        rows = cursor.fetchall()
        if rows:
            print("\n   Date       | Tests | Successes | Rate")
            print("   " + "-" * 45)
            for row in rows:
                date, tests, successes, rate = row
                print(f"   {date} |   {tests:>3} |       {successes:>3} | {rate:>4}%")

            # Calculate improvement
            if len(rows) >= 2:
                recent_rate = rows[0][3]
                old_rate = rows[-1][3]
                improvement = recent_rate - old_rate
                if improvement > 0:
                    print(f"\n   📈 Improvement: +{improvement:.1f}% over period")
                elif improvement < 0:
                    print(f"\n   📉 Decline: {improvement:.1f}% over period")
                else:
                    print(f"\n   → Stable performance")
        else:
            print("   No data available yet")
            print("   (Run multiple hunts to track progress)")

    print("\n\n📊 Pattern Reuse Efficiency:")
    with db._get_connection() as conn:
        cursor = conn.cursor()

        # Total patterns
        cursor.execute("SELECT COUNT(*) FROM learned_patterns")
        total_patterns = cursor.fetchone()[0]

        # Patterns with 50%+ success rate
        cursor.execute("""
            SELECT COUNT(*)
            FROM learned_patterns
            WHERE success_rate >= 0.5
        """)
        effective_patterns = cursor.fetchone()[0]

        print(f"\n   Total Patterns Learned: {total_patterns}")
        print(f"   Effective Patterns (50%+ success): {effective_patterns}")

        if total_patterns > 0:
            efficiency = (effective_patterns / total_patterns) * 100
            print(f"   Pattern Efficiency: {efficiency:.1f}%")

            if efficiency >= 70:
                print("   ✓ Excellent - High quality learning")
            elif efficiency >= 50:
                print("   ✓ Good - Decent pattern quality")
            elif efficiency >= 30:
                print("   ⚠ Fair - Some noise in patterns")
            else:
                print("   ⚠ Low - Review pattern extraction")


async def main():
    """Run all examples"""
    print("\n" + "🎯" * 30)
    print("AI-POWERED HUNTER - USAGE EXAMPLES")
    print("🎯" * 30 + "\n")

    # Run examples sequentially
    try:
        # Example 1: Basic hunt (requires API key)
        result = await example_1_basic_hunt()

        # Example 2: Command routing (no API key needed)
        await example_2_command_routing()

        # Example 3: Pattern extraction (requires API key)
        if os.getenv("ANTHROPIC_API_KEY"):
            await example_3_pattern_extraction()
        else:
            print("\n⚠  Skipping Example 3 (requires ANTHROPIC_API_KEY)")

        # Example 4: Custom hypothesis (requires API key)
        if os.getenv("ANTHROPIC_API_KEY"):
            await example_4_hypothesis_testing()
        else:
            print("\n⚠  Skipping Example 4 (requires ANTHROPIC_API_KEY)")

        # Example 5: Database queries (always available)
        await example_5_database_queries()

        # Example 6: Learning progress (always available)
        await example_6_learning_progress()

    except KeyboardInterrupt:
        print("\n\n⚠  Examples interrupted by user")
        return
    except Exception as e:
        print(f"\n\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()
        return

    # Final summary
    print("\n" + "=" * 60)
    print("EXAMPLES COMPLETE")
    print("=" * 60)
    print("\n📚 Next Steps:")
    print("   1. Set ANTHROPIC_API_KEY environment variable")
    print("   2. Run a real hunt: /hunt testphp.vulnweb.com")
    print("   3. Review patterns: Query learned_patterns table")
    print("   4. Check analytics: Run Example 5 periodically")
    print("   5. Build pattern database: Run 5+ hunts")
    print("\n📖 See docs/AI_HUNTER_GUIDE.md for detailed documentation")
    print()


if __name__ == "__main__":
    asyncio.run(main())
