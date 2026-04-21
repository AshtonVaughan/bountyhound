#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BountyHound Agent Profile Manager

Manages which agent groups are active to optimize context window usage.
Moves inactive agents to disabled/ folder and restores them when needed.
"""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import List, Set

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

PLUGIN_ROOT = Path(__file__).parent.parent
AGENTS_DIR = PLUGIN_ROOT / "agents"
DISABLED_DIR = AGENTS_DIR / "disabled"
PROFILES_FILE = Path(__file__).parent / "agent-profiles.json"


def load_profiles() -> dict:
    """Load agent profiles configuration."""
    with open(PROFILES_FILE, 'r') as f:
        return json.load(f)


def get_all_agent_files() -> Set[str]:
    """Get all agent markdown files (active + disabled)."""
    agents = set()

    # Active agents
    if AGENTS_DIR.exists():
        for f in AGENTS_DIR.glob("*.md"):
            agents.add(f.stem)

    # Disabled agents
    if DISABLED_DIR.exists():
        for f in DISABLED_DIR.glob("*.md"):
            agents.add(f.stem)

    return agents


def get_active_agents() -> Set[str]:
    """Get currently active agent names."""
    if not AGENTS_DIR.exists():
        return set()

    return {f.stem for f in AGENTS_DIR.glob("*.md")}


def disable_agent(agent_name: str):
    """Move an agent to the disabled folder."""
    DISABLED_DIR.mkdir(exist_ok=True)

    src = AGENTS_DIR / f"{agent_name}.md"
    dst = DISABLED_DIR / f"{agent_name}.md"

    if src.exists():
        shutil.move(str(src), str(dst))
        print(f"  ✓ Disabled {agent_name}")
    elif dst.exists():
        pass  # Already disabled
    else:
        print(f"  ⚠ Agent not found: {agent_name}")


def enable_agent(agent_name: str):
    """Move an agent from disabled folder to active."""
    src = DISABLED_DIR / f"{agent_name}.md"
    dst = AGENTS_DIR / f"{agent_name}.md"

    if src.exists():
        shutil.move(str(src), str(dst))
        print(f"  ✓ Enabled {agent_name}")
    elif dst.exists():
        pass  # Already enabled
    else:
        print(f"  ⚠ Agent not found: {agent_name}")


def enable_profile(profile_name: str, profiles: dict):
    """Enable all agents in a profile."""
    if profile_name not in profiles['profiles']:
        print(f"❌ Unknown profile: {profile_name}")
        print(f"Available: {', '.join(profiles['profiles'].keys())}")
        return

    profile = profiles['profiles'][profile_name]
    print(f"\n🔧 Enabling profile: {profile_name}")
    print(f"   {profile['description']}")

    for agent_name in profile['agents']:
        enable_agent(agent_name)


def disable_profile(profile_name: str, profiles: dict):
    """Disable all agents in a profile."""
    if profile_name not in profiles['profiles']:
        print(f"❌ Unknown profile: {profile_name}")
        return

    profile = profiles['profiles'][profile_name]
    print(f"\n🔧 Disabling profile: {profile_name}")

    for agent_name in profile['agents']:
        disable_agent(agent_name)


def reset_to_defaults(profiles: dict):
    """Disable all agents except default profiles."""
    print("\n🔄 Resetting to default configuration...")
    print(f"   Enabling: {', '.join(profiles['default_enabled'])}")

    # Get all agents that should be enabled
    enabled_set = set()
    for profile_name in profiles['default_enabled']:
        if profile_name in profiles['profiles']:
            enabled_set.update(profiles['profiles'][profile_name]['agents'])

    # Disable everything first
    all_agents = get_all_agent_files()
    DISABLED_DIR.mkdir(exist_ok=True)

    for agent_name in all_agents:
        if agent_name not in enabled_set:
            disable_agent(agent_name)

    # Enable default profiles
    for agent_name in enabled_set:
        enable_agent(agent_name)

    print(f"\n✅ Reset complete!")
    print(f"   Active: {len(enabled_set)} agents")
    print(f"   Disabled: {len(all_agents) - len(enabled_set)} agents")


def show_status(profiles: dict):
    """Show current agent status."""
    active = get_active_agents()
    all_agents = get_all_agent_files()
    disabled = all_agents - active

    print("\n📊 Agent Status")
    print(f"   Active: {len(active)} agents")
    print(f"   Disabled: {len(disabled)} agents")
    print(f"   Total: {len(all_agents)} agents")

    print("\n🔍 Active Profiles:")
    for profile_name, profile in profiles['profiles'].items():
        profile_agents = set(profile['agents'])
        active_count = len(profile_agents & active)
        total_count = len(profile_agents)

        status = "✅" if active_count == total_count else "⚠️" if active_count > 0 else "❌"
        print(f"   {status} {profile_name}: {active_count}/{total_count} agents")
        print(f"      {profile['description']}")


def list_profiles(profiles: dict):
    """List all available profiles."""
    print("\n📋 Available Profiles:\n")

    for name, profile in profiles['profiles'].items():
        count = len(profile['agents'])
        print(f"  • {name:20s} ({count:3d} agents) - {profile['description']}")

    print(f"\n🔧 Default enabled: {', '.join(profiles['default_enabled'])}")


def main():
    import sys

    profiles = load_profiles()

    if len(sys.argv) < 2:
        print("BountyHound Agent Manager\n")
        print("Usage:")
        print("  manage-agents.py status              - Show current status")
        print("  manage-agents.py list                - List all profiles")
        print("  manage-agents.py reset               - Reset to defaults (core+web+api)")
        print("  manage-agents.py enable <profile>    - Enable a profile")
        print("  manage-agents.py disable <profile>   - Disable a profile")
        print("\nProfiles:")
        for name in profiles['profiles'].keys():
            print(f"  - {name}")
        return

    command = sys.argv[1].lower()

    if command == "status":
        show_status(profiles)

    elif command == "list":
        list_profiles(profiles)

    elif command == "reset":
        reset_to_defaults(profiles)
        show_status(profiles)

    elif command == "enable":
        if len(sys.argv) < 3:
            print("❌ Usage: manage-agents.py enable <profile>")
            return
        enable_profile(sys.argv[2], profiles)

    elif command == "disable":
        if len(sys.argv) < 3:
            print("❌ Usage: manage-agents.py disable <profile>")
            return
        disable_profile(sys.argv[2], profiles)

    else:
        print(f"❌ Unknown command: {command}")


if __name__ == "__main__":
    main()
