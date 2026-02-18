#!/usr/bin/env python3
"""
Add the UTM MCP server to the Claude Desktop configuration.

Reads the existing claude_desktop_config.json, adds the utm entry
under mcpServers (preserving existing servers), and writes it back.

Usage:
    python add_to_claude_desktop.py /path/to/utm_mcp

If no path is given, defaults to the directory containing this script.
"""

import json
import os
import sys

CONFIG_PATH = os.path.expanduser(
    "~/Library/Application Support/Claude/claude_desktop_config.json"
)

SERVER_KEY = "utm"


def main() -> None:
    """Add the UTM MCP server config entry."""
    # Determine the utm_mcp source directory
    if len(sys.argv) > 1:
        source_dir = os.path.abspath(sys.argv[1])
    else:
        source_dir = os.path.dirname(os.path.abspath(__file__))

    venv_python = os.path.join(source_dir, ".venv", "bin", "python")
    mcp_script = os.path.join(source_dir, "utm_mcp.py")

    # Validate paths
    if not os.path.isfile(mcp_script):
        print(f"Error: utm_mcp.py not found at {mcp_script}")
        sys.exit(1)
    if not os.path.isfile(venv_python):
        print(f"Error: .venv/bin/python not found at {venv_python}")
        print("Run: python -m venv .venv && .venv/bin/pip install -r requirements.txt")
        sys.exit(1)

    server_entry = {
        "command": venv_python,
        "args": [mcp_script],
    }

    # Load existing config
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
        print(f"Loaded existing config from {CONFIG_PATH}")
    else:
        config = {}
        print(f"No existing config found, creating new one at {CONFIG_PATH}")

    # Ensure mcpServers key exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}

    # Check if already configured
    if SERVER_KEY in config["mcpServers"]:
        print(f"'{SERVER_KEY}' is already in mcpServers. Overwriting.")

    # Add the UTM entry
    config["mcpServers"][SERVER_KEY] = server_entry

    # Write back
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    print(f"Added '{SERVER_KEY}' MCP server to {CONFIG_PATH}")
    print(f"  command: {venv_python}")
    print(f"  args:    [{mcp_script}]")
    print("Restart Claude Desktop to pick up the new server.")


if __name__ == "__main__":
    main()
