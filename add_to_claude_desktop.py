#!/usr/bin/env python3
"""
Add the UTM MCP server to the Claude Desktop configuration.

Reads the existing claude_desktop_config.json, adds the utm entry
under mcpServers (preserving existing servers), and writes it back.
"""

import json
import os

CONFIG_PATH = os.path.expanduser(
    "~/Library/Application Support/Claude/claude_desktop_config.json"
)

UTM_SERVER_ENTRY = {
    "command": "/Users/mike/Projects/utm_mcp/.venv/bin/python",
    "args": ["/Users/mike/Projects/utm_mcp/utm_mcp.py"],
}

SERVER_KEY = "utm"


def main() -> None:
    """Add the UTM MCP server config entry."""
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
    config["mcpServers"][SERVER_KEY] = UTM_SERVER_ENTRY

    # Write back
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    print(f"Added '{SERVER_KEY}' MCP server to {CONFIG_PATH}")
    print("Restart Claude Desktop to pick up the new server.")


if __name__ == "__main__":
    main()
