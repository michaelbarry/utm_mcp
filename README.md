# UTM MCP Server

**Talk to your virtual machines.** Start, stop, inspect, and run commands inside your [UTM](https://mac.getutm.app/) VMs through natural conversation with an AI assistant.

This MCP server connects Claude (or any MCP-compatible client) to UTM's `utmctl` CLI, letting you manage your entire VM fleet conversationally. Instead of memorizing CLI flags or switching between terminal windows, just ask: "start my Ubuntu server," "what's the IP of my dev box," or "run the migration script on staging."

## What Can You Do?

- **Manage VM lifecycle** -- start, stop, suspend, clone, and delete VMs by name
- **Run commands on guests** -- execute shell commands and multi-line scripts inside running VMs
- **Transfer files** -- push and pull files between your host and guest filesystems
- **Query VM state** -- check status, get IP addresses, list all VMs
- **USB passthrough** -- connect and disconnect USB devices to VMs

## Prerequisites

- macOS with [UTM](https://mac.getutm.app/) installed at `/Applications/UTM.app`
- Python 3.10+

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
python utm_mcp.py
```

The server uses stdio transport by default, suitable for use with Claude Code and other MCP clients.

## Claude Desktop Configuration

Run the helper script to automatically add the server to your Claude Desktop config:

```bash
python add_to_claude_desktop.py
```

Or manually add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "utm": {
      "command": "/path/to/utm_mcp/.venv/bin/python",
      "args": ["/path/to/utm_mcp/utm_mcp.py"]
    }
  }
}
```

## Tools

### VM Lifecycle

| Tool | Description |
|------|-------------|
| `utm_list_vms` | List all registered virtual machines |
| `utm_get_status` | Query the status of a VM |
| `utm_start_vm` | Start or resume a VM (supports disposable and recovery mode) |
| `utm_suspend_vm` | Suspend a running VM to memory (optionally save state to disk) |
| `utm_stop_vm` | Shut down a VM (force, kill, or graceful request) |
| `utm_clone_vm` | Clone an existing VM |
| `utm_delete_vm` | Permanently delete a VM (irreversible) |
| `utm_get_ip_address` | List IP addresses on the guest |

### Guest Operations

Require the QEMU/SPICE guest agent running inside the VM.

| Tool | Description |
|------|-------------|
| `utm_exec_command` | Execute a command inside the guest |
| `utm_file_pull` | Fetch a file from the guest |
| `utm_file_push` | Upload text content to a file on the guest |

### USB

| Tool | Description |
|------|-------------|
| `utm_list_usb` | List connected USB devices |
| `utm_connect_usb` | Connect a USB device to a VM |
| `utm_disconnect_usb` | Disconnect a USB device from a VM |

## License

MIT
