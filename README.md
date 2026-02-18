# UTM MCP Server

An MCP (Model Context Protocol) server that provides tools for managing [UTM](https://mac.getutm.app/) virtual machines via the `utmctl` CLI.

## Prerequisites

- macOS with [UTM](https://mac.getutm.app/) installed at `/Applications/UTM.app`
- Python 3.10+
- UTM must be running in the current user session (`utmctl` uses Apple Events)

## Setup

```bash
git clone https://github.com/michaelbarry/utm_mcp.git
cd utm_mcp
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
# Uses the current directory by default
python add_to_claude_desktop.py

# Or specify the path to your utm_mcp checkout
python add_to_claude_desktop.py /path/to/utm_mcp
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
| `utm_clone_vm` | Clone an existing VM (with disk space checks and warnings) |
| `utm_delete_vm` | Permanently delete a VM (irreversible) |
| `utm_get_ip_address` | List IP addresses on the guest |

### Guest Operations

Require the QEMU/SPICE guest agent running inside the VM.

| Tool | Description |
|------|-------------|
| `utm_exec_command` | Execute a command inside the guest |
| `utm_exec_script` | Push and execute a multi-line script on the guest |
| `utm_file_pull` | Fetch a file from the guest |
| `utm_file_push` | Upload text content to a file on the guest |

### USB

| Tool | Description |
|------|-------------|
| `utm_list_usb` | List connected USB devices |
| `utm_connect_usb` | Connect a USB device to a VM |
| `utm_disconnect_usb` | Disconnect a USB device from a VM |

## Storage Notes

`utm_clone_vm` checks available disk space before cloning and warns if:

- UTM storage is on the local disk rather than external storage
- Free space would drop below 50 GB after the clone

UTM can be configured to store VMs on an external volume via UTM preferences. This is recommended for machines with limited internal storage.

## Limitations

- `utmctl` requires an active GUI session (Apple Events). It does not work over SSH.
- Guest operations require the QEMU/SPICE guest agent installed and running inside the VM.
- Clone operations copy the entire VM disk image and can take significant time and space.

## License

MIT
