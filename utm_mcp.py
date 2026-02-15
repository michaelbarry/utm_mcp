#!/usr/bin/env python3
"""
MCP Server for UTM Virtual Machine Management.

Provides tools to manage UTM virtual machines via the utmctl CLI,
including lifecycle management, guest operations, and USB device handling.
"""

import asyncio
import logging
from enum import Enum
from typing import Optional, List

from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UTMCTL_PATH = "/Applications/UTM.app/Contents/MacOS/utmctl"

# Logging goes to stderr so it does not interfere with stdio transport
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("utm_mcp")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("utm_mcp")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StopMode(str, Enum):
    """Method used to stop a virtual machine."""
    FORCE = "force"
    KILL = "kill"
    REQUEST = "request"


# ---------------------------------------------------------------------------
# Pydantic Input Models
# ---------------------------------------------------------------------------


class VmIdentifierInput(BaseModel):
    """Input requiring a VM identifier (UUID or full name)."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )


class StartVmInput(BaseModel):
    """Input for starting a virtual machine."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    disposable: bool = Field(
        default=False,
        description="Run as a snapshot without saving changes to disk",
    )
    recovery: bool = Field(
        default=False,
        description="Boot the VM in recovery mode",
    )


class SuspendVmInput(BaseModel):
    """Input for suspending a virtual machine."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    save_state: bool = Field(
        default=False,
        description="Save the VM state to disk after suspending",
    )


class StopVmInput(BaseModel):
    """Input for stopping a virtual machine."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    mode: StopMode = Field(
        default=StopMode.FORCE,
        description=(
            "Stop method: 'force' sends power-off event (default), "
            "'kill' force-kills the VM process, "
            "'request' asks the guest OS to shut down gracefully"
        ),
    )


class CloneVmInput(BaseModel):
    """Input for cloning a virtual machine."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine to clone",
        min_length=1,
    )
    name: Optional[str] = Field(
        default=None,
        description="Name for the cloned virtual machine",
    )


class ExecInput(BaseModel):
    """Input for executing a command on a guest VM."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    command: List[str] = Field(
        ...,
        description="Command and arguments to execute on the guest (e.g. ['ls', '-la', '/tmp'])",
        min_length=1,
    )
    env: Optional[List[str]] = Field(
        default=None,
        description="Environment variables in NAME=VALUE format (e.g. ['PATH=/usr/bin', 'HOME=/root'])",
    )


class FilePullInput(BaseModel):
    """Input for pulling a file from a guest VM."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    path: str = Field(
        ...,
        description="Absolute path of the file on the guest to retrieve",
        min_length=1,
    )


class FilePushInput(BaseModel):
    """Input for pushing content to a file on a guest VM."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    path: str = Field(
        ...,
        description="Destination path on the guest",
        min_length=1,
    )
    content: str = Field(
        ...,
        description="Text content to write to the file on the guest",
    )


class UsbConnectInput(BaseModel):
    """Input for connecting a USB device to a VM."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    device: str = Field(
        ...,
        description="USB device identifier as VID:PID pair (e.g. 'DEAD:BEEF') or location number (e.g. '4')",
        min_length=1,
    )


class UsbDisconnectInput(BaseModel):
    """Input for disconnecting a USB device."""
    model_config = ConfigDict(str_strip_whitespace=True)

    device: str = Field(
        ...,
        description="USB device identifier as VID:PID pair (e.g. 'DEAD:BEEF') or location number (e.g. '4')",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Shared Helpers
# ---------------------------------------------------------------------------


# Subcommands that accept the --hide flag (EnvironmentOptions in utmctl).
# The "file" and "usb" subcommands have their own sub-parsers and do NOT
# accept --hide, so we must omit it for those.
_HIDE_SUPPORTED_SUBCOMMANDS = {
    "list", "start", "stop", "suspend", "delete", "clone",
    "status", "ip-address", "exec",
}


async def _run_utmctl(*args: str, stdin_data: Optional[str] = None) -> str:
    """
    Execute a utmctl command and return its combined stdout/stderr output.

    Passes --hide for subcommands that support it to prevent the UTM
    window from appearing.

    Args:
        *args: Arguments to pass to utmctl.
        stdin_data: Optional string to pipe into stdin.

    Returns:
        The command's stdout output as a string.

    Raises:
        RuntimeError: If the command exits with a non-zero status.
    """
    arg_list = list(args)
    if arg_list:
        subcommand = arg_list[0]
        if subcommand in _HIDE_SUPPORTED_SUBCOMMANDS:
            cmd = [UTMCTL_PATH, subcommand, "--hide"] + arg_list[1:]
        else:
            cmd = [UTMCTL_PATH] + arg_list
    else:
        cmd = [UTMCTL_PATH]
    logger.info("Running: %s", " ".join(cmd))

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
    )

    stdin_bytes = stdin_data.encode("utf-8") if stdin_data is not None else None
    stdout, stderr = await process.communicate(input=stdin_bytes)

    stdout_text = stdout.decode("utf-8", errors="replace").strip()
    stderr_text = stderr.decode("utf-8", errors="replace").strip()

    if process.returncode != 0:
        error_detail = stderr_text or stdout_text or "unknown error"
        logger.error("utmctl failed (exit %d): %s", process.returncode, error_detail)
        raise RuntimeError(f"utmctl exited with code {process.returncode}: {error_detail}")

    return stdout_text


def _format_error(e: Exception) -> str:
    """Format an exception into an actionable error message."""
    if isinstance(e, RuntimeError):
        return f"Error: {e}"
    if isinstance(e, FileNotFoundError):
        return f"Error: utmctl not found at {UTMCTL_PATH}. Is UTM installed?"
    return f"Error: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Tools: VM Lifecycle
# ---------------------------------------------------------------------------


@mcp.tool(
    name="utm_list_vms",
    annotations={
        "title": "List UTM Virtual Machines",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_list_vms() -> str:
    """List all registered UTM virtual machines.

    Returns each VM's name, status, and UUID.

    Returns:
        str: One VM per line in the format printed by utmctl, or an error message.
    """
    try:
        output = await _run_utmctl("list")
        if not output:
            return "No virtual machines found."
        return output
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_get_status",
    annotations={
        "title": "Get VM Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_get_status(params: VmIdentifierInput) -> str:
    """Query the current status of a UTM virtual machine.

    Args:
        params: Contains the VM identifier (UUID or name).

    Returns:
        str: The VM status (e.g. started, stopped, suspended) or an error message.
    """
    try:
        return await _run_utmctl("status", params.identifier)
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_start_vm",
    annotations={
        "title": "Start Virtual Machine",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def utm_start_vm(params: StartVmInput) -> str:
    """Start a UTM virtual machine or resume a suspended one.

    Supports disposable mode (snapshot, no disk changes) and recovery mode boot.

    Args:
        params: VM identifier plus optional disposable/recovery flags.

    Returns:
        str: Confirmation message or error.
    """
    try:
        args = ["start", params.identifier]
        if params.disposable:
            args.append("--disposable")
        if params.recovery:
            args.append("--recovery")
        output = await _run_utmctl(*args)
        return output or f"VM '{params.identifier}' start command issued."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_suspend_vm",
    annotations={
        "title": "Suspend Virtual Machine",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_suspend_vm(params: SuspendVmInput) -> str:
    """Suspend a running UTM virtual machine to memory.

    Optionally saves the VM state to disk for later resumption.

    Args:
        params: VM identifier and optional save_state flag.

    Returns:
        str: Confirmation message or error.
    """
    try:
        args = ["suspend", params.identifier]
        if params.save_state:
            args.append("--save-state")
        output = await _run_utmctl(*args)
        return output or f"VM '{params.identifier}' suspended."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_stop_vm",
    annotations={
        "title": "Stop Virtual Machine",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_stop_vm(params: StopVmInput) -> str:
    """Shut down a running UTM virtual machine.

    Supports three stop modes:
    - force: Send a power-off event (default)
    - kill: Force-kill the VM process
    - request: Ask the guest OS to shut down gracefully

    Args:
        params: VM identifier and stop mode.

    Returns:
        str: Confirmation message or error.
    """
    try:
        args = ["stop", params.identifier, f"--{params.mode.value}"]
        output = await _run_utmctl(*args)
        return output or f"VM '{params.identifier}' stop ({params.mode.value}) command issued."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_clone_vm",
    annotations={
        "title": "Clone Virtual Machine",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def utm_clone_vm(params: CloneVmInput) -> str:
    """Clone an existing UTM virtual machine.

    Creates a full copy of the VM. Optionally specify a name for the clone.

    Args:
        params: Source VM identifier and optional clone name.

    Returns:
        str: Confirmation message or error.
    """
    try:
        args = ["clone", params.identifier]
        if params.name:
            args.extend(["--name", params.name])
        output = await _run_utmctl(*args)
        return output or f"VM '{params.identifier}' cloned successfully."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_delete_vm",
    annotations={
        "title": "Delete Virtual Machine",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def utm_delete_vm(params: VmIdentifierInput) -> str:
    """Permanently delete a UTM virtual machine.

    WARNING: This is irreversible and there is no confirmation prompt.
    The VM and all its data will be removed.

    Args:
        params: VM identifier (UUID or name) to delete.

    Returns:
        str: Confirmation message or error.
    """
    try:
        output = await _run_utmctl("delete", params.identifier)
        return output or f"VM '{params.identifier}' deleted."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_get_ip_address",
    annotations={
        "title": "Get VM IP Addresses",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_get_ip_address(params: VmIdentifierInput) -> str:
    """List all IP addresses associated with a guest VM's network interfaces.

    IPv4 addresses are listed before IPv6 addresses. Requires the guest agent
    to be running inside the VM.

    Args:
        params: VM identifier (UUID or name).

    Returns:
        str: IP addresses (one per line) or error message.
    """
    try:
        output = await _run_utmctl("ip-address", params.identifier)
        if not output:
            return f"No IP addresses found for VM '{params.identifier}'. Is the guest agent running?"
        return output
    except Exception as e:
        return _format_error(e)


# ---------------------------------------------------------------------------
# Tools: Guest Operations
# ---------------------------------------------------------------------------


@mcp.tool(
    name="utm_exec_command",
    annotations={
        "title": "Execute Command on Guest",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def utm_exec_command(params: ExecInput) -> str:
    """Execute a command inside a guest virtual machine.

    Requires the QEMU/SPICE guest agent to be installed and running in the VM.
    Returns the command's exit code and output.

    Args:
        params: VM identifier, command list, and optional environment variables.

    Returns:
        str: Command output or error message.
    """
    try:
        args = ["exec", params.identifier]
        if params.env:
            for env_var in params.env:
                args.extend(["--env", env_var])
        args.append("--cmd")
        args.extend(params.command)
        output = await _run_utmctl(*args)
        return output if output else "(command produced no output)"
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_file_pull",
    annotations={
        "title": "Pull File from Guest",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_file_pull(params: FilePullInput) -> str:
    """Fetch a file from a guest VM.

    Retrieves the contents of a file from the guest filesystem. Requires
    the guest agent to be running.

    Args:
        params: VM identifier and guest file path.

    Returns:
        str: File contents or error message.
    """
    try:
        output = await _run_utmctl("file", "pull", params.identifier, params.path)
        return output if output else "(file is empty)"
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_file_push",
    annotations={
        "title": "Push File to Guest",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_file_push(params: FilePushInput) -> str:
    """Upload text content to a file on a guest VM.

    Writes the provided content to the specified path on the guest filesystem.
    Requires the guest agent to be running.

    Args:
        params: VM identifier, destination path, and file content.

    Returns:
        str: Confirmation message or error.
    """
    try:
        output = await _run_utmctl(
            "file", "push", params.identifier, params.path,
            stdin_data=params.content,
        )
        return output or f"Content written to '{params.path}' on VM '{params.identifier}'."
    except Exception as e:
        return _format_error(e)


# ---------------------------------------------------------------------------
# Tools: USB
# ---------------------------------------------------------------------------


@mcp.tool(
    name="utm_list_usb",
    annotations={
        "title": "List USB Devices",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_list_usb() -> str:
    """List all connected USB devices visible to UTM.

    Returns:
        str: USB device list or message if none found.
    """
    try:
        output = await _run_utmctl("usb", "list")
        if not output:
            return "No USB devices found."
        return output
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_connect_usb",
    annotations={
        "title": "Connect USB Device to VM",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_connect_usb(params: UsbConnectInput) -> str:
    """Connect a USB device to a running virtual machine.

    The device can be identified by VID:PID pair (e.g. 'DEAD:BEEF') or
    by location number (e.g. '4'). Use utm_list_usb to see available devices.

    Args:
        params: VM identifier and USB device identifier.

    Returns:
        str: Confirmation message or error.
    """
    try:
        output = await _run_utmctl("usb", "connect", params.identifier, params.device)
        return output or f"USB device '{params.device}' connected to VM '{params.identifier}'."
    except Exception as e:
        return _format_error(e)


@mcp.tool(
    name="utm_disconnect_usb",
    annotations={
        "title": "Disconnect USB Device",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def utm_disconnect_usb(params: UsbDisconnectInput) -> str:
    """Disconnect a USB device from its current virtual machine.

    The device can be identified by VID:PID pair or location number.

    Args:
        params: USB device identifier.

    Returns:
        str: Confirmation message or error.
    """
    try:
        output = await _run_utmctl("usb", "disconnect", params.device)
        return output or f"USB device '{params.device}' disconnected."
    except Exception as e:
        return _format_error(e)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()

