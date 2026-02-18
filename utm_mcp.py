#!/usr/bin/env python3
"""
MCP Server for UTM Virtual Machine Management.

Provides tools to manage UTM virtual machines on macOS via the utmctl CLI.

The only host requirement is UTM.app installed at the default location.

Tools are grouped into three categories:
- VM lifecycle (list/start/stop/suspend/clone/delete) — always available.
- Guest operations (exec/script/file push/pull) — require the QEMU guest
  agent to be running *inside* the VM. The agent runs as root.
- USB passthrough (list/connect/disconnect) — always available.
"""

import asyncio
import logging
import os
import shutil
from enum import Enum
from pathlib import Path
from typing import Optional, List

from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UTMCTL_PATH = "/Applications/UTM.app/Contents/MacOS/utmctl"

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


class ExecScriptInput(BaseModel):
    """Input for pushing and executing a multi-line script on a guest VM."""
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(
        ...,
        description="UUID or complete name of the virtual machine",
        min_length=1,
    )
    script: str = Field(
        ...,
        description="Script content to execute (bash by default)",
    )
    interpreter: str = Field(
        default="/bin/bash",
        description="Interpreter to run the script (e.g. '/bin/bash', '/usr/bin/python3')",
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
# "file" and "usb" subcommands do NOT accept --hide.
# "start" supports --hide but it causes ~7s delays and OSStatus -10004
# errors on some UTM versions (Apple Events timeout), so we skip it.
# Minimum free space (bytes) on the local disk before warning on clone.
# Default 50 GB. Clones land on whatever volume UTM uses for storage.
_LOW_DISK_THRESHOLD_BYTES = 50 * 1024 * 1024 * 1024

# Known UTM VM storage locations (checked in order).
_UTM_STORAGE_CANDIDATES = [
    Path.home() / "Library" / "Containers" / "com.utmapp.UTM" / "Data" / "Documents",
    Path.home() / "Library" / "Group Containers" / "WDNLXAD4W8.com.utmapp.UTM",
]


def _get_utm_storage_path() -> Optional[Path]:
    """Return the UTM storage directory.

    First checks for .utm bundles in known locations, then falls back to
    scanning /Volumes for .utm bundles (UTM can be configured to store
    VMs on external drives).
    """
    # Check default container locations
    for candidate in _UTM_STORAGE_CANDIDATES:
        if candidate.is_dir():
            # Only return if it actually contains .utm bundles
            if any(p.suffix == ".utm" for p in candidate.iterdir()):
                return candidate

    # Scan /Volumes for .utm bundles (external storage)
    volumes = Path("/Volumes")
    if volumes.is_dir():
        for vol in volumes.iterdir():
            if not vol.is_dir():
                continue
            try:
                for entry in vol.iterdir():
                    if entry.suffix == ".utm" and entry.is_dir():
                        return vol
            except PermissionError:
                continue

    # Last resort: check default candidates even without .utm bundles
    for candidate in _UTM_STORAGE_CANDIDATES:
        if candidate.is_dir():
            return candidate

    return None


def _get_disk_free(path: str) -> int:
    """Return free bytes on the filesystem containing *path*."""
    return shutil.disk_usage(path).free


def _format_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


async def _estimate_vm_size(identifier: str) -> Optional[int]:
    """Estimate the disk size of a VM by finding its .utm bundle.

    Returns size in bytes, or None if the bundle can't be found.
    """
    storage = _get_utm_storage_path()
    if not storage:
        return None

    # VM bundles are directories ending in .utm
    for entry in storage.iterdir():
        if entry.suffix == ".utm" and entry.is_dir():
            # Match by name (the directory name minus .utm is often the VM name)
            bundle_name = entry.stem
            if bundle_name == identifier or identifier in bundle_name:
                total = sum(
                    f.stat().st_size
                    for f in entry.rglob("*")
                    if f.is_file()
                )
                return total
    return None


_HIDE_SUPPORTED_SUBCOMMANDS = {
    "list", "stop", "suspend", "delete", "clone",
    "status", "ip-address", "exec",
}


# Default timeout in seconds for utmctl commands. Start/stop may take
# longer than simple queries, but anything beyond 30s is likely hung.
_UTMCTL_TIMEOUT = 30


async def _run_utmctl(
    *args: str,
    stdin_data: Optional[str] = None,
    timeout: Optional[float] = None,
) -> str:
    """Execute a utmctl command and return stdout.

    Automatically passes --hide for subcommands that support it to
    prevent the UTM window from stealing focus.

    Times out after _UTMCTL_TIMEOUT seconds (default 30) to prevent
    indefinite hangs when UTM.app is unresponsive or not running.
    """
    if timeout is None:
        timeout = _UTMCTL_TIMEOUT

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
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=stdin_bytes),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        # Kill the hung process
        try:
            process.kill()
            await process.wait()
        except ProcessLookupError:
            pass
        raise RuntimeError(
            f"utmctl timed out after {timeout}s running: {' '.join(cmd)}. "
            f"Is UTM.app running in the current user session?"
        )

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
    if isinstance(e, asyncio.TimeoutError):
        return "Error: utmctl timed out. Is UTM.app running in the current user session?"
    return f"Error: {type(e).__name__}: {e}"


# ===========================================================================
# Tools: VM Lifecycle
# ===========================================================================


@mcp.tool(
    name="utm_list_vms",
    annotations={
        "title": "List Virtual Machines",
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
        "idempotentHint": False,
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
        "destructiveHint": False,
        "idempotentHint": False,
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
        args = ["stop", params.identifier]
        if params.mode == StopMode.KILL:
            args.append("--kill")
        elif params.mode == StopMode.REQUEST:
            args.append("--request")
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
    Checks available disk space before cloning and warns if free space
    would drop below the safety threshold (50 GB).

    Args:
        params: Source VM identifier and optional clone name.

    Returns:
        str: Confirmation message with storage details, or error.
    """
    try:
        warnings = []

        # Estimate source VM size
        vm_size = await _estimate_vm_size(params.identifier)

        # Check where clones will land and available space
        storage_path = _get_utm_storage_path()
        if storage_path:
            free_before = _get_disk_free(str(storage_path))

            # Check if storage is on a small local volume (not external)
            mount_point = str(storage_path)
            is_external = mount_point.startswith("/Volumes/")
            if not is_external:
                warnings.append(
                    "WARNING: UTM storage is on the local disk, not external storage. "
                    "Clones will consume local disk space. Consider moving UTM storage "
                    "to an external volume."
                )

            if vm_size and free_before - vm_size < _LOW_DISK_THRESHOLD_BYTES:
                warnings.append(
                    f"WARNING: Low disk space after clone. "
                    f"VM size: ~{_format_bytes(vm_size)}, "
                    f"Free now: {_format_bytes(free_before)}, "
                    f"Free after: ~{_format_bytes(free_before - vm_size)}. "
                    f"Threshold: {_format_bytes(_LOW_DISK_THRESHOLD_BYTES)}."
                )

        # Perform the clone
        args = ["clone", params.identifier]
        if params.name:
            args.extend(["--name", params.name])
        output = await _run_utmctl(*args)

        # Build result with storage info
        result_parts = []
        if warnings:
            result_parts.extend(warnings)
            result_parts.append("")

        result_parts.append(output or f"VM '{params.identifier}' cloned successfully.")

        if storage_path:
            free_after = _get_disk_free(str(storage_path))
            result_parts.append(
                f"Storage: {storage_path} "
                f"(free: {_format_bytes(free_after)})"
            )
        if vm_size:
            result_parts.append(f"Estimated clone size: ~{_format_bytes(vm_size)}")

        return "\n".join(result_parts)
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


# ===========================================================================
# Tools: Guest Operations
# ===========================================================================


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

    Runs as root via the QEMU guest agent. Best for simple, single-line
    commands. For multi-line scripts or complex logic, use utm_exec_script
    instead.

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
    name="utm_exec_script",
    annotations={
        "title": "Execute Script on Guest",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def utm_exec_script(params: ExecScriptInput) -> str:
    """Push a script to a guest VM and execute it in one step.

    Writes the script to a temp file on the guest, makes it executable,
    runs it with the specified interpreter, captures combined stdout/stderr,
    and cleans up the temp file. Runs as root.

    Use this instead of utm_exec_command when you need multi-line logic,
    pipelines, or complex shell constructs. Saves multiple round-trips
    compared to file_push + exec_command.

    Args:
        params: VM identifier, script content, and optional interpreter.

    Returns:
        str: Script output (stdout + stderr) or error message.
    """
    try:
        import uuid

        script_path = f"/tmp/_mcp_script_{uuid.uuid4().hex[:8]}"

        # Push script content to guest
        await _run_utmctl(
            "file", "push", params.identifier, script_path,
            stdin_data=params.script,
        )

        # Make executable, run, capture output, clean up
        exec_args = [
            "exec", params.identifier, "--cmd",
            "bash", "-c",
            f"chmod +x {script_path} && "
            f"{params.interpreter} {script_path} 2>&1; "
            f"EXIT=$?; rm -f {script_path}; exit $EXIT",
        ]
        output = await _run_utmctl(*exec_args)
        return output if output else "(script produced no output)"
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


# ===========================================================================
# Tools: USB
# ===========================================================================


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

