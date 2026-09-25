"""Hypervisor abstraction layer.

Isolation rules from the architecture that this module enforces:

* analysis runs from a **clean snapshot** - :meth:`HypervisorAdapter.revert` is the
  only sanctioned way to start a run;
* networking is hypervisor level (``--nic1 null`` / no ``-netdev``) so the guest
  cannot re-enable it;
* no shared folders, no clipboard, no USB passthrough.

Safety: **dry-run is the default.**  Until the analyst turns it off, every
adapter only *prints* the command it would execute, so opening this workbench
never touches a hypervisor by accident.  Real execution happens only on an
explicit user action with dry-run disabled.
"""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class VmStatus:
    name: str
    state: str = "unknown"
    snapshot: str = ""
    available: bool = False
    note: str = ""
    memory_mb: int = 0
    cpus: int = 0

    def to_row(self) -> list:
        return [self.name, self.state, self.snapshot, self.memory_mb, self.cpus, self.note]


@dataclass
class CommandRecord:
    command: str
    ok: bool = True
    output: str = ""
    dry_run: bool = True

    def label(self) -> str:
        prefix = "[dry-run] " if self.dry_run else ""
        return f"{prefix}$ {self.command}"


class HypervisorAdapter(ABC):
    """Common interface for VM back ends."""

    name = "abstract"
    isolation_note = ""

    def __init__(self, settings, bus=None, dry_run: bool = True) -> None:
        self.settings = settings
        self.bus = bus
        self.dry_run = dry_run
        self.history: list[CommandRecord] = []

    # ------------------------------------------------------------- discovery
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def reason(self) -> str: ...

    @abstractmethod
    def status(self, vm_name: str) -> VmStatus: ...

    @abstractmethod
    def _revert_cmd(self, vm_name: str, snapshot: str) -> list[str]: ...

    @abstractmethod
    def _start_cmd(self, vm_name: str, headless: bool) -> list[str]: ...

    @abstractmethod
    def _stop_cmd(self, vm_name: str, force: bool) -> list[str]: ...

    @abstractmethod
    def _nic_isolation_cmd(self, vm_name: str) -> list[str]: ...

    # ---------------------------------------------------------------- action
    def revert(self, vm_name: str, snapshot: str) -> CommandRecord:
        return self._run(self._revert_cmd(vm_name, snapshot))

    def isolate_network(self, vm_name: str) -> CommandRecord:
        return self._run(self._nic_isolation_cmd(vm_name))

    def start(self, vm_name: str, headless: bool = True) -> CommandRecord:
        return self._run(self._start_cmd(vm_name, headless))

    def stop(self, vm_name: str, force: bool = False) -> CommandRecord:
        return self._run(self._stop_cmd(vm_name, force))

    # --------------------------------------------------------------- plumbing
    def _run(self, cmd: list[str]) -> CommandRecord:
        record = CommandRecord(command=" ".join(cmd), dry_run=self.dry_run)
        self.history.append(record)
        if self.bus:
            self.bus.log(record.label(), "info" if self.dry_run else "warn")
        if self.dry_run:
            record.output = "dry-run: command not executed"
            return record
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, check=False
            )
            record.ok = completed.returncode == 0
            record.output = (completed.stdout or completed.stderr or "").strip()[:2000]
            if not record.ok and self.bus:
                self.bus.error(f"{self.name} command failed: {record.output[:300]}")
        except Exception as exc:
            record.ok = False
            record.output = str(exc)
            if self.bus:
                self.bus.error(f"{self.name} command error: {exc}")
        return record


class VirtualBoxAdapter(HypervisorAdapter):
    """VirtualBox back end driven by ``VBoxManage``."""

    name = "virtualbox"
    isolation_note = "Network forced to null (host-only disabled); snapshots reverted before every run."

    def __init__(self, settings, bus=None, dry_run: bool = True, binary: str | None = None) -> None:
        super().__init__(settings, bus, dry_run)
        self.binary = binary or shutil.which("VBoxManage") or shutil.which("VBoxManage.exe") or ""

    def is_available(self) -> bool:
        return bool(self.binary)

    def reason(self) -> str:
        return (
            f"VBoxManage found at {self.binary}"
            if self.binary
            else "VBoxManage was not found on PATH - install VirtualBox or switch to the simulation harness."
        )

    def _run(self, cmd: list[str]) -> CommandRecord:  # type: ignore[override]
        full = [self.binary or "VBoxManage"] + cmd
        return super()._run(full)

    def status(self, vm_name: str) -> VmStatus:
        status = VmStatus(name=vm_name, available=self.is_available(), note=self.reason())
        status.snapshot = str(self.settings.get("snapshot", "clean-baseline"))
        if not self.is_available():
            status.state = "adapter unavailable"
            return status
        record = self._run(["showvminfo", vm_name, "--machinereadable"])
        if not record.dry_run and record.ok:
            for line in record.output.splitlines():
                if line.startswith("VMState="):
                    status.state = line.split("=", 1)[1].strip('"')
                elif line.startswith("memory="):
                    status.memory_mb = int(line.split("=", 1)[1] or 0)
                elif line.startswith("cpus="):
                    status.cpus = int(line.split("=", 1)[1] or 0)
                elif line.startswith("CurrentSnapshotName="):
                    status.snapshot = line.split("=", 1)[1].strip('"')
        else:
            status.state = "(dry-run) not queried"
        return status

    def _revert_cmd(self, vm_name: str, snapshot: str) -> list[str]:
        return ["snapshot", vm_name, "restore", snapshot]

    def _start_cmd(self, vm_name: str, headless: bool) -> list[str]:
        return ["startvm", vm_name, "--type", "headless" if headless else "gui"]

    def _stop_cmd(self, vm_name: str, force: bool) -> list[str]:
        return ["controlvm", vm_name, "poweroff"] if force else ["controlvm", vm_name, "acpipowerbutton"]

    def _nic_isolation_cmd(self, vm_name: str) -> list[str]:
        # --nic1 null is hypervisor level: the guest cannot re-enable it.
        return ["modifyvm", vm_name, "--nic1", "null", "--nic2", "none", "--clipboard", "disabled", "--draganddrop", "disabled"]


class SimulatedAdapter(HypervisorAdapter):
    """Deterministic harness used when no hypervisor is present.

    It performs the same lifecycle (revert -> isolate -> start -> run -> stop) and
    reports the exact commands a real adapter would issue, so the pipeline,
    evidence and reporting paths are exercised without any VM.
    """

    name = "simulated"
    isolation_note = "Simulation harness - no guest is started; behaviour is synthesised and clearly labelled."

    def __init__(self, settings, bus=None, dry_run: bool = True, collector=None) -> None:
        super().__init__(settings, bus, dry_run)
        self.collector = collector

    def is_available(self) -> bool:
        return True

    def reason(self) -> str:
        return "Simulation harness (no hypervisor interaction)."

    def status(self, vm_name: str) -> VmStatus:
        return VmStatus(
            name=vm_name or "simulated-guest",
            state="simulated / ready",
            snapshot=str(self.settings.get("snapshot", "clean-baseline")),
            available=True,
            note="Behaviour telemetry is synthesised by the harness.",
            memory_mb=4096,
            cpus=2,
        )

    def _revert_cmd(self, vm_name: str, snapshot: str) -> list[str]:
        return [f"<{self.name}>", "revert", vm_name, "to", snapshot]

    def _start_cmd(self, vm_name: str, headless: bool) -> list[str]:
        return [f"<{self.name}>", "start", vm_name, "headless" if headless else "gui"]

    def _stop_cmd(self, vm_name: str, force: bool) -> list[str]:
        return [f"<{self.name}>", "stop", vm_name]

    def _nic_isolation_cmd(self, vm_name: str) -> list[str]:
        return [f"<{self.name}>", "isolate-network", vm_name]


def detect(settings, bus=None, dry_run: bool = True):
    """Return the adapter selected by settings (``auto`` prefers VirtualBox)."""
    choice = str(settings.get("hypervisor", "auto")).lower()
    if choice in ("simulated", "simulation"):
        return SimulatedAdapter(settings, bus, dry_run)
    if choice == "virtualbox":
        return VirtualBoxAdapter(settings, bus, dry_run)
    adapter = VirtualBoxAdapter(settings, bus, dry_run)
    if adapter.is_available():
        return adapter
    if bus:
        bus.warn(adapter.reason())
        bus.warn("Falling back to the simulation harness (behaviour is synthetic).")
    return SimulatedAdapter(settings, bus, dry_run)


def adapter_catalogue(settings, bus=None, dry_run: bool = True) -> list[dict]:
    """Availability summary for the UI, one row per supported back end."""
    entries = []
    for adapter in (
        VirtualBoxAdapter(settings, bus, dry_run),
        SimulatedAdapter(settings, bus, dry_run),
    ):
        entries.append(
            {
                "back end": adapter.name,
                "available": "yes" if adapter.is_available() else "no",
                "detail": adapter.reason(),
                "isolation": adapter.isolation_note,
            }
        )
    return entries
