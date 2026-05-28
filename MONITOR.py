"""
Portable internet stability monitor and network diagnostics utility.

This application uses only Python standard library modules and native
operating system networking commands. It runs on Windows, Linux and macOS,
collects real-time connectivity metrics, detects anomalies and writes a
human-readable TXT report when the session ends.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_CYAN = "\033[36m"
ANSI_DIM = "\033[2m"
ANSI_CLEAR = "\033[2J\033[H"


DEFAULT_TARGETS = ("1.1.1.1", "8.8.8.8", "google.com")
DEFAULT_DNS_HOSTS = ("google.com", "cloudflare.com", "openai.com")


def now() -> datetime:
    """Return the current local datetime."""
    return datetime.now()


def fmt_dt(value: datetime) -> str:
    """Format a timestamp for terminal and report output."""
    return value.strftime("%Y-%m-%d %H:%M:%S")


def color(text: str, ansi: str, enabled: bool = True) -> str:
    """Wrap text in ANSI color codes when color output is enabled."""
    if not enabled:
        return text
    return f"{ansi}{text}{ANSI_RESET}"


def run_command(command: list[str], timeout: float) -> tuple[int, str]:
    """Run a native command safely and return exit code plus combined output."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            shell=False,
        )
        return completed.returncode, f"{completed.stdout}\n{completed.stderr}".strip()
    except subprocess.TimeoutExpired as exc:
        partial = ""
        if exc.stdout:
            partial += str(exc.stdout)
        if exc.stderr:
            partial += str(exc.stderr)
        return 124, partial.strip() or "command timed out"
    except FileNotFoundError:
        return 127, "command not found"
    except OSError as exc:
        return 1, str(exc)


@dataclass(slots=True)
class MonitorConfig:
    """Runtime configuration for the monitoring session."""

    targets: list[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    dns_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_DNS_HOSTS))
    interval_seconds: float = 5.0
    ping_timeout_seconds: float = 2.5
    command_timeout_seconds: float = 12.0
    traceroute_hop_timeout_seconds: float = 2.0
    traceroute_interval: int = 6
    max_hops: int = 20
    duration_seconds: float = 0.0
    report_dir: Path = field(default_factory=lambda: Path("reports"))
    no_color: bool = False
    no_dashboard: bool = False
    auto_export: bool = False

    high_latency_ms: float = 180.0
    severe_latency_ms: float = 350.0
    high_jitter_ms: float = 60.0
    packet_loss_warn_percent: float = 5.0
    packet_loss_bad_percent: float = 15.0
    degradation_window: int = 10


@dataclass(slots=True)
class PingResult:
    """Single ping probe result."""

    target: str
    timestamp: datetime
    success: bool
    latency_ms: float | None = None
    packet_loss_percent: float | None = None
    error: str | None = None
    raw_output: str = ""


@dataclass(slots=True)
class DNSResult:
    """DNS resolution result."""

    host: str
    timestamp: datetime
    success: bool
    elapsed_ms: float | None = None
    addresses: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class GatewayResult:
    """Gateway discovery and reachability result."""

    timestamp: datetime
    gateway: str | None
    reachable: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class TraceHop:
    """Traceroute hop analysis."""

    number: int
    host: str
    latencies_ms: list[float] = field(default_factory=list)
    timeout: bool = False

    @property
    def average_ms(self) -> float | None:
        if not self.latencies_ms:
            return None
        return statistics.fmean(self.latencies_ms)


@dataclass(slots=True)
class TraceResult:
    """Traceroute execution result."""

    target: str
    timestamp: datetime
    success: bool
    hops: list[TraceHop] = field(default_factory=list)
    route_changed: bool = False
    error: str | None = None
    raw_output: str = ""


@dataclass(slots=True)
class CycleResult:
    """Detailed diagnostics result for one monitoring cycle."""

    number: int
    timestamp: datetime
    ping_results: list[PingResult]
    dns_results: list[DNSResult]
    gateway_result: GatewayResult
    trace_result: TraceResult | None
    elapsed_seconds: float


@dataclass(slots=True)
class AnomalyEvent:
    """Timestamped anomaly or important session event."""

    timestamp: datetime
    severity: str
    category: str
    message: str


class SystemAdapter:
    """Cross-platform command builder and host network information collector."""

    def __init__(self) -> None:
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.is_macos = self.system == "darwin"
        self.is_linux = self.system == "linux"

    @property
    def name(self) -> str:
        if self.is_windows:
            return "Windows"
        if self.is_macos:
            return "macOS"
        if self.is_linux:
            return "Linux"
        return platform.system() or "Unknown"

    def command_exists(self, name: str) -> bool:
        """Return True when a native command is available in PATH."""
        return shutil.which(name) is not None

    def ping_command(self, host: str, timeout_seconds: float) -> list[str]:
        """Build a single-probe ping command for the current OS."""
        if self.is_windows:
            return ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), host]
        if self.is_macos:
            return ["ping", "-c", "1", "-W", str(int(timeout_seconds * 1000)), host]
        return ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), host]

    def traceroute_command(self, host: str, max_hops: int, timeout_seconds: float) -> list[str] | None:
        """Build a traceroute command using native utilities with fallbacks."""
        if self.is_windows:
            if self.command_exists("tracert"):
                return [
                    "tracert",
                    "-d",
                    "-h",
                    str(max_hops),
                    "-w",
                    str(int(timeout_seconds * 1000)),
                    host,
                ]
            if self.command_exists("pathping"):
                return ["pathping", "-n", "-h", str(max_hops), host]
            return None

        if self.command_exists("traceroute"):
            return [
                "traceroute",
                "-n",
                "-m",
                str(max_hops),
                "-w",
                str(max(1, int(timeout_seconds))),
                host,
            ]
        if self.is_linux and self.command_exists("tracepath"):
            return ["tracepath", "-n", "-m", str(max_hops), host]
        return None

    def dns_command(self, host: str) -> list[str] | None:
        """Return a native DNS diagnostic command when available."""
        if self.command_exists("nslookup"):
            return ["nslookup", host]
        if not self.is_windows and self.command_exists("dig"):
            return ["dig", host]
        return None

    def gateway_command_candidates(self) -> list[list[str]]:
        """Return native commands that may expose the default gateway."""
        if self.is_windows:
            return [["ipconfig"]]
        if self.is_linux:
            candidates = []
            if self.command_exists("ip"):
                candidates.append(["ip", "route"])
            if self.command_exists("route"):
                candidates.append(["route", "-n"])
            if self.command_exists("netstat"):
                candidates.append(["netstat", "-rn"])
            return candidates
        if self.is_macos:
            candidates = []
            if self.command_exists("route"):
                candidates.append(["route", "-n", "get", "default"])
            if self.command_exists("netstat"):
                candidates.append(["netstat", "-rn"])
            if self.command_exists("ifconfig"):
                candidates.append(["ifconfig"])
            return candidates
        return []

    def collect_dns_config(self) -> str:
        """Collect DNS server configuration using native OS information."""
        if self.is_windows:
            code, output = run_command(["ipconfig", "/all"], 8)
            return output if code == 0 else f"Unavailable: {output}"

        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.exists():
            try:
                return resolv_conf.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return f"Unavailable: {exc}"
        return "Unavailable: /etc/resolv.conf not found"

    def local_ip(self) -> str | None:
        """Best-effort local IP detection without sending payload data."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return None

    def public_ip(self) -> str | None:
        """Return public IP when it can be inferred without third-party libraries."""
        if self.command_exists("nslookup"):
            command = ["nslookup", "myip.opendns.com", "resolver1.opendns.com"]
        elif not self.is_windows and self.command_exists("dig"):
            command = ["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"]
        else:
            return None
        code, output = run_command(command, 5)
        if code != 0:
            return None
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
        valid_ips = []
        for value in ips:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not ip.is_private and not ip.is_loopback and not ip.is_reserved:
                valid_ips.append(value)
        return valid_ips[-1] if valid_ips else None

    def default_gateway(self) -> str | None:
        """Discover the default gateway from native command output."""
        for command in self.gateway_command_candidates():
            code, output = run_command(command, 8)
            if code != 0:
                continue
            gateway = self._parse_gateway(output)
            if gateway:
                return gateway
        return None

    def _parse_gateway(self, output: str) -> str | None:
        """Parse gateway IP from platform-specific routing output."""
        if self.is_windows:
            lines = output.splitlines()
            for index, line in enumerate(lines):
                if "Default Gateway" in line or "Gateway Padr" in line:
                    candidates = [line]
                    candidates.extend(lines[index + 1 : index + 3])
                    for candidate in candidates:
                        match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", candidate)
                        if match:
                            return match.group(0)

        for pattern in (
            r"default\s+via\s+((?:\d{1,3}\.){3}\d{1,3})",
            r"gateway:\s*((?:\d{1,3}\.){3}\d{1,3})",
            r"^0\.0\.0\.0\s+((?:\d{1,3}\.){3}\d{1,3})",
            r"^default\s+((?:\d{1,3}\.){3}\d{1,3})",
        ):
            match = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1)
        return None


class PingDiagnostics:
    """Execute and parse single-probe ping diagnostics."""

    TIME_PATTERN = re.compile(r"(?:time[=<]\s*|tempo[=<]\s*)(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)
    LOSS_PATTERN = re.compile(r"(\d+(?:[.,]\d+)?)\s*%.*(?:loss|perda)", re.IGNORECASE)

    def __init__(self, adapter: SystemAdapter, config: MonitorConfig) -> None:
        self.adapter = adapter
        self.config = config

    def probe(self, target: str) -> PingResult:
        """Ping a target once and parse latency/loss information."""
        command = self.adapter.ping_command(target, self.config.ping_timeout_seconds)
        code, output = run_command(command, self.config.ping_timeout_seconds + 2)
        latency = self._parse_latency(output)
        loss = self._parse_packet_loss(output)
        success = code == 0 and latency is not None
        if loss is None:
            loss = 0.0 if success else 100.0
        error = None if success else self._short_error(output)
        return PingResult(
            target=target,
            timestamp=now(),
            success=success,
            latency_ms=latency,
            packet_loss_percent=loss,
            error=error,
            raw_output=output,
        )

    def _parse_latency(self, output: str) -> float | None:
        match = self.TIME_PATTERN.search(output)
        if match:
            return float(match.group(1).replace(",", "."))
        return None

    def _parse_packet_loss(self, output: str) -> float | None:
        match = self.LOSS_PATTERN.search(output)
        if match:
            return float(match.group(1).replace(",", "."))
        if "100% loss" in output.lower() or "100% perda" in output.lower():
            return 100.0
        return None

    def _short_error(self, output: str) -> str:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return "no ping response"
        return lines[-1][:160]


class DNSDiagnostics:
    """Perform DNS resolution timing and optional native DNS command checks."""

    def __init__(self, adapter: SystemAdapter, config: MonitorConfig) -> None:
        self.adapter = adapter
        self.config = config

    def resolve(self, host: str) -> DNSResult:
        """Resolve a host with socket.getaddrinfo and record elapsed time."""
        started = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, None)
            elapsed = (time.perf_counter() - started) * 1000
            addresses = sorted({info[4][0] for info in infos})
            return DNSResult(host=host, timestamp=now(), success=True, elapsed_ms=elapsed, addresses=addresses)
        except OSError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            return DNSResult(host=host, timestamp=now(), success=False, elapsed_ms=elapsed, error=str(exc))

    def native_lookup(self, host: str) -> str:
        """Run nslookup/dig when available for report-level diagnostics."""
        command = self.adapter.dns_command(host)
        if not command:
            return "No native nslookup/dig command available."
        _, output = run_command(command, self.config.command_timeout_seconds)
        return output


class TraceDiagnostics:
    """Run and analyze traceroute/tracert/pathping output."""

    LATENCY_PATTERN = re.compile(r"(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, adapter: SystemAdapter, config: MonitorConfig) -> None:
        self.adapter = adapter
        self.config = config
        self.route_history: list[list[str]] = []
        self.route_change_count = 0

    def trace(self, target: str) -> TraceResult:
        """Execute a route trace and detect route instability."""
        command = self.adapter.traceroute_command(
            target,
            self.config.max_hops,
            self.config.traceroute_hop_timeout_seconds,
        )
        if command is None:
            return TraceResult(
                target=target,
                timestamp=now(),
                success=False,
                error="No native traceroute/tracert/pathping command available.",
            )

        timeout = self.config.command_timeout_seconds + (
            self.config.max_hops * self.config.traceroute_hop_timeout_seconds
        )
        code, output = run_command(command, timeout)
        hops = self._parse_hops(output)
        route_changed = self._detect_route_change(hops)
        success = bool(hops) and code not in (124, 127)
        error = None if success else output[:200] or "traceroute failed"
        return TraceResult(
            target=target,
            timestamp=now(),
            success=success,
            hops=hops,
            route_changed=route_changed,
            error=error,
            raw_output=output,
        )

    def _parse_hops(self, output: str) -> list[TraceHop]:
        hops: list[TraceHop] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if not match:
                continue
            number = int(match.group(1))
            body = match.group(2)
            latencies = [float(value.replace(",", ".")) for value in self.LATENCY_PATTERN.findall(body)]
            timeout = "*" in body and not latencies
            host = self._extract_hop_host(body)
            hops.append(TraceHop(number=number, host=host, latencies_ms=latencies, timeout=timeout))
        return hops

    def _extract_hop_host(self, body: str) -> str:
        ips = self.IP_PATTERN.findall(body)
        if ips:
            return ips[-1]
        tokens = [token for token in body.split() if token != "*" and not token.lower().endswith("ms")]
        for token in reversed(tokens):
            clean = token.strip("[]()")
            if clean and not re.fullmatch(r"\d+(?:[.,]\d+)?", clean):
                return clean
        return "*"

    def _detect_route_change(self, hops: list[TraceHop]) -> bool:
        route = [hop.host for hop in hops if hop.host != "*"]
        if not route:
            return False
        changed = False
        if self.route_history:
            previous = self.route_history[-1]
            compare_count = min(len(previous), len(route), 8)
            changed = compare_count > 0 and previous[:compare_count] != route[:compare_count]
        self.route_history.append(route)
        if len(self.route_history) > 20:
            self.route_history.pop(0)
        if changed:
            self.route_change_count += 1
        return changed


class SessionStats:
    """In-memory statistics, anomaly analysis and health scoring."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.start_time = now()
        self.end_time: datetime | None = None
        self.pings: list[PingResult] = []
        self.dns_results: list[DNSResult] = []
        self.gateway_results: list[GatewayResult] = []
        self.traces: list[TraceResult] = []
        self.events: list[AnomalyEvent] = []
        self.interruptions = 0
        self._was_online = True
        self._lock = threading.Lock()

    def add_event(self, severity: str, category: str, message: str) -> None:
        """Record a timestamped event."""
        self.events.append(AnomalyEvent(now(), severity, category, message))

    def add_ping_results(self, results: list[PingResult]) -> None:
        """Store ping results and detect latency/loss/connectivity anomalies."""
        with self._lock:
            self.pings.extend(results)
            successful = [item for item in results if item.success]
            online = bool(successful)
            if not online and self._was_online:
                self.interruptions += 1
                self.add_event("critical", "connectivity", "Internet interruption detected.")
            if online and not self._was_online:
                self.add_event("info", "connectivity", "Internet connectivity restored.")
            self._was_online = online

            for item in results:
                if not item.success:
                    self.add_event("warning", "ping", f"{item.target} did not respond: {item.error}")
                    continue
                if item.latency_ms is None:
                    continue
                if item.latency_ms >= self.config.severe_latency_ms:
                    self.add_event("critical", "latency", f"Severe latency spike to {item.target}: {item.latency_ms:.1f} ms.")
                elif item.latency_ms >= self.config.high_latency_ms:
                    self.add_event("warning", "latency", f"High latency to {item.target}: {item.latency_ms:.1f} ms.")

            loss = self.packet_loss_percent()
            if loss >= self.config.packet_loss_bad_percent:
                self.add_event("critical", "packet_loss", f"High packet loss observed: {loss:.1f}%.")
            elif loss >= self.config.packet_loss_warn_percent:
                self.add_event("warning", "packet_loss", f"Packet loss observed: {loss:.1f}%.")

            jitter = self.jitter_ms()
            if jitter is not None and jitter >= self.config.high_jitter_ms:
                self.add_event("warning", "jitter", f"Abnormal jitter fluctuation: {jitter:.1f} ms.")

            if self._degradation_detected():
                self.add_event("warning", "degradation", "Latency degradation trend detected.")

    def add_dns_results(self, results: list[DNSResult]) -> None:
        """Store DNS results and detect DNS anomalies."""
        with self._lock:
            self.dns_results.extend(results)
            for result in results:
                if not result.success:
                    self.add_event("warning", "dns", f"DNS failure for {result.host}: {result.error}")
                elif result.elapsed_ms is not None and result.elapsed_ms > 500:
                    self.add_event("warning", "dns", f"Slow DNS resolution for {result.host}: {result.elapsed_ms:.1f} ms.")

    def add_gateway_result(self, result: GatewayResult) -> None:
        """Store gateway result and detect gateway instability."""
        with self._lock:
            self.gateway_results.append(result)
            if result.gateway and not result.reachable:
                self.add_event("warning", "gateway", f"Gateway {result.gateway} is not reachable.")
            elif not result.gateway:
                self.add_event("info", "gateway", "Default gateway could not be discovered.")

    def add_trace_result(self, result: TraceResult) -> None:
        """Store traceroute result and detect route anomalies."""
        with self._lock:
            self.traces.append(result)
            if not result.success:
                self.add_event("warning", "route", f"Traceroute failed for {result.target}: {result.error}")
            if result.route_changed:
                self.add_event("warning", "route", f"Route change detected for {result.target}.")
            timeout_hops = sum(1 for hop in result.hops if hop.timeout)
            if timeout_hops >= 3:
                self.add_event("warning", "route", f"{timeout_hops} timeout hops detected in route to {result.target}.")

    def latencies(self) -> list[float]:
        """Return successful ping latencies."""
        return [item.latency_ms for item in self.pings if item.success and item.latency_ms is not None]

    def min_latency_ms(self) -> float | None:
        values = self.latencies()
        return min(values) if values else None

    def max_latency_ms(self) -> float | None:
        values = self.latencies()
        return max(values) if values else None

    def avg_latency_ms(self) -> float | None:
        values = self.latencies()
        return statistics.fmean(values) if values else None

    def jitter_ms(self) -> float | None:
        values = self.latencies()
        if len(values) < 2:
            return None
        diffs = [abs(values[index] - values[index - 1]) for index in range(1, len(values))]
        return statistics.fmean(diffs) if diffs else None

    def packet_loss_percent(self) -> float:
        if not self.pings:
            return 0.0
        lost = sum(1 for item in self.pings if not item.success)
        return lost / len(self.pings) * 100

    def uptime_percent(self) -> float:
        if not self.pings:
            return 0.0
        rounds: dict[str, list[PingResult]] = {}
        for item in self.pings:
            key = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            rounds.setdefault(key, []).append(item)
        online_rounds = sum(1 for results in rounds.values() if any(item.success for item in results))
        return online_rounds / max(1, len(rounds)) * 100

    def health_score(self) -> int:
        """Calculate an overall connection health score from 0 to 100."""
        score = 100.0
        loss = self.packet_loss_percent()
        jitter = self.jitter_ms() or 0.0
        avg = self.avg_latency_ms() or 0.0
        score -= min(45, loss * 2.2)
        score -= min(20, self.interruptions * 8)
        score -= min(15, max(0.0, avg - 80.0) / 12.0)
        score -= min(12, max(0.0, jitter - 25.0) / 5.0)
        score -= min(10, sum(1 for event in self.events if event.category == "dns") * 2)
        score -= min(10, sum(1 for event in self.events if event.category == "route") * 2)
        return max(0, min(100, round(score)))

    def status_label(self) -> str:
        score = self.health_score()
        if score >= 85:
            return "Excellent"
        if score >= 70:
            return "Good"
        if score >= 50:
            return "Degraded"
        return "Unstable"

    def _degradation_detected(self) -> bool:
        values = self.latencies()
        window = self.config.degradation_window
        if len(values) < window * 2:
            return False
        previous = statistics.fmean(values[-window * 2 : -window])
        current = statistics.fmean(values[-window:])
        return current > previous * 1.5 and current - previous > 40

    def finish(self) -> None:
        self.end_time = now()

    def snapshot(self) -> dict[str, Any]:
        """Return a serializable snapshot of important session metrics."""
        return {
            "start": fmt_dt(self.start_time),
            "end": fmt_dt(self.end_time or now()),
            "avg_latency_ms": self.avg_latency_ms(),
            "min_latency_ms": self.min_latency_ms(),
            "max_latency_ms": self.max_latency_ms(),
            "packet_loss_percent": self.packet_loss_percent(),
            "jitter_ms": self.jitter_ms(),
            "uptime_percent": self.uptime_percent(),
            "interruptions": self.interruptions,
            "health_score": self.health_score(),
            "status": self.status_label(),
        }


class DiagnosticsEngine:
    """Coordinate non-blocking diagnostics probes and OS-specific utilities."""

    def __init__(self, config: MonitorConfig, adapter: SystemAdapter, stats: SessionStats) -> None:
        self.config = config
        self.adapter = adapter
        self.stats = stats
        self.ping = PingDiagnostics(adapter, config)
        self.dns = DNSDiagnostics(adapter, config)
        self.trace = TraceDiagnostics(adapter, config)
        self.gateway = adapter.default_gateway()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=False)

    def run_cycle(self, cycle_number: int) -> CycleResult:
        """Run one diagnostics cycle with parallel ping/DNS/gateway checks."""
        started = time.perf_counter()
        ping_futures = [self.executor.submit(self.ping.probe, target) for target in self.config.targets]
        dns_futures = [self.executor.submit(self.dns.resolve, host) for host in self.config.dns_hosts]

        ping_results = [future.result() for future in concurrent.futures.as_completed(ping_futures)]
        dns_results = [future.result() for future in concurrent.futures.as_completed(dns_futures)]
        self.stats.add_ping_results(ping_results)
        self.stats.add_dns_results(dns_results)

        gateway_result = self.check_gateway()
        self.stats.add_gateway_result(gateway_result)

        trace_result = None
        if cycle_number == 1 or cycle_number % self.config.traceroute_interval == 0:
            trace_result = self.trace.trace(self.config.targets[0])
            self.stats.add_trace_result(trace_result)

        return CycleResult(
            number=cycle_number,
            timestamp=now(),
            ping_results=sorted(ping_results, key=lambda item: item.target),
            dns_results=sorted(dns_results, key=lambda item: item.host),
            gateway_result=gateway_result,
            trace_result=trace_result,
            elapsed_seconds=time.perf_counter() - started,
        )

    def check_gateway(self) -> GatewayResult:
        """Verify default gateway reachability when it is known."""
        if not self.gateway:
            self.gateway = self.adapter.default_gateway()
        if not self.gateway:
            return GatewayResult(timestamp=now(), gateway=None, reachable=False, error="gateway unavailable")
        result = self.ping.probe(self.gateway)
        return GatewayResult(
            timestamp=result.timestamp,
            gateway=self.gateway,
            reachable=result.success,
            latency_ms=result.latency_ms,
            error=result.error,
        )


class Dashboard:
    """ANSI terminal dashboard with continuous refresh and no flooding."""

    def __init__(self, config: MonitorConfig, adapter: SystemAdapter, stats: SessionStats) -> None:
        self.config = config
        self.adapter = adapter
        self.stats = stats

    def render(self, cycle_result: CycleResult | None = None) -> None:
        if self.config.no_dashboard:
            return
        enabled = not self.config.no_color
        data = self.stats.snapshot()
        score = data["health_score"]
        status_color = ANSI_GREEN if score >= 85 else ANSI_YELLOW if score >= 60 else ANSI_RED
        avg = self._fmt_ms(data["avg_latency_ms"])
        minimum = self._fmt_ms(data["min_latency_ms"])
        maximum = self._fmt_ms(data["max_latency_ms"])
        jitter = self._fmt_ms(data["jitter_ms"])
        loss = f"{data['packet_loss_percent']:.1f}%"
        uptime = f"{data['uptime_percent']:.1f}%"
        latest_trace = (
            cycle_result.trace_result
            if cycle_result and cycle_result.trace_result
            else self.stats.traces[-1] if self.stats.traces else None
        )
        latest_dns = cycle_result.dns_results if cycle_result else self.stats.dns_results[-len(self.config.dns_hosts) :]
        latest_events = self.stats.events[-8:]
        cycle_label = f"Cycle #{cycle_result.number}" if cycle_result else "Cycle"
        elapsed = f"{cycle_result.elapsed_seconds:.2f}s" if cycle_result else "n/a"

        lines = [
            ANSI_CLEAR,
            color("Internet Stability Monitor", ANSI_BOLD + ANSI_CYAN, enabled),
            f"Time: {fmt_dt(now())} | OS: {self.adapter.name} | Host: {socket.gethostname()}",
            "=" * 96,
            color("SESSION SUMMARY", ANSI_BOLD, enabled),
            self._table(
                ("Metric", "Value", "Metric", "Value"),
                (
                    ("Health", color(str(score) + "/100 " + data["status"], status_color, enabled), "Uptime", uptime),
                    ("Latency avg", avg, "Latency min/max", f"{minimum} / {maximum}"),
                    ("Packet loss", self._loss_colored(loss, data["packet_loss_percent"], enabled), "Jitter", jitter),
                    ("Interruptions", str(data["interruptions"]), "Runtime", self._runtime()),
                ),
                (20, 24, 20, 24),
            ),
            "",
            color("CURRENT CYCLE - STEP BY STEP", ANSI_BOLD, enabled),
            self._table(
                ("Step", "Status", "Details"),
                self._step_rows(cycle_result),
                (24, 14, 52),
            ),
            "",
            color("PING MONITORING", ANSI_BOLD, enabled),
            self._table(
                ("Target", "Status", "Latency", "Loss/Error"),
                self._ping_rows(cycle_result, enabled),
                (24, 12, 14, 42),
            ),
        ]

        lines.extend([
            "",
            color("DNS DIAGNOSTICS", ANSI_BOLD, enabled),
            self._table(
                ("Host", "Status", "Time", "Addresses/Error"),
                self._dns_rows(latest_dns, enabled),
                (24, 12, 12, 48),
            ),
            "",
            color("GATEWAY", ANSI_BOLD, enabled),
            self._table(
                ("Gateway", "Status", "Latency", "Error"),
                (self._gateway_row(cycle_result, enabled),),
                (24, 14, 14, 44),
            ),
            "",
            color("TRACEROUTE / ROUTE STABILITY", ANSI_BOLD, enabled),
        ])
        if latest_trace:
            route_status = "changed" if latest_trace.route_changed else "stable"
            lines.append(self._table(
                ("Target", "Success", "Hops", "Route"),
                ((latest_trace.target, str(latest_trace.success), str(len(latest_trace.hops)), route_status),),
                (24, 12, 10, 42),
            ))
            lines.append(
                self._table(
                    ("Hop", "Host", "Avg latency", "State"),
                    self._trace_rows(latest_trace),
                    (8, 34, 16, 30),
                )
            )
        else:
            lines.append("  Traceroute scheduled for first cycle and then every configured interval.")

        lines.extend(["", color("RECENT ALERTS", ANSI_BOLD, enabled)])
        if latest_events:
            rows = []
            for event in latest_events:
                event_color = ANSI_RED if event.severity == "critical" else ANSI_YELLOW if event.severity == "warning" else ANSI_DIM
                rows.append((fmt_dt(event.timestamp), color(event.severity.upper(), event_color, enabled), event.category, event.message))
            lines.append(self._table(("Timestamp", "Severity", "Category", "Message"), rows, (20, 12, 14, 46)))
        else:
            lines.append("  no anomalies detected")

        lines.append("")
        lines.append(color("Press Ctrl+C to stop. You will be asked whether to export the TXT report.", ANSI_DIM, enabled))
        sys.stdout.write("\n".join(lines))
        sys.stdout.flush()

    def _fmt_ms(self, value: float | None) -> str:
        return "n/a" if value is None else f"{value:.1f} ms"

    def _loss_colored(self, text: str, loss: float, enabled: bool) -> str:
        if loss >= self.config.packet_loss_bad_percent:
            return color(text, ANSI_RED, enabled)
        if loss >= self.config.packet_loss_warn_percent:
            return color(text, ANSI_YELLOW, enabled)
        return color(text, ANSI_GREEN, enabled)

    def _gateway_line(self) -> str:
        latest = self.stats.gateway_results[-1] if self.stats.gateway_results else None
        if not latest:
            return "waiting"
        if not latest.gateway:
            return "not discovered"
        status = "reachable" if latest.reachable else "unreachable"
        latency = self._fmt_ms(latest.latency_ms)
        return f"{latest.gateway} {status} {latency}"

    def _dns_line(self, results: list[DNSResult]) -> str:
        if not results:
            return "waiting"
        ok = sum(1 for item in results if item.success)
        avg_values = [item.elapsed_ms for item in results if item.elapsed_ms is not None]
        avg = statistics.fmean(avg_values) if avg_values else None
        return f"{ok}/{len(results)} healthy, avg {self._fmt_ms(avg)}"

    def _runtime(self) -> str:
        seconds = int((now() - self.stats.start_time).total_seconds())
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _table(self, headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...] | list[tuple[str, ...]], widths: tuple[int, ...]) -> str:
        header = " | ".join(self._cell(value, widths[index]) for index, value in enumerate(headers))
        separator = "-+-".join("-" * width for width in widths)
        body = [" | ".join(self._cell(str(value), widths[index]) for index, value in enumerate(row)) for row in rows]
        return "\n".join((header, separator, *body))

    def _cell(self, value: str, width: int) -> str:
        clean = value.replace("\n", " ")
        if len(clean) > width:
            clean = clean[: max(0, width - 3)] + "..."
        return f"{clean:<{width}}"

    def _step_rows(self, cycle_result: CycleResult | None) -> tuple[tuple[str, str, str], ...]:
        if not cycle_result:
            return (("Initialization", "waiting", "Preparing first diagnostics cycle."),)
        trace_status = "executed" if cycle_result.trace_result else "scheduled"
        return (
            ("1. Public endpoints", "done", f"{len(cycle_result.ping_results)} ping probes completed"),
            ("2. DNS resolution", "done", f"{len(cycle_result.dns_results)} host lookups completed"),
            ("3. Gateway check", "done", self._gateway_line()),
            ("4. Traceroute", trace_status, self._trace_step_detail(cycle_result.trace_result)),
            ("5. Analysis", "done", f"Cycle elapsed {cycle_result.elapsed_seconds:.2f}s"),
        )

    def _trace_step_detail(self, trace_result: TraceResult | None) -> str:
        if not trace_result:
            return f"Runs every {self.config.traceroute_interval} cycle(s)."
        route = "changed" if trace_result.route_changed else "stable"
        return f"{len(trace_result.hops)} hops, route {route}, success={trace_result.success}"

    def _ping_rows(self, cycle_result: CycleResult | None, enabled: bool) -> tuple[tuple[str, str, str, str], ...]:
        rows = []
        source = cycle_result.ping_results if cycle_result else []
        for target in self.config.targets:
            item = next((result for result in source if result.target == target), None)
            if not item:
                rows.append((target, "waiting", "n/a", "n/a"))
            elif item.success:
                rows.append((target, color("ONLINE", ANSI_GREEN, enabled), self._fmt_ms(item.latency_ms), f"{item.packet_loss_percent:.1f}%"))
            else:
                rows.append((target, color("OFFLINE", ANSI_RED, enabled), "n/a", item.error or "no response"))
        return tuple(rows)

    def _dns_rows(self, results: list[DNSResult], enabled: bool) -> tuple[tuple[str, str, str, str], ...]:
        if not results:
            return (("waiting", "waiting", "n/a", "n/a"),)
        rows = []
        for item in results:
            status = color("OK", ANSI_GREEN, enabled) if item.success else color("FAIL", ANSI_RED, enabled)
            detail = ", ".join(item.addresses[:3]) if item.success else item.error or "resolution failed"
            rows.append((item.host, status, self._fmt_ms(item.elapsed_ms), detail))
        return tuple(rows)

    def _gateway_row(self, cycle_result: CycleResult | None, enabled: bool) -> tuple[str, str, str, str]:
        item = cycle_result.gateway_result if cycle_result else (self.stats.gateway_results[-1] if self.stats.gateway_results else None)
        if not item:
            return ("waiting", "waiting", "n/a", "n/a")
        status = color("REACHABLE", ANSI_GREEN, enabled) if item.reachable else color("UNREACHABLE", ANSI_RED, enabled)
        return (item.gateway or "not discovered", status, self._fmt_ms(item.latency_ms), item.error or "")

    def _trace_rows(self, trace_result: TraceResult) -> tuple[tuple[str, str, str, str], ...]:
        if not trace_result.hops:
            return (("n/a", "No route hops parsed", "n/a", trace_result.error or "failed"),)
        rows = []
        for hop in trace_result.hops[:12]:
            state = "timeout" if hop.timeout else "ok"
            rows.append((str(hop.number), hop.host, self._fmt_ms(hop.average_ms), state))
        return tuple(rows)


class ReportWriter:
    """Generate structured human-readable TXT session reports."""

    def __init__(
        self,
        config: MonitorConfig,
        adapter: SystemAdapter,
        stats: SessionStats,
        engine: DiagnosticsEngine,
    ) -> None:
        self.config = config
        self.adapter = adapter
        self.stats = stats
        self.engine = engine

    def write(self) -> Path:
        """Write the final report to the reports directory."""
        self.config.report_dir.mkdir(parents=True, exist_ok=True)
        stamp = now().strftime("%Y%m%d_%H%M%S")
        path = self.config.report_dir / f"internet_diagnostics_{stamp}.txt"
        content = self._build_report()
        path.write_text(content, encoding="utf-8", errors="replace")
        return path

    def _build_report(self) -> str:
        local_ip = self.adapter.local_ip() or "Unavailable"
        public_ip = self.adapter.public_ip() or "Unavailable"
        dns_config = self.adapter.collect_dns_config()
        native_dns = "\n\n".join(
            f"Lookup for {host}\n{self.engine.dns.native_lookup(host)}"
            for host in self.config.dns_hosts[:2]
        )
        snapshot = self.stats.snapshot()
        lines = [
            "INTERNET STABILITY MONITOR - DIAGNOSTIC REPORT",
            "=" * 72,
            "",
            "SESSION",
            "-" * 72,
            f"Start timestamp: {fmt_dt(self.stats.start_time)}",
            f"End timestamp: {fmt_dt(self.stats.end_time or now())}",
            f"Duration seconds: {self._duration_seconds():.1f}",
            "",
            "HOST AND OPERATING SYSTEM",
            "-" * 72,
            f"Operating system: {platform.platform()}",
            f"Python version: {platform.python_version()}",
            f"Hostname: {socket.gethostname()}",
            f"Local IP: {local_ip}",
            f"Public IP: {public_ip}",
            f"Monitoring targets: {', '.join(self.config.targets)}",
            "",
            "SUMMARY",
            "-" * 72,
            f"Health score: {snapshot['health_score']}/100",
            f"Final stability assessment: {snapshot['status']}",
            f"Connection uptime: {snapshot['uptime_percent']:.2f}%",
            f"Connection interruptions: {snapshot['interruptions']}",
            f"Packet loss: {snapshot['packet_loss_percent']:.2f}%",
            f"Average latency: {self._fmt(snapshot['avg_latency_ms'])}",
            f"Minimum latency: {self._fmt(snapshot['min_latency_ms'])}",
            f"Maximum latency: {self._fmt(snapshot['max_latency_ms'])}",
            f"Jitter: {self._fmt(snapshot['jitter_ms'])}",
            "",
            "GATEWAY ANALYSIS",
            "-" * 72,
            f"Detected gateway: {self.engine.gateway or 'Unavailable'}",
        ]

        lines.extend(self._gateway_report())
        lines.extend([
            "",
            "DNS CONFIGURATION",
            "-" * 72,
            dns_config.strip() or "Unavailable",
            "",
            "DNS DIAGNOSTICS",
            "-" * 72,
        ])
        lines.extend(self._dns_report())
        lines.extend(["", "NATIVE DNS COMMAND OUTPUT", "-" * 72, native_dns.strip() or "Unavailable"])
        lines.extend(["", "LATENCY AND PACKET LOSS DETAILS", "-" * 72])
        lines.extend(self._target_report())
        lines.extend(["", "TRACEROUTE RESULTS", "-" * 72])
        lines.extend(self._trace_report())
        lines.extend(["", "ANOMALY TIMELINE", "-" * 72])
        lines.extend(self._event_report())
        lines.extend(["", "RAW METRIC SNAPSHOT", "-" * 72, json.dumps(snapshot, indent=2, ensure_ascii=False)])
        lines.extend(["", "DIAGNOSTIC CONCLUSIONS", "-" * 72, self._conclusion()])
        return "\n".join(lines) + "\n"

    def _duration_seconds(self) -> float:
        end = self.stats.end_time or now()
        return max(0.0, (end - self.stats.start_time).total_seconds())

    def _fmt(self, value: float | None) -> str:
        return "n/a" if value is None else f"{value:.2f} ms"

    def _gateway_report(self) -> list[str]:
        if not self.stats.gateway_results:
            return ["No gateway checks were recorded."]
        checks = self.stats.gateway_results
        reachable = sum(1 for item in checks if item.reachable)
        latencies = [item.latency_ms for item in checks if item.latency_ms is not None]
        avg = statistics.fmean(latencies) if latencies else None
        return [
            f"Gateway checks: {len(checks)}",
            f"Reachable checks: {reachable}",
            f"Gateway average latency: {self._fmt(avg)}",
        ]

    def _dns_report(self) -> list[str]:
        if not self.stats.dns_results:
            return ["No DNS checks were recorded."]
        lines = []
        for host in self.config.dns_hosts:
            results = [item for item in self.stats.dns_results if item.host == host]
            if not results:
                continue
            ok = sum(1 for item in results if item.success)
            timings = [item.elapsed_ms for item in results if item.elapsed_ms is not None]
            avg = statistics.fmean(timings) if timings else None
            failures = len(results) - ok
            lines.append(f"{host}: {ok}/{len(results)} successful, failures={failures}, avg={self._fmt(avg)}")
        return lines or ["No DNS host results available."]

    def _target_report(self) -> list[str]:
        if not self.stats.pings:
            return ["No ping checks were recorded."]
        lines = []
        for target in self.config.targets:
            items = [item for item in self.stats.pings if item.target == target]
            if not items:
                continue
            latencies = [item.latency_ms for item in items if item.success and item.latency_ms is not None]
            loss = (sum(1 for item in items if not item.success) / len(items)) * 100
            avg = statistics.fmean(latencies) if latencies else None
            minimum = min(latencies) if latencies else None
            maximum = max(latencies) if latencies else None
            lines.append(
                f"{target}: probes={len(items)}, loss={loss:.2f}%, "
                f"avg={self._fmt(avg)}, min={self._fmt(minimum)}, max={self._fmt(maximum)}"
            )
        return lines

    def _trace_report(self) -> list[str]:
        if not self.stats.traces:
            return ["No traceroute checks were recorded."]
        lines = []
        for trace in self.stats.traces:
            lines.append("")
            lines.append(f"{fmt_dt(trace.timestamp)} target={trace.target} success={trace.success} changed={trace.route_changed}")
            if trace.error:
                lines.append(f"Error: {trace.error}")
            for hop in trace.hops:
                avg = self._fmt(hop.average_ms)
                timeout = " timeout" if hop.timeout else ""
                lines.append(f"  {hop.number:>2} {hop.host:<28} {avg}{timeout}")
        return lines

    def _event_report(self) -> list[str]:
        if not self.stats.events:
            return ["No anomalies detected during the session."]
        return [
            f"{fmt_dt(event.timestamp)} [{event.severity.upper()}] {event.category}: {event.message}"
            for event in self.stats.events
        ]

    def _conclusion(self) -> str:
        score = self.stats.health_score()
        loss = self.stats.packet_loss_percent()
        jitter = self.stats.jitter_ms() or 0.0
        avg = self.stats.avg_latency_ms() or 0.0
        if score >= 85:
            return "The connection was stable during this monitoring session."
        if score >= 70:
            return "The connection was usable, with minor signs of latency, DNS or route variation."
        if loss >= self.config.packet_loss_bad_percent or self.stats.interruptions:
            return "The connection showed instability with packet loss or temporary interruptions."
        if jitter >= self.config.high_jitter_ms or avg >= self.config.high_latency_ms:
            return "The connection showed latency instability that may affect real-time traffic."
        return "The connection showed degraded behavior and should be investigated further."


def parse_args(argv: list[str]) -> MonitorConfig:
    """Parse CLI arguments and build monitor configuration."""
    parser = argparse.ArgumentParser(description="Portable internet stability monitor.")
    parser.add_argument("--target", action="append", dest="targets", help="Ping target. Can be used multiple times.")
    parser.add_argument("--dns-host", action="append", dest="dns_hosts", help="DNS host to resolve. Can be used multiple times.")
    parser.add_argument("--interval", type=float, default=5.0, help="Monitoring interval in seconds.")
    parser.add_argument("--traceroute-interval", type=int, default=6, help="Run traceroute every N cycles.")
    parser.add_argument("--max-hops", type=int, default=20, help="Maximum traceroute hops.")
    parser.add_argument("--duration", type=float, default=0.0, help="Optional duration in seconds. 0 means until Ctrl+C.")
    parser.add_argument("--report-dir", default="reports", help="Directory where TXT reports are saved.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable real-time dashboard refresh.")
    parser.add_argument("--auto-export", action="store_true", help="Export TXT report without asking when the session stops.")
    args = parser.parse_args(argv)

    config = MonitorConfig(
        targets=args.targets or list(DEFAULT_TARGETS),
        dns_hosts=args.dns_hosts or list(DEFAULT_DNS_HOSTS),
        interval_seconds=max(1.0, args.interval),
        traceroute_interval=max(1, args.traceroute_interval),
        max_hops=max(1, args.max_hops),
        duration_seconds=max(0.0, args.duration),
        report_dir=Path(args.report_dir),
        no_color=args.no_color,
        no_dashboard=args.no_dashboard,
        auto_export=args.auto_export,
    )
    return config


def ask_yes_no(question: str, default: bool = True) -> bool:
    """Ask a terminal yes/no question."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        try:
            answer = input(question + suffix).strip().lower()
        except EOFError:
            return default
        if not answer:
            return default
        if answer in {"y", "yes", "s", "sim"}:
            return True
        if answer in {"n", "no", "nao", "não"}:
            return False
        print("Please answer yes/no or sim/nao.")


def sleep_until_next_cycle(started: float, interval: float) -> None:
    """Sleep only the remaining interval after diagnostics work finishes."""
    elapsed = time.perf_counter() - started
    remaining = max(0.0, interval - elapsed)
    if remaining:
        time.sleep(remaining)


def main(argv: list[str] | None = None) -> int:
    """Application entry point."""
    config = parse_args(argv or sys.argv[1:])
    adapter = SystemAdapter()
    stats = SessionStats(config)
    engine = DiagnosticsEngine(config, adapter, stats)
    dashboard = Dashboard(config, adapter, stats)
    reporter = ReportWriter(config, adapter, stats, engine)
    duration_seconds = getattr(config, "duration_seconds", 0.0)
    started = time.perf_counter()
    cycle = 0

    try:
        while True:
            cycle += 1
            cycle_started = time.perf_counter()
            cycle_result = engine.run_cycle(cycle)
            dashboard.render(cycle_result)
            if duration_seconds and time.perf_counter() - started >= duration_seconds:
                break
            sleep_until_next_cycle(cycle_started, config.interval_seconds)
    except KeyboardInterrupt:
        stats.add_event("info", "session", "Monitoring interrupted by user.")
    finally:
        stats.finish()
        engine.close()
        if not config.no_dashboard:
            sys.stdout.write("\n\n")
        should_export = bool(getattr(config, "auto_export", False) or duration_seconds)
        if not should_export:
            should_export = ask_yes_no("Deseja exportar o relatorio TXT desta sessao?", default=True)
        if should_export:
            report_path = reporter.write()
            print(f"Report generated: {report_path.resolve()}")
        else:
            print("Report export skipped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
