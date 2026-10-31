#!/usr/bin/env python3
"""Generate Windows route table commands from IPv4 BGP prefixes by ASN.

The script intentionally uses only the Python standard library.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import select
import socket
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Iterable, TextIO


# =============================================================================
# Configuration
# =============================================================================

ASN_LIST = "3216,6697,6764,8901,12668,12389,12876,21030,29226,33844,35237,39812,43647,44386,48282,48642,50340,51464,56694,56971,62261,201706,205638,208398,209024,216158"

OUTPUT_FILE = "ruroutes.dat"

GATEWAY = "0.0.0.0"

RIPE_HOST = "riswhois.ripe.net"

RIPE_PORT = 43

CONNECT_TIMEOUT = 10
READ_POLL_TIMEOUT = 1
QUERY_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 3
MAX_ROUTES_PER_FILE = 1024

DEBUG = False
ENABLE_IRRD_MULTICOMMAND = True
FETCH_ASN_NAMES = False
ASN_NAME_QUERY_TEMPLATE = "!iAS{asn},aut-num"


EXIT_SUCCESS = 0
EXIT_GENERAL_FAILURE = 1
EXIT_CONFIG_ERROR = 2
EXIT_NETWORK_FAILURE = 3
EXIT_OUTPUT_FAILURE = 4
EXIT_INTERRUPTED = 130

ASN_MIN = 0
ASN_MAX = 4_294_967_295

PREFIX_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
ROUTE_LINE_RE = re.compile(
    r"^route add (?P<network>\d{1,3}(?:\.\d{1,3}){3}) "
    r"mask (?P<mask>\d{1,3}(?:\.\d{1,3}){3}) "
    r"(?P<gateway>\d{1,3}(?:\.\d{1,3}){3}) & rem "
    r"(?P<comment>AS\d+(?: [^,\r\n]+)?(?:, AS\d+(?: [^,\r\n]+)?)*)$"
)
CMD_UNSAFE_CHARS = str.maketrans({char: " " for char in "&|<>^%"})


class ConfigError(Exception):
    """Configuration is invalid and no network connection should be attempted."""


class NetworkQueryError(Exception):
    """The RIPE query failed due to network, timeout, or incomplete response."""


class ProtocolError(Exception):
    """The RIPE/IRRd stream did not follow the expected framing."""


class DataValidationError(Exception):
    """RIPE returned data that cannot safely be used."""


class OutputValidationError(Exception):
    """The generated output failed validation before atomic replacement."""


@dataclass
class IRRdResponse:
    kind: str
    payload: bytes = b""
    message: str = ""


@dataclass(frozen=True)
class Origin:
    asn: int
    name: str


@dataclass
class ASNData:
    asn: int
    name: str = "UNKNOWN"
    prefixes: list[ipaddress.IPv4Network] = field(default_factory=list)
    aggregated_prefixes: list[ipaddress.IPv4Network] = field(default_factory=list)
    raw_prefix_count: int = 0
    duplicates_removed: int = 0
    invalid_prefixes: int = 0
    status: str = "pending"
    error: str = ""


@dataclass
class RunStats:
    asn_requested: int = 0
    asn_processed: int = 0
    asn_without_ipv4_routes: int = 0
    asn_failed: int = 0
    raw_prefixes: int = 0
    duplicates_removed: int = 0
    aggregated_prefixes: int = 0
    moas_duplicates_merged: int = 0
    final_routes: int = 0
    output_files: list[str] = field(default_factory=list)
    ripe_fetch_time: float = 0.0
    aggregation_time: float = 0.0
    total_time: float = 0.0


class ProgressReporter:
    def __init__(self, stream: TextIO = sys.stdout) -> None:
        self.stream = stream
        self.is_tty = stream.isatty()
        self.spinner = "|/-\\"
        self.spinner_index = 0
        self.last_len = 0

    def update(self, phase: str, message: str, *, force: bool = False) -> None:
        if not self.is_tty and not force:
            return
        spin = self.spinner[self.spinner_index % len(self.spinner)]
        self.spinner_index += 1
        line = f"[{phase}] {message} | {spin}"
        if self.is_tty:
            padding = " " * max(0, self.last_len - len(line))
            self.stream.write("\r" + line + padding)
            self.stream.flush()
            self.last_len = len(line)
        else:
            self.stream.write(line + "\n")
            self.stream.flush()

    def finish_line(self) -> None:
        if self.is_tty and self.last_len:
            self.stream.write("\n")
            self.stream.flush()
            self.last_len = 0

    def milestone(self, phase: str, message: str) -> None:
        self.finish_line()
        self.stream.write(f"[{phase}] {message}\n")
        self.stream.flush()

    def warn(self, message: str) -> None:
        self.finish_line()
        self.stream.write(f"[WARN] {message}\n")
        self.stream.flush()

    def error(self, message: str) -> None:
        self.finish_line()
        self.stream.write(f"ERROR: {message}\n")
        self.stream.flush()


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def parse_asn_list(value: str) -> list[int]:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("ASN_LIST must be a non-empty comma-separated string")

    result: list[int] = []
    seen: set[int] = set()
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            raise ConfigError("invalid ASN value: empty item")
        if item.upper().startswith("AS"):
            item = item[2:].strip()
        if not item.isdigit():
            raise ConfigError(f"invalid ASN value: {raw_item.strip()}")
        asn = int(item)
        if asn < ASN_MIN or asn > ASN_MAX:
            raise ConfigError(f"ASN out of range: {asn}")
        if asn not in seen:
            seen.add(asn)
            result.append(asn)
    return result


def validate_config() -> list[int]:
    asns = parse_asn_list(ASN_LIST)
    if not OUTPUT_FILE:
        raise ConfigError("OUTPUT_FILE must not be empty")
    ipaddress.IPv4Address(GATEWAY)
    if not RIPE_HOST:
        raise ConfigError("RIPE_HOST must not be empty")
    if RIPE_PORT <= 0 or RIPE_PORT > 65535:
        raise ConfigError(f"invalid RIPE_PORT: {RIPE_PORT}")
    for name, value in (
        ("CONNECT_TIMEOUT", CONNECT_TIMEOUT),
        ("READ_POLL_TIMEOUT", READ_POLL_TIMEOUT),
        ("QUERY_TIMEOUT", QUERY_TIMEOUT),
        ("MAX_RETRIES", MAX_RETRIES),
        ("MAX_ROUTES_PER_FILE", MAX_ROUTES_PER_FILE),
    ):
        if value <= 0:
            raise ConfigError(f"{name} must be positive")
    if RETRY_DELAY < 0:
        raise ConfigError("RETRY_DELAY must not be negative")
    return asns


class RISWhoisClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        progress: ProgressReporter | None = None,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None:
        self.host = host
        self.port = port
        self.progress = progress or ProgressReporter()
        self.time_func = time_func
        self.sock: socket.socket | None = None

    def connect(self, *, attempt: int = 1, total: int = MAX_RETRIES) -> None:
        self.close()
        started = self.time_func()
        last_progress = 0.0
        last_error: Exception | None = None
        try:
            addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise NetworkQueryError(f"failed to resolve {self.host}: {exc}") from exc

        for family, socktype, proto, _canonname, sockaddr in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            try:
                err = sock.connect_ex(sockaddr)
                if err not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                    raise OSError(err, os.strerror(err))
                deadline = started + CONNECT_TIMEOUT
                while True:
                    now = self.time_func()
                    if now - last_progress >= 0.5:
                        self.progress.update(
                            "CONNECT",
                            f"{self.host}:{self.port} | attempt {attempt}/{total} "
                            f"| elapsed: {format_duration(now - started)}",
                        )
                        last_progress = now
                    remaining = deadline - now
                    if remaining <= 0:
                        raise socket.timeout(f"connect timed out after {CONNECT_TIMEOUT}s")
                    _readable, writable, _errors = select.select(
                        [], [sock], [], min(READ_POLL_TIMEOUT, remaining)
                    )
                    if not writable:
                        continue
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err:
                        raise OSError(err, os.strerror(err))
                    sock.setblocking(True)
                    sock.settimeout(READ_POLL_TIMEOUT)
                    self.sock = sock
                    self.enable_multi_command_mode()
                    self.progress.milestone("OK", f"Connected to {self.host}:{self.port}")
                    return
            except Exception as exc:
                last_error = exc
                sock.close()
                debug_log(f"connect candidate failed: {exc!r}")

        raise NetworkQueryError(f"failed to connect to {self.host}:{self.port}: {last_error}")

    def reconnect(self, *, attempt: int, total: int) -> None:
        debug_log("reconnecting")
        self.close()
        self.connect(attempt=attempt, total=total)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def send_query(self, query: str) -> None:
        if self.sock is None:
            self.connect()
        assert self.sock is not None
        payload = (query.rstrip("\r\n") + "\n").encode("ascii")
        self.sock.sendall(payload)

    def enable_multi_command_mode(self) -> None:
        if not ENABLE_IRRD_MULTICOMMAND:
            return
        if self.sock is None:
            raise NetworkQueryError("socket is not connected")
        self.sock.sendall(b"!!\n")
        debug_log("IRRd multi-command mode enabled")

    def query_ipv4_prefixes(self, asn: int, current: int, total: int) -> str:
        response = self._query_with_retries(f"!gAS{asn}", asn, current, total, "prefixes")
        if response.kind in ("C", "D"):
            return ""
        if response.kind != "A":
            raise ProtocolError(f"unexpected response for AS{asn}: {response.kind}")
        return response.payload.decode("utf-8", errors="replace")

    def query_as_name(self, asn: int, current: int, total: int) -> str:
        if not FETCH_ASN_NAMES:
            return "UNKNOWN"
        query = ASN_NAME_QUERY_TEMPLATE.format(asn=asn)
        try:
            response = self._query_with_retries(
                query, asn, current, total, "asn-name", tolerate_f=True
            )
        except Exception as exc:
            debug_log(f"AS{asn} name lookup failed: {exc!r}")
            return "UNKNOWN"
        if response.kind != "A":
            return "UNKNOWN"
        text = response.payload.decode("utf-8", errors="replace")
        return extract_as_name(text) or "UNKNOWN"

    def _query_with_retries(
        self,
        query: str,
        asn: int,
        current: int,
        total: int,
        label: str,
        *,
        tolerate_f: bool = False,
    ) -> IRRdResponse:
        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if self.sock is None:
                    self.connect(attempt=attempt, total=MAX_RETRIES)
                self.send_query(query)
                started = self.time_func()
                response = self._read_irrd_response(
                    asn=asn,
                    current=current,
                    total=total,
                    query_started_at=started,
                    label=label,
                )
                if response.kind == "F" and not tolerate_f:
                    raise ProtocolError(response.message or f"RIPE returned F for {query}")
                return response
            except (OSError, NetworkQueryError, ProtocolError) as exc:
                last_error = exc
                self.progress.warn(
                    f"AS{asn} {label} attempt {attempt}/{MAX_RETRIES} failed: {exc}"
                )
                self.close()
                if attempt >= MAX_RETRIES:
                    break
                if RETRY_DELAY:
                    time.sleep(RETRY_DELAY)
        raise NetworkQueryError(f"AS{asn}: query failed after {MAX_RETRIES} attempts: {last_error}")

    def _read_irrd_response(
        self,
        *,
        asn: int,
        current: int,
        total: int,
        query_started_at: float,
        label: str,
    ) -> IRRdResponse:
        header = self._read_line(
            asn=asn,
            current=current,
            total=total,
            query_started_at=query_started_at,
            last_data_received_at=query_started_at,
            received=0,
            prefixes=0,
            label=label,
        )
        if not header:
            raise ProtocolError("empty IRRd response header")

        marker = chr(header[0])
        if marker == "A":
            length_text = header[1:].decode("ascii", errors="replace").strip()
            if not length_text.isdigit():
                raise ProtocolError(f"invalid A response length: {length_text!r}")
            length = int(length_text)
            payload, last_data = self._read_exact_payload(
                length,
                asn=asn,
                current=current,
                total=total,
                query_started_at=query_started_at,
                label=label,
            )
            terminator = self._read_terminator(
                asn=asn,
                current=current,
                total=total,
                query_started_at=query_started_at,
                last_data_received_at=last_data,
                received=length,
                prefixes=count_prefix_tokens(payload),
                label=label,
            )
            if terminator != b"C":
                raise ProtocolError(f"expected C terminator after A payload, got {terminator!r}")
            return IRRdResponse("A", payload=payload)

        if marker in ("C", "D"):
            return IRRdResponse(marker)
        if marker == "F":
            return IRRdResponse("F", message=header[1:].decode("utf-8", errors="replace").strip())
        raise ProtocolError(f"unknown IRRd response marker: {marker!r}")

    def _read_exact_payload(
        self,
        length: int,
        *,
        asn: int,
        current: int,
        total: int,
        query_started_at: float,
        label: str,
    ) -> tuple[bytes, float]:
        payload = bytearray()
        last_data = query_started_at
        last_progress = 0.0
        while len(payload) < length:
            def on_wait(now: float) -> None:
                nonlocal last_progress
                if now - last_progress >= 0.5:
                    self.progress.update(
                        "FETCH",
                        f"{current}/{total} AS{asn} | waiting for RIPE | {label}: "
                        f"{count_prefix_tokens(payload)} | received: {len(payload) // 1024} KB "
                        f"| elapsed: {format_duration(now - query_started_at)} "
                        f"| last data: {now - last_data:.1f}s",
                    )
                    last_progress = now

            byte = self._read_byte(query_started_at=query_started_at, on_wait=on_wait)
            payload.extend(byte)
            now = self.time_func()
            if now - last_progress >= 0.5:
                self.progress.update(
                    "FETCH",
                    f"{current}/{total} AS{asn} | {label}: {count_prefix_tokens(payload)} "
                    f"| received: {len(payload) // 1024} KB "
                    f"| elapsed: {format_duration(now - query_started_at)} "
                    f"| last data: {now - last_data:.1f}s",
                )
                last_progress = now
            last_data = now
        return bytes(payload), last_data

    def _read_line(
        self,
        *,
        asn: int,
        current: int,
        total: int,
        query_started_at: float,
        last_data_received_at: float,
        received: int,
        prefixes: int,
        label: str,
    ) -> bytes:
        line = bytearray()
        last_data = last_data_received_at
        last_progress = 0.0
        while True:
            try:
                def on_wait(now: float) -> None:
                    nonlocal last_progress
                    if now - last_progress >= 0.5:
                        self.progress.update(
                            "FETCH",
                            f"{current}/{total} AS{asn} | waiting for RIPE | {label} "
                            f"| prefixes: {prefixes} | received: {received // 1024} KB "
                            f"| elapsed: {format_duration(now - query_started_at)} "
                            f"| last data: {now - last_data:.1f}s",
                        )
                        last_progress = now

                byte = self._read_byte(query_started_at=query_started_at, on_wait=on_wait)
            except socket.timeout:
                raise
            if byte == b"":
                raise NetworkQueryError("connection closed before complete IRRd response")
            line.extend(byte)
            now = self.time_func()
            if now - last_progress >= 0.5:
                self.progress.update(
                    "FETCH",
                    f"{current}/{total} AS{asn} | {label} | prefixes: {prefixes} "
                    f"| received: {received // 1024} KB "
                    f"| elapsed: {format_duration(now - query_started_at)} "
                    f"| last data: {now - last_data:.1f}s",
                )
                last_progress = now
            last_data = now
            if byte == b"\n":
                return bytes(line).rstrip(b"\r\n")

    def _read_terminator(
        self,
        *,
        asn: int,
        current: int,
        total: int,
        query_started_at: float,
        last_data_received_at: float,
        received: int,
        prefixes: int,
        label: str,
    ) -> bytes:
        while True:
            line = self._read_line(
                asn=asn,
                current=current,
                total=total,
                query_started_at=query_started_at,
                last_data_received_at=last_data_received_at,
                received=received,
                prefixes=prefixes,
                label=label,
            )
            if line:
                return line

    def _read_byte(
        self, *, query_started_at: float, on_wait: Callable[[float], None] | None = None
    ) -> bytes:
        if self.sock is None:
            raise NetworkQueryError("socket is not connected")
        while True:
            now = self.time_func()
            if now - query_started_at > QUERY_TIMEOUT:
                raise NetworkQueryError(f"query timed out after {QUERY_TIMEOUT}s")
            try:
                chunk = self.sock.recv(1)
            except socket.timeout:
                now = self.time_func()
                if now - query_started_at > QUERY_TIMEOUT:
                    raise NetworkQueryError(f"query timed out after {QUERY_TIMEOUT}s")
                if on_wait is not None:
                    on_wait(now)
                continue
            if chunk == b"":
                raise NetworkQueryError("connection closed before complete IRRd response")
            return chunk


def count_prefix_tokens(data: bytes | bytearray) -> int:
    return sum(1 for token in bytes(data).split() if PREFIX_RE.match(token.decode("ascii", "ignore")))


def extract_as_name(text: str) -> str:
    for line in text.splitlines():
        if line.lower().startswith("as-name:"):
            return sanitize_asn_name(line.split(":", 1)[1].strip())
    for line in text.splitlines():
        if line.lower().startswith("descr:"):
            return sanitize_asn_name(line.split(":", 1)[1].strip())
    return ""


def sanitize_asn_name(value: str) -> str:
    cleaned = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in value)
    cleaned = cleaned.translate(CMD_UNSAFE_CHARS)
    cleaned = " ".join(cleaned.split())
    return cleaned[:120] or "UNKNOWN"


def normalize_prefixes(text: str, *, asn: int) -> tuple[list[ipaddress.IPv4Network], int]:
    networks: list[ipaddress.IPv4Network] = []
    invalid = 0
    for token in text.split():
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            invalid += 1
            raise DataValidationError(f"AS{asn}: invalid prefix from RIPE: {token!r}: {exc}") from exc
        if isinstance(network, ipaddress.IPv6Network):
            invalid += 1
            continue
        networks.append(network)
    return networks, invalid


def deduplicate_prefixes(
    prefixes: Iterable[ipaddress.IPv4Network],
) -> tuple[list[ipaddress.IPv4Network], int]:
    seen: set[ipaddress.IPv4Network] = set()
    result: list[ipaddress.IPv4Network] = []
    duplicates = 0
    for network in sorted(prefixes, key=network_sort_key):
        if network in seen:
            duplicates += 1
            continue
        seen.add(network)
        result.append(network)
    return result, duplicates


def aggregate_prefixes(prefixes: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    return sorted(ipaddress.collapse_addresses(prefixes), key=network_sort_key)


def aggregate_all_asns(
    asn_data: list[ASNData], progress: ProgressReporter
) -> tuple[float, int, int]:
    started = time.monotonic()
    duplicates_removed = 0
    aggregated_total = 0
    total = len(asn_data)
    for index, data in enumerate(asn_data, start=1):
        phase_started = time.monotonic()
        progress.update(
            "AGGREGATE",
            f"ASN {index}/{total} AS{data.asn} | {len(data.prefixes)} prefixes",
            force=True,
        )
        unique_prefixes, duplicates = deduplicate_prefixes(data.prefixes)
        data.duplicates_removed = duplicates
        data.aggregated_prefixes = aggregate_prefixes(unique_prefixes)
        duplicates_removed += duplicates
        aggregated_total += len(data.aggregated_prefixes)
        reduction = 0.0
        if data.raw_prefix_count:
            reduction = 100.0 * (1.0 - (len(data.aggregated_prefixes) / data.raw_prefix_count))
        progress.milestone(
            "OK",
            f"AS{data.asn} | {data.raw_prefix_count} -> {len(data.aggregated_prefixes)} "
            f"prefixes | reduction: {reduction:.1f}% | time: {time.monotonic() - phase_started:.2f}s",
        )
    return time.monotonic() - started, duplicates_removed, aggregated_total


def merge_exact_moas(asn_data: list[ASNData]) -> tuple[dict[ipaddress.IPv4Network, list[Origin]], int]:
    merged: dict[ipaddress.IPv4Network, list[Origin]] = {}
    total_entries = 0
    for data in asn_data:
        for network in data.aggregated_prefixes:
            total_entries += 1
            origins = merged.setdefault(network, [])
            origin = Origin(data.asn, data.name)
            if origin not in origins:
                origins.append(origin)
    return merged, total_entries - len(merged)


def network_sort_key(network: ipaddress.IPv4Network) -> tuple[int, int]:
    return int(network.network_address), network.prefixlen


def build_route_lines(
    routes: dict[ipaddress.IPv4Network, list[Origin]], gateway: str
) -> list[str]:
    lines: list[str] = []
    for network in sorted(routes, key=network_sort_key):
        origins = sorted(routes[network], key=lambda item: item.asn)
        comment = ", ".join(f"AS{origin.asn}" for origin in origins)
        lines.append(
            f"route add {network.network_address} mask {network.netmask} {gateway} & rem {comment}"
        )
    return lines


def validate_output(lines: list[str], *, gateway: str, asn_data: list[ASNData]) -> None:
    if not lines:
        raise OutputValidationError("generated output contains no routes")
    if any(data.status == "failed" for data in asn_data):
        failed = ", ".join(f"AS{data.asn}" for data in asn_data if data.status == "failed")
        raise OutputValidationError(f"not all ASN were processed successfully: {failed}")

    seen_lines: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line or line.endswith("\r") or line.endswith("\n"):
            raise OutputValidationError(f"line {line_number}: invalid line ending/content")
        if line in seen_lines:
            raise OutputValidationError(f"duplicate route command at line {line_number}")
        seen_lines.add(line)
        match = ROUTE_LINE_RE.match(line)
        if not match:
            raise OutputValidationError(f"line {line_number}: invalid route format")
        if match.group("gateway") != gateway:
            raise OutputValidationError(f"line {line_number}: unexpected gateway")
        ipaddress.IPv4Address(match.group("network"))
        ipaddress.IPv4Address(match.group("mask"))


def split_route_lines(lines: list[str], max_lines: int) -> list[list[str]]:
    if max_lines <= 0:
        raise OutputValidationError("MAX_ROUTES_PER_FILE must be positive")
    return [lines[index : index + max_lines] for index in range(0, len(lines), max_lines)]


def split_output_filename(output_file: str, index: int) -> str:
    if index == 0:
        return output_file
    directory = os.path.dirname(output_file)
    basename = os.path.basename(output_file)
    stem, extension = os.path.splitext(basename)
    filename = f"{stem}({index}){extension}"
    return os.path.join(directory, filename) if directory else filename


def cleanup_stale_split_outputs(output_file: str, keep_count: int) -> None:
    directory = os.path.dirname(os.path.abspath(output_file)) or "."
    basename = os.path.basename(output_file)
    stem, extension = os.path.splitext(basename)
    pattern = re.compile(rf"^{re.escape(stem)}\((\d+)\){re.escape(extension)}$")
    for entry in os.listdir(directory):
        match = pattern.match(entry)
        if not match:
            continue
        index = int(match.group(1))
        if index >= keep_count:
            os.unlink(os.path.join(directory, entry))


def write_output_temp(lines: list[str], output_file: str) -> str:
    absolute_output = os.path.abspath(output_file)
    directory = os.path.dirname(absolute_output) or "."
    basename = os.path.basename(output_file)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=directory,
            prefix=f".{basename}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_name = handle.name
            for line in lines:
                handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return tmp_name
    except Exception:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
        raise


def write_outputs_atomic(
    chunks: list[list[str]], output_file: str, *, max_lines: int
) -> list[str]:
    outputs = [split_output_filename(output_file, index) for index in range(len(chunks))]
    temp_files: list[str] = []
    try:
        for index, chunk in enumerate(chunks):
            if len(chunk) > max_lines:
                raise OutputValidationError(
                    f"internal split error: output chunk {index} has more than {max_lines} lines"
                )
            temp_files.append(write_output_temp(chunk, outputs[index]))
        for temp_file, output in zip(temp_files, outputs):
            os.replace(temp_file, os.path.abspath(output))
        temp_files.clear()
        cleanup_stale_split_outputs(output_file, len(chunks))
        return outputs
    finally:
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except FileNotFoundError:
                pass


def validate_and_write_output(
    lines: list[str],
    output_file: str,
    *,
    gateway: str,
    asn_data: list[ASNData],
    max_lines: int = MAX_ROUTES_PER_FILE,
) -> list[str]:
    validate_output(lines, gateway=gateway, asn_data=asn_data)
    chunks = split_route_lines(lines, max_lines)
    return write_outputs_atomic(chunks, output_file, max_lines=max_lines)


def fetch_all_asns(
    asns: list[int], client: RISWhoisClient, progress: ProgressReporter
) -> tuple[list[ASNData], float]:
    started = time.monotonic()
    result: list[ASNData] = []
    total = len(asns)
    for index, asn in enumerate(asns, start=1):
        item_started = time.monotonic()
        data = ASNData(asn=asn)
        progress.update("FETCH", f"{index}/{total} AS{asn} | waiting...", force=True)
        try:
            text = client.query_ipv4_prefixes(asn, index, total)
            prefixes, invalid = normalize_prefixes(text, asn=asn)
            data.prefixes = prefixes
            data.raw_prefix_count = len(prefixes)
            data.invalid_prefixes = invalid
            data.name = sanitize_asn_name(client.query_as_name(asn, index, total))
            data.status = "empty" if not prefixes else "ok"
            if not prefixes:
                progress.milestone("OK", f"AS{asn}: 0 prefixes | time: {time.monotonic() - item_started:.1f}s")
            else:
                name_part = f" | name: {data.name}" if FETCH_ASN_NAMES else ""
                progress.milestone(
                    "OK",
                    f"AS{asn} | raw: {len(prefixes)}{name_part} "
                    f"| time: {time.monotonic() - item_started:.1f}s",
                )
        except (NetworkQueryError, ProtocolError, DataValidationError) as exc:
            data.status = "failed"
            data.error = str(exc)
            progress.error(f"failed to query AS{asn}: {exc}")
        result.append(data)
    return result, time.monotonic() - started


def print_summary(stats: RunStats, output_file: str, progress: ProgressReporter) -> None:
    reduction = 0.0
    if stats.raw_prefixes:
        reduction = 100.0 * (1.0 - (stats.final_routes / stats.raw_prefixes))
    progress.finish_line()
    print("=" * 60)
    print("Completed successfully")
    print()
    print(f"ASN requested:          {stats.asn_requested:8d}")
    print(f"ASN processed:          {stats.asn_processed:8d}")
    print(f"ASN without IPv4 routes:{stats.asn_without_ipv4_routes:8d}")
    print(f"ASN failed:             {stats.asn_failed:8d}")
    print()
    print(f"Raw prefixes:           {stats.raw_prefixes:8d}")
    print(f"Duplicates removed:     {stats.duplicates_removed:8d}")
    print(f"Aggregated prefixes:    {stats.aggregated_prefixes:8d}")
    print(f"MOAS duplicates merged: {stats.moas_duplicates_merged:8d}")
    print(f"Final routes:           {stats.final_routes:8d}")
    print()
    print(f"Reduction:              {reduction:7.1f}%")
    print()
    print(f"RIPE fetch time:        {stats.ripe_fetch_time:7.1f}s")
    print(f"Aggregation time:       {stats.aggregation_time:7.1f}s")
    print(f"Total time:             {stats.total_time:7.1f}s")
    print()
    print("Output:")
    for path in stats.output_files or [output_file]:
        print(path)
    print("=" * 60)


def run() -> int:
    progress = ProgressReporter()
    client: RISWhoisClient | None = None
    started = time.monotonic()
    try:
        asns = validate_config()
        stats = RunStats(asn_requested=len(asns))
        client = RISWhoisClient(RIPE_HOST, RIPE_PORT, progress=progress)
        client.connect()
        asn_data, fetch_time = fetch_all_asns(asns, client, progress)
        stats.ripe_fetch_time = fetch_time
        failed = [data for data in asn_data if data.status == "failed"]
        if failed:
            stats.asn_failed = len(failed)
            progress.error("one or more ASN failed; existing output file was not modified")
            return EXIT_NETWORK_FAILURE

        aggregation_time, duplicates, aggregated_total = aggregate_all_asns(asn_data, progress)
        progress.update("MOAS", "merging exact duplicate prefixes", force=True)
        route_map, moas_merged = merge_exact_moas(asn_data)
        progress.milestone("OK", f"MOAS exact duplicates merged: {moas_merged}")
        progress.update("SORT", "building route commands", force=True)
        lines = build_route_lines(route_map, GATEWAY)
        progress.update("WRITE", f"validating and writing {OUTPUT_FILE}", force=True)
        output_files = validate_and_write_output(lines, OUTPUT_FILE, gateway=GATEWAY, asn_data=asn_data)
        progress.milestone(
            "OK",
            f"Wrote {len(lines)} routes to {len(output_files)} file(s): {', '.join(output_files)}",
        )

        stats.asn_processed = sum(1 for data in asn_data if data.status in ("ok", "empty"))
        stats.asn_without_ipv4_routes = sum(1 for data in asn_data if data.status == "empty")
        stats.raw_prefixes = sum(data.raw_prefix_count for data in asn_data)
        stats.duplicates_removed = duplicates
        stats.aggregated_prefixes = aggregated_total
        stats.moas_duplicates_merged = moas_merged
        stats.final_routes = len(lines)
        stats.output_files = output_files
        stats.aggregation_time = aggregation_time
        stats.total_time = time.monotonic() - started
        print_summary(stats, OUTPUT_FILE, progress)
        return EXIT_SUCCESS
    except ConfigError as exc:
        progress.error(str(exc))
        return EXIT_CONFIG_ERROR
    except KeyboardInterrupt:
        progress.finish_line()
        print(f"Interrupted by user. Existing {OUTPUT_FILE} was not modified.")
        return EXIT_INTERRUPTED
    except OutputValidationError as exc:
        progress.error(f"output validation/write failure: {exc}")
        return EXIT_OUTPUT_FAILURE
    except NetworkQueryError as exc:
        progress.error(str(exc))
        return EXIT_NETWORK_FAILURE
    except Exception as exc:
        progress.error(str(exc))
        if DEBUG:
            traceback.print_exc()
        return EXIT_GENERAL_FAILURE
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    sys.exit(run())
