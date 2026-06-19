#!/usr/bin/env python3
"""Summarize MTProxy FakeTLS lifecycle markers from collect_mtproxy_logs.ps1.

The analyzer is intentionally conservative: it does not try to prove DPI by
itself. It groups log markers by ConnectionSocket pointer and shows the exact
phase where each attempt stopped, so VPN/non-VPN captures can be compared.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


CONNECTION_RE = re.compile(r"connection\(([^)]+)\)")
PROFILE_RE = re.compile(r"profile selected=([a-z_]+)")
CONNECT_RE = re.compile(r"connect_start .*profile=([a-z_]+).*address=([^ ]+) port=([0-9]+)")
DISCONNECT_RE = re.compile(
    r"mtproxy_disconnect reason=([-0-9]+) error=([-0-9]+) "
    r"proxy_state=([-0-9]+) tls_state=([-0-9]+) bytes_read=([0-9]+)"
)


@dataclass
class Attempt:
    key: str
    first_line: int = 0
    last_line: int = 0
    lines: list[str] = field(default_factory=list)
    events: Counter[str] = field(default_factory=Counter)
    profile: str = ""
    address: str = ""
    port: str = ""
    disconnect: str = ""

    def add(self, line_no: int, text: str) -> None:
        if not self.first_line:
            self.first_line = line_no
        self.last_line = line_no
        self.lines.append(text)

        connect = CONNECT_RE.search(text)
        if connect:
            self.profile = connect.group(1)
            self.address = connect.group(2)
            self.port = connect.group(3)

        profile = PROFILE_RE.search(text)
        if profile:
            self.profile = profile.group(1)

        disconnect = DISCONNECT_RE.search(text)
        if disconnect:
            self.disconnect = (
                f"reason={disconnect.group(1)} error={disconnect.group(2)} "
                f"proxy_state={disconnect.group(3)} tls_state={disconnect.group(4)} "
                f"bytes_read={disconnect.group(5)}"
            )

        event_map = {
            "connect_start": "connect_start",
            "socket_connect_start": "socket_connect_start",
            "socket_connected": "socket_connected",
            "client_hello_send_progress": "client_hello_send_progress",
            "client_hello_sent": "client_hello_sent",
            "server_hello_hmac_ok": "server_hello_hmac_ok",
            "server_hello_hmac_timeout": "server_hello_hmac_timeout",
            "server_hello_timeout_close": "server_hello_timeout_close",
            "TLS server hello hmac wait": "server_hello_hmac_wait",
            "admission_freeze_detected": "admission_freeze_detected",
            "on_connected": "on_connected",
            "first_tls_app_sent": "first_tls_app_sent",
            "first_tls_app_recv": "first_tls_app_recv",
            "tls_alert": "tls_alert",
            "recv_eof": "recv_eof",
            "EPOLLHUP": "epoll_hup",
            "EPOLLRDHUP": "epoll_rdhup",
            "socket error": "socket_error",
            "TLS response version mismatch": "tls_response_version_mismatch",
            "TLS response record type mismatch": "tls_response_record_type_mismatch",
        }
        for needle, event in event_map.items():
            if needle in text:
                self.events[event] += 1

    def verdict(self) -> str:
        has = self.events.__contains__
        if not has("socket_connected"):
            return "tcp_not_connected_or_not_reached"
        if not has("client_hello_sent"):
            return "connected_but_client_hello_not_fully_sent"
        if not has("server_hello_hmac_ok"):
            if has("server_hello_hmac_timeout") or has("server_hello_hmac_wait"):
                return "server_hello_hmac_mismatch_or_incompatible_profile"
            if has("server_hello_timeout_close") or has("admission_freeze_detected"):
                return "no_valid_server_hello_after_client_hello"
            if has("recv_eof"):
                return "peer_closed_after_client_hello"
            return "client_hello_sent_but_no_hmac_ok"
        if not has("on_connected"):
            return "hmac_ok_but_on_connected_not_reached"
        if has("first_tls_app_sent") and not has("first_tls_app_recv"):
            return "post_handshake_no_server_appdata"
        if has("first_tls_app_recv") and self.disconnect:
            return "connected_then_dropped_later"
        if has("first_tls_app_recv"):
            return "connected_and_received_appdata"
        return "connected_waiting_for_first_appdata"


def marker_text(line: str) -> tuple[int, str]:
    # collect_mtproxy_logs.ps1 writes: path:line_number: original log line
    match = re.match(r"^.*?:([0-9]+):\s*(.*)$", line.rstrip("\n"))
    if match:
        return int(match.group(1)), match.group(2)
    return 0, line.rstrip("\n")


def load_attempts(path: Path) -> tuple[list[Attempt], list[str]]:
    attempts: dict[str, Attempt] = {}
    global_lines: list[str] = []
    sequence_by_key: defaultdict[str, int] = defaultdict(int)

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip() == "No MTProxy markers found.":
            continue
        line_no, text = marker_text(raw)
        connection = CONNECTION_RE.search(text)
        if not connection:
            global_lines.append(text)
            continue

        pointer = connection.group(1)
        key = pointer
        if "connect_start" in text and pointer in attempts and attempts[pointer].events["connect_start"]:
            sequence_by_key[pointer] += 1
            key = f"{pointer}#{sequence_by_key[pointer]}"

        attempt = attempts.get(key)
        if attempt is None:
            attempt = Attempt(key=key)
            attempts[key] = attempt
        attempt.add(line_no, text)

    return sorted(attempts.values(), key=lambda item: (item.first_line, item.key)), global_lines


def print_report(attempts: list[Attempt], global_lines: list[str]) -> None:
    print("MTProxy FakeTLS diagnostic summary")
    print("===================================")
    if not attempts and not global_lines:
        print("No MTProxy markers found.")
        print("Most likely causes: APK was built without LOGS_ENABLED, wrong package was captured, or the MTProxy path was not exercised.")
        return

    verdicts = Counter(attempt.verdict() for attempt in attempts)
    profiles = Counter(attempt.profile or "unknown" for attempt in attempts)
    print(f"Attempts: {len(attempts)}")
    print("Verdicts:")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict}: {count}")
    print("Profiles:")
    for profile, count in profiles.most_common():
        print(f"  {profile}: {count}")

    if global_lines:
        print(f"Global/non-connection markers: {len(global_lines)}")

    print()
    print("Per-attempt details:")
    for attempt in attempts:
        endpoint = ""
        if attempt.address:
            endpoint = f" {attempt.address}:{attempt.port}"
        flags = ",".join(sorted(attempt.events)) or "no_known_phase"
        print(f"- {attempt.key}{endpoint} profile={attempt.profile or 'unknown'} verdict={attempt.verdict()}")
        print(f"  lines={attempt.first_line}-{attempt.last_line} events={flags}")
        if attempt.disconnect:
            print(f"  disconnect={attempt.disconnect}")

    print()
    print("How to read the verdicts:")
    print("- tcp_not_connected_or_not_reached: TCP/connect/IP/proxy availability layer.")
    print("- no_valid_server_hello_after_client_hello: compare VPN vs non-VPN; with VPN failure points to server/client compatibility, without VPN it can be DPI blackhole.")
    print("- server_hello_hmac_mismatch_or_incompatible_profile: likely ClientHello/profile/server response mismatch, not plain packet loss.")
    print("- post_handshake_no_server_appdata: HMAC passed; inspect TLS app-data write/read path and first MTProto packets.")
    print("- connected_then_dropped_later: startup worked; look at later MTProto keepalive, server close, or external throttling.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("markers", type=Path, help="Path to mtproxy_markers.txt")
    args = parser.parse_args()

    if not args.markers.exists():
        raise SystemExit(f"markers file not found: {args.markers}")

    attempts, global_lines = load_attempts(args.markers)
    print_report(attempts, global_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
