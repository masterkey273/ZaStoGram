#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
MTPROXY_ALL = ROOT / "Tools/check_mtproxy_all.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    brace = text.find("{", start)
    if brace == -1:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def main() -> int:
    failures: list[str] = []
    connections = read(CONNECTIONS)
    mtproxy_all = read(MTPROXY_ALL)
    resolver_class = method_body(connections, "private static class ResolveHostByNameTask")
    resolver_body = method_body(resolver_class, "protected ResolvedDomain doInBackground")

    require("import java.io.FileNotFoundException;" in connections, "resolver must import FileNotFoundException for controlled DoH fallback", failures)
    require("import java.net.UnknownHostException;" in connections, "resolver must import UnknownHostException for controlled DNS fallback", failures)
    require(
        "private static final String DOH_USER_AGENT" in connections
        and "Android 10; K" in connections
        and "Chrome/" in connections
        and "iPhone OS 10_0" not in connections,
        "DoH requests must use a shared modern Android Chrome user-agent, not the old iPhone Safari UA",
        failures,
    )
    require(
        "private static URLConnection openDohJsonConnection" in connections
        and 'addRequestProperty("User-Agent", DOH_USER_AGENT)' in connections
        and 'addRequestProperty("accept", "application/dns-json")' in connections
        and "setConnectTimeout(connectTimeout)" in connections
        and "setReadTimeout(readTimeout)" in connections,
        "ConnectionsManager must centralize JSON DoH connection headers and timeouts",
        failures,
    )
    require(
        'addRequestProperty("User-Agent",' not in connections.replace('addRequestProperty("User-Agent", DOH_USER_AGENT)', "")
        and 'addRequestProperty("accept",' not in connections.replace('addRequestProperty("accept", "application/dns-json")', ""),
        "DoH tasks must not configure User-Agent/accept headers outside the shared helper",
        failures,
    )
    require(
        "private static String randomDohPadding()" in connections
        and "private static NativeByteBuffer parseDnsTxtConfig" in connections,
        "TXT DoH tasks must share padding generation and JSON TXT config parsing",
        failures,
    )
    require(
        "private static final String[] HOST_RESOLVER_DOH_ENDPOINTS" in connections
        and '"https://cloudflare-dns.com/dns-query?name="' in connections
        and '"https://dns.google.com/resolve?name="' in connections,
        "host resolver must try more than one JSON DoH provider instead of depending on Google only",
        failures,
    )
    require(
        "for (String dohEndpoint : HOST_RESOLVER_DOH_ENDPOINTS)" in resolver_body
        and 'openDohJsonConnection(dohEndpoint + currentHostName + "&type=A", 1000, 2000)' in resolver_body,
        "host resolver must iterate through the configured DoH provider chain",
        failures,
    )
    require(
        "https://www.google.com/resolve" not in resolver_body,
        "host resolver DoH URL must not use www.google.com with a mismatched Host header",
        failures,
    )
    require(
        'addRequestProperty("Host", "dns.google.com")' not in resolver_body,
        "host resolver must not spoof Host: dns.google.com over a www.google.com URL",
        failures,
    )
    controlled_doh_idx = resolver_body.find("catch (FileNotFoundException | UnknownHostException")
    unexpected_idx = resolver_body.find("catch (Throwable e)", controlled_doh_idx + 1)
    fallback_idx = resolver_body.find("InetAddress.getByName(currentHostName)")
    require(
        controlled_doh_idx >= 0
        and unexpected_idx >= 0
        and fallback_idx >= 0
        and controlled_doh_idx < unexpected_idx < fallback_idx,
        "DoH FileNotFoundException/UnknownHostException must be a controlled fallback before InetAddress",
        failures,
    )
    controlled_doh = resolver_body[controlled_doh_idx:unexpected_idx]
    require(
        'logDohExpectedFailure("host_resolver", currentHostName, dohEndpoint, e)' in controlled_doh,
        "controlled DoH failures must be logged as debug without a stacktrace",
        failures,
    )
    require(
        'openDohJsonConnection(dohEndpoint + currentHostName + "&type=A", 1000, 2000)' in resolver_body,
        "host resolver DoH requests must use the shared UA and request JSON DNS explicitly",
        failures,
    )
    unexpected_doh = resolver_body[unexpected_idx:fallback_idx]
    require(
        "FileLog.e(e, false)" in unexpected_doh,
        "unexpected DoH failures must still use FileLog.e(e, false)",
        failures,
    )
    fallback_body = resolver_body[fallback_idx:]
    require(
        "catch (UnknownHostException e)" in fallback_body
        and 'FileLog.d("dns inet fallback failed host=" + currentHostName + " reason=" + e.getClass().getSimpleName())' in fallback_body,
        "InetAddress UnknownHostException should be controlled DNS fallback noise, not a stacktrace",
        failures,
    )
    require(
        '"check_dns_resolver_fallback.py"' in mtproxy_all,
        "full MTProxy guard suite must include DNS resolver fallback guard",
        failures,
    )

    for class_name in ("GoogleDnsLoadTask", "MozillaDnsLoadTask"):
        task = method_body(connections, f"private static class {class_name}")
        require(
            "openDohJsonConnection(" in task
            and "openConnection()" not in task
            and "addRequestProperty(" not in task,
            f"{class_name} must use the shared JSON DoH helper instead of hand-rolled request setup",
            failures,
        )
        require(
            "catch (FileNotFoundException | UnknownHostException" in task
            and "logDohExpectedFailure(" in task,
            f"{class_name} must treat expected DoH provider failures as debug fallback noise",
            failures,
        )

    if failures:
        print("DNS resolver fallback guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("DNS resolver fallback guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
