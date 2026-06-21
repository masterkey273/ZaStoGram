#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "diagnostics": ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckDiagnostics.java",
    "connections_java": ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java",
    "notification_center": ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/NotificationCenter.java",
    "proxy_list": ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java",
    "values": ROOT / "TMessagesProj/src/main/res/values/strings.xml",
    "values_ru": ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml",
    "defines": ROOT / "TMessagesProj/jni/tgnet/Defines.h",
    "wrapper": ROOT / "TMessagesProj/jni/TgNetWrapper.cpp",
    "socket": ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp",
    "socket_h": ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h",
    "collector": ROOT / "Tools/collect_mtproxy_logs.ps1",
}

LIVE_PHASES = [
    "admission_queue",
    "host_resolve_start",
    "connect_start",
    "socket_connect_start",
    "socket_connected",
    "client_hello_sent",
    "admission_hold_after_client_hello_failure",
    "server_hello_hmac_ok",
    "on_connected",
    "first_tls_app_sent",
    "first_tls_app_recv",
    "first_mtproxy_packet_sent",
    "first_mtproxy_packet_recv",
]


def text(name: str) -> str:
    return FILES[name].read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    diagnostics = text("diagnostics")
    combined = "\n".join(text(name) for name in FILES)

    for phase in LIVE_PHASES:
        require(phase in diagnostics, f"ProxyCheckDiagnostics must define live phase '{phase}'")
        require(phase in text("socket") or phase in text("connections_java"), f"live phase '{phase}' must be emitted or consumed")
    for phase in sorted(set(re.findall(r'publishProxyConnectionStage\("([^"]+)"\)', text("socket")))):
        require(phase in diagnostics, f"native published phase '{phase}' must be present in ProxyCheckDiagnostics for GUI rendering")

    require(
        "isLivePhase" in diagnostics
        and "hasFreshLivePhase" in diagnostics
        and "ProxyStatusHostResolve" in diagnostics
        and "ProxyStatusClientHelloSent" in diagnostics
        and "ProxyStatusServerHelloOk" in diagnostics,
        "ProxyCheckDiagnostics must map live native stages to user-facing status text",
    )
    header_idx = diagnostics.find("public static String headerStatusText")
    header_checking_idx = diagnostics.find("if (proxyInfo.checking)", header_idx)
    header_live_idx = diagnostics.find("if (hasFreshLivePhase(proxyInfo))", header_idx)
    require(
        header_idx >= 0
        and header_live_idx >= 0
        and header_checking_idx >= 0
        and header_live_idx < header_checking_idx,
        "proxy window header must show fresh live stages before generic checking text",
    )
    status_idx = diagnostics.find("public static String statusText")
    status_live_idx = diagnostics.find("if (hasFreshLivePhase(proxyInfo))", status_idx)
    status_failure_idx = diagnostics.find("if (hasFreshFailure(proxyInfo))", status_idx)
    status_connected_idx = diagnostics.find("currentConnectionState == ConnectionsManager.ConnectionStateConnected", status_idx)
    status_connecting_idx = diagnostics.find("currentConnectionState == ConnectionsManager.ConnectionStateConnectingToProxy", status_idx)
    header_failure_idx = diagnostics.find("if (hasFreshFailure(proxyInfo))", header_idx)
    header_connected_idx = diagnostics.find("currentConnectionState == ConnectionsManager.ConnectionStateConnected", header_idx)
    header_connecting_idx = diagnostics.find("currentConnectionState == ConnectionsManager.ConnectionStateConnectingToProxy", header_idx)
    require(
        status_idx >= 0
        and status_live_idx >= 0
        and status_failure_idx >= 0
        and status_failure_idx < status_live_idx
        and header_failure_idx < header_live_idx,
        "current proxy terminal failures must override live stages in row and header text",
    )
    require(
        status_failure_idx >= 0
        and status_connected_idx >= 0
        and status_failure_idx < status_connected_idx
        and header_failure_idx >= 0
        and header_connected_idx >= 0
        and header_failure_idx < header_connected_idx,
        "fresh terminal failures must override generic Connected text, otherwise the GUI can show connected while the proxy data path is failing",
    )
    require(
        status_failure_idx >= 0
        and status_connecting_idx >= 0
        and status_failure_idx < status_connecting_idx
        and header_failure_idx >= 0
        and header_connecting_idx >= 0
        and header_failure_idx < header_connecting_idx,
        "fresh terminal failures must render before generic ConnectionStateConnectingToProxy text, otherwise the UI shows red 'waiting TCP'",
    )
    color_idx = diagnostics.find("public static int statusColorKey")
    color_failure_idx = diagnostics.find("if (hasFreshFailure(proxyInfo))", color_idx)
    color_connected_idx = diagnostics.find("currentConnectionState == ConnectionsManager.ConnectionStateConnected", color_idx)
    require(
        color_idx >= 0
        and color_failure_idx >= 0
        and color_connected_idx >= 0
        and color_failure_idx < color_connected_idx,
        "current proxy terminal failures must color the row as failure before generic connected blue",
    )
    has_failure_idx = diagnostics.find("public static boolean hasFreshFailure")
    has_failure_body = diagnostics[has_failure_idx:diagnostics.find("public static String statusText", has_failure_idx)]
    require(
        "lastCheckDiagnosticTime" in has_failure_body
        and "isFailure(proxyInfo.lastCheckDiagnostic)" in has_failure_body,
        "fresh failure phases must use diagnostic timestamp, not only proxy-check availability timestamp",
    )
    require(
        "ProxyCheckDiagnostics.isFailure(normalizedDiagnostic)" in text("connections_java")
        and "!ProxyCheckDiagnostics.UNKNOWN_FAIL.equals(normalizedDiagnostic)" in text("connections_java"),
        "current proxy stage callback must accept concrete failure phases while rejecting unknown_fail noise",
    )
    require(
        "shouldKeepFreshFailure" in diagnostics
        and "isEarlyRetryPhase" in diagnostics
        and "ProxyCheckDiagnostics.shouldKeepFreshFailure(currentProxy, normalizedDiagnostic)" in text("connections_java"),
        "fresh terminal failures must not be overwritten by early retry phases such as admission_queue or host_resolve_start",
    )
    require(
        "isProxyUsableSuccessPhase" in diagnostics
        and "SERVER_HELLO_HMAC_OK" in diagnostics
        and "FIRST_TLS_APP_RECV" in diagnostics
        and "FIRST_MTPROXY_PACKET_RECV" in diagnostics,
        "ProxyCheckDiagnostics must define concrete success phases that prove a proxy is usable again",
    )
    require(
        "ProxyCheckDiagnostics.isProxyUsableSuccessPhase(normalizedDiagnostic)" in text("connections_java")
        and "ProxyCheckScheduler.markConnectionUsable(currentProxy, normalizedDiagnostic)" in text("connections_java"),
        "concrete success phases from native must clear stale Java endpoint backoff and fresh terminal failures",
    )
    require(
        "proxyConnectionStageChanged" in text("notification_center")
        and "onProxyConnectionStageChanged" in text("connections_java")
        and "NotificationCenter.proxyConnectionStageChanged" in text("connections_java"),
        "Java must expose a NotificationCenter event for current proxy live stages",
    )
    require(
        "NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyConnectionStageChanged" in text("connections_java"),
        "proxy live stages must also be posted globally because SharedConfig.currentProxy is global across accounts",
    )
    require(
        "onProxyConnectionStageChanged" in text("defines")
        and "jclass_ConnectionsManager_onProxyConnectionStageChanged" in text("wrapper")
        and 'GetStaticMethodID(jclass_ConnectionsManager, "onProxyConnectionStageChanged", "(ILjava/lang/String;)V")' in text("wrapper"),
        "JNI bridge must forward native proxy live stages to ConnectionsManager",
    )
    require(
        "publishProxyConnectionStage" in text("socket_h")
        and "publishProxyConnectionStage(" in text("socket")
        and "isCurrentMtProxyConnection()" in text("socket_h")
        and "markMtProxyFirstPlainDataSent" in text("socket_h")
        and "markMtProxyFirstPlainDataReceived" in text("socket_h")
        and "void ConnectionSocket::markMtProxyFirstPlainDataSent" in text("socket")
        and "void ConnectionSocket::markMtProxyFirstPlainDataReceived" in text("socket")
        and "!isCurrentMtProxyConnection()" in text("socket")
        and "!overrideProxyAddress.empty()" in text("socket")
        and 'publishProxyConnectionStage("host_resolve_start")' in text("socket")
        and 'proxyCheckDiagnostic = "host_resolve_failed"' in text("socket")
        and 'publishProxyConnectionStage("client_hello_sent")' in text("socket")
        and 'publishProxyConnectionStage("admission_hold_after_client_hello_failure")' in text("socket")
        and 'publishProxyConnectionStage("server_hello_hmac_ok")' in text("socket")
        and 'publishProxyConnectionStage("first_tls_app_recv")' in text("socket"),
        "ConnectionSocket must publish live stages for plain dd/legacy MTProxy too, not only FakeTLS ee",
    )
    require(
        "publishProxyConnectionStage(proxyCheckDiagnostic.c_str())" in text("socket"),
        "ConnectionSocket must publish a concrete terminal diagnostic on failed current-proxy disconnects",
    )
    require(
        "NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxyConnectionStageChanged)" in text("proxy_list")
        and "NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.proxyConnectionStageChanged)" in text("proxy_list")
        and "NotificationCenter.getInstance(currentAccount).addObserver(this, NotificationCenter.proxyConnectionStageChanged)" not in text("proxy_list")
        and "NotificationCenter.getInstance(currentAccount).removeObserver(this, NotificationCenter.proxyConnectionStageChanged)" not in text("proxy_list")
        and "id == NotificationCenter.proxyConnectionStageChanged" in text("proxy_list"),
        "Proxy list must refresh header and current row on global live proxy stage updates from any account",
    )
    require(
        "proxy_connection_stage" in text("collector"),
        "live Java proxy stages must be collected into mtproxy marker logs",
    )
    for name in ("values", "values_ru"):
        source = text(name)
        for string_name in (
            "ProxyStatusAdmissionQueue",
            "ProxyStatusHostResolve",
            "ProxyStatusHostResolveFailed",
            "ProxyStatusTcpConnecting",
            "ProxyStatusTcpConnected",
            "ProxyStatusClientHelloSent",
            "ProxyStatusAdmissionHoldAfterClientHelloFailure",
            "ProxyStatusServerHelloOk",
            "ProxyStatusMtprotoStarting",
            "ProxyStatusFirstDataSent",
            "ProxyStatusFirstDataReceived",
            "ProxyStatusFirstMtproxyPacketSent",
            "ProxyStatusFirstMtproxyPacketReceived",
        ):
            require(f'name="{string_name}"' in source, f"{name} must define {string_name}")

    print("Proxy live connection stages guard passed.")


if __name__ == "__main__":
    main()
