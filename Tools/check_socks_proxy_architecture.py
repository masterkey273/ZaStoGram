#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
PROXY_SETTINGS = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxySettingsActivity.java"
MINI_BRIDGE = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/WssMiniAppProxyBridge.java"
WSS_CPP = ROOT / "TMessagesProj/jni/tgnet/WssTransport.cpp"
WSS_H = ROOT / "TMessagesProj/jni/tgnet/WssTransport.h"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    shared_config = text(SHARED_CONFIG)
    connections = text(CONNECTIONS)
    proxy_list = text(PROXY_LIST)
    proxy_settings = text(PROXY_SETTINGS)
    mini_bridge = text(MINI_BRIDGE)
    wss_cpp = text(WSS_CPP)
    wss_h = text(WSS_H)

    require("currentWssSocksProxy" in shared_config, "SharedConfig must keep WSS SOCKS upstream separate from the legacy currentProxy")
    require("wss_socks_proxy_ip" in shared_config and "saveWssSocksProxy" in shared_config and "clearWssSocksProxy" in shared_config, "WSS SOCKS upstream selection must have its own persisted keys")
    require("if (currentWssSocksProxy == proxyInfo)" in shared_config and "clearWssSocksProxy()" in shared_config, "deleting a SOCKS proxy must also clear the WSS upstream selection")

    resolve_section = connections.split("private static WssSocksProxy resolveWssSocksProxy", 1)[1].split("public static void setWssTransportSettings", 1)[0]
    require("SharedConfig.currentWssSocksProxy" in resolve_section, "WSS native settings must read the WSS upstream selection, not the legacy currentProxy")
    require("SharedConfig.currentProxy" not in resolve_section, "WSS upstream resolver must not depend on legacy currentProxy")

    require("isProxySelectedForCurrentMode" in proxy_list and "isProxyActiveForCurrentMode" in proxy_list, "proxy list rows must render normal SOCKS and WSS upstream selection independently")
    require("saveSelectedWssSocksProxy" in proxy_list, "clicking a SOCKS row in WSS mode must save a WSS upstream, not a legacy proxy")
    require("SharedConfig.currentWssSocksProxy == info" in proxy_list, "WSS SOCKS row toggling must compare against the WSS upstream selection")
    require("SharedConfig.currentProxy == info" in proxy_list, "normal SOCKS row selection must still use the legacy currentProxy")

    clear_section = proxy_list.split("private void clearSelectedWssSocksProxy", 1)[1].split("private int getWssTransportModeIndex", 1)[0]
    require("SharedConfig.clearWssSocksProxy()" in clear_section, "clearing WSS SOCKS must clear only the WSS upstream selection")
    require('"proxy_ip"' not in clear_section and "ConnectionsManager.setProxySettings(false" not in clear_section, "clearing WSS SOCKS must not erase or disable the normal SOCKS proxy")

    save_wss_section = proxy_settings.split("boolean saveForWssSocksUpstream", 1)[1].split("NotificationCenter.getGlobalInstance().postNotificationName", 1)[0]
    require("SharedConfig.saveWssSocksProxy(currentProxyInfo)" in save_wss_section, "WSS SOCKS editor must save the WSS upstream selection")
    require("SharedConfig.currentProxy = currentProxyInfo" not in save_wss_section.split("if (saveForWssSocksUpstream)", 1)[1].split("} else", 1)[0], "WSS SOCKS editor must not select the legacy proxy")

    selected_socks_section = mini_bridge.split("private static SocksProxyConfig selectedSocksProxy()", 1)[1].split("public static int ensureStarted()", 1)[0]
    require("SharedConfig.currentWssSocksProxy" in selected_socks_section, "miniapp bridge must reuse the WSS SOCKS upstream selection")
    require("SharedConfig.currentProxy" not in selected_socks_section, "miniapp bridge must not read the legacy proxy selection for WSS SOCKS")

    require("TcpSocksGreetingWrite" in wss_h and "TcpSocksConnectRead" in wss_h, "WSS transport must keep a TCP SOCKS5 handshake before TLS/WebSocket")
    require("wss_tcp_socks connect_ok" in wss_cpp and "State::TlsHandshake" in wss_cpp, "WSS TCP SOCKS5 path must switch to TLS only after SOCKS CONNECT succeeds")

    print("SOCKS proxy architecture guard passed.")


if __name__ == "__main__":
    main()
