#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
FILE_LOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java"
FILE_UPLOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileUploadOperation.java"
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
WRAPPER_CPP = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    connections = text(CONNECTIONS_JAVA)
    proxy_list = text(PROXY_LIST)
    file_load = text(FILE_LOAD)
    file_upload = text(FILE_UPLOAD)
    shared_config = text(SHARED_CONFIG)
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)
    manager_cpp = text(MANAGER_CPP)
    manager_h = text(MANAGER_H)
    wrapper_cpp = text(WRAPPER_CPP)

    require(
        "MT_PROXY_TLS_PROFILE_AUTO_ROTATE" in connections,
        "ConnectionsManager must expose Auto rotate TLS profile mode",
    )
    require(
        "MtProxyTlsProfileAutoRotate" in proxy_list
        and "MT_PROXY_TLS_PROFILE_AUTO_ROTATE" in proxy_list,
        "proxy settings UI must expose Auto rotate as a selectable JA4 mode",
    )
    require(
        re.search(
            r"private static final int MT_PROXY_TLS_PROFILE_RANDOM_COUNT = 2;",
            connections,
        )
        and "return MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP;" not in connections,
        "stable Auto pool must exclude Android OkHttp until it is server-compatible",
    )
    require(
        "return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;" in connections
        and "return MT_PROXY_TLS_PROFILE_YANDEX;" in connections,
        "stable Auto pool must currently use Firefox Android and Yandex only",
    )
    require(
        "mtProxyTlsAutoRotateProfiles" in socket_cpp
        and "rotateMtProxyTlsProfileOnFailureIfNeeded" in socket_cpp
        and "currentEffectiveProxyTlsProfile" in socket_h,
        "native FakeTLS path must rotate effective JA4 profile on suspicious disconnect phases",
    )
    require(
        "client_hello_sent_no_server_hello" in socket_cpp
        and "server_hello_hmac_mismatch" in socket_cpp
        and "post_handshake_no_appdata" in socket_cpp
        and "tcp_connected_no_pong" in socket_cpp,
        "native rotation must be keyed by semantic diagnostic phases, not numeric errors",
    )
    require(
        "tcp_not_connected" in socket_cpp
        and "return false; // ClientHello was not sent, so JA4 did not cause this failure." in socket_cpp,
        "native rotation must not change JA4 for pre-TCP failures",
    )
    require(
        "getMtProxySoftMuxDownloadConnectionType" in connections
        and "getMtProxySoftMuxUploadConnectionType" in connections
        and "isMtProxySoftMuxEnabled" in connections,
        "ConnectionsManager must expose a runtime soft mux connection-slot policy for MTProxy",
    )
    require(
        "mtProxySoftMux" in shared_config
        and 'getBoolean("mtProxySoftMux", true)' in shared_config
        and 'putBoolean("mtProxySoftMux", mtProxySoftMux)' in shared_config,
        "SharedConfig must persist soft mux as an enabled-by-default runtime setting",
    )
    require(
        "mtProxySoftMuxRow" in proxy_list
        and "MtProxySoftMux" in proxy_list
        and "SharedConfig.mtProxySoftMux" in proxy_list,
        "proxy settings UI must expose a soft mux toggle",
    )
    require(
        "getMtProxySoftMuxDownloadConnectionType(i)" in file_load
        and "getMtProxySoftMuxDownloadConnectionType(requestsCount)" in file_load,
        "FileLoadOperation must use the MTProxy soft mux policy for download slots",
    )
    require(
        "getMtProxySoftMuxUploadConnectionType(requestNumFinal)" in file_upload,
        "FileUploadOperation must use the MTProxy soft mux policy for upload slots",
    )
    require(
        "mtProxyHandshakeAdmission" in shared_config
        and 'getBoolean("mtProxyHandshakeAdmission", false)' in shared_config
        and 'putBoolean("mtProxyHandshakeAdmission", mtProxyHandshakeAdmission)' in shared_config,
        "SharedConfig must persist admission-controller as a disabled-by-default runtime setting",
    )
    require(
        "mtProxyHandshakeAdmissionRow" in proxy_list
        and "MtProxyHandshakeAdmission" in proxy_list
        and "SharedConfig.mtProxyHandshakeAdmission" in proxy_list,
        "proxy settings UI must expose an admission-controller toggle",
    )
    require(
        "resolveMtProxyHandshakeAdmissionMode()" in connections
        and "mtProxyHandshakeAdmission" in connections
        and "native_setProxySettings(currentAccount, proxyAddress, proxyPort, proxyUsername, proxyPassword, proxySecret, mtProxyTlsProfile, mtProxyClientHelloFragmentation, mtProxyHandshakeAdmission, mtProxyRecordSizingMode, mtProxyTimingMode)" in connections,
        "Java must pass the runtime admission-controller setting into native proxy settings",
    )
    require(
        'native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIII)V"' in wrapper_cpp
        and 'native_checkProxy", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIIILorg/telegram/tgnet/RequestTimeDelegate;)J"' in wrapper_cpp,
        "JNI signatures must carry the admission-controller integer",
    )
    require(
        "int32_t proxyHandshakeAdmission = 0" in manager_h
        and "handshakeAdmissionChanged" in manager_cpp
        and "proxyHandshakeAdmission = normalizeMtProxyHandshakeAdmission" in manager_cpp,
        "native ConnectionsManager must store admission-controller runtime state and reconnect when it changes",
    )
    require(
        "MT_PROXY_HANDSHAKE_ADMISSION_ENABLED" not in socket_cpp
        and "proxyHandshakeAdmission == 0" in socket_cpp
        and "admission_disabled" in socket_cpp,
        "ConnectionSocket must use runtime admission state instead of a compile-time disabled flag",
    )
    require(
        "if (ConnectionsManager::getInstance(instanceNum).proxyHandshakeAdmission != 0) {\n        hasNextRequest = mtProxyTakeNextQueuedRequestLocked" in socket_cpp,
        "ConnectionSocket must not grant queued admission requests after the runtime gate is disabled",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        require(
            'name="MtProxyTlsProfileAutoRotate"' in source,
            f"{path.name} must define MtProxyTlsProfileAutoRotate",
        )
        require(
            'name="MtProxySoftMux"' in source
            and 'name="MtProxySoftMuxInfo"' in source
            and 'name="MtProxyHandshakeAdmission"' in source
            and 'name="MtProxyHandshakeAdmissionInfo"' in source,
            f"{path.name} must define soft mux and admission-controller strings",
        )

    print("MTProxy rotation and soft mux guard passed.")


if __name__ == "__main__":
    main()
