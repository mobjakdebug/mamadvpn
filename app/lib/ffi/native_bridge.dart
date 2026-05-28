import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

/// FFI bindings to the MamadVPN Rust C API (mamadvpn_api).
///
/// On Android, the native library is loaded from the APK lib directory.
/// On desktop (dev/testing), it's loaded from the build output.
class MamadVPNFFI {
  static MamadVPNFFI? _instance;

  late final DynamicLibrary _lib;
  late final int Function(Pointer<Utf8>) _nativeInit;
  late final int Function() _nativeStart;
  late final int Function() _nativeStop;
  late final void Function() _nativeShutdown;
  late final int Function(Pointer<Utf8>) _nativeUpdateConfig;
  late final int Function(Pointer<Utf8>, Pointer<Utf8>, int) _nativeParseTrojanUrl;
  late final int Function(Pointer<NativeStats>) _nativeGetStats;
  late final int Function(Pointer<Utf8>, int) _nativeGetStatus;
  late final int Function(Pointer<Utf8>, int) _nativeGetLogs;
  late final int Function() _nativeClearLogs;
  late final int Function(int) _nativeSetTunFd;

  MamadVPNFFI._() {
    _lib = _loadLibrary();
    _nativeInit = _lib.lookupFunction<
        Int32 Function(Pointer<Utf8>),
        int Function(Pointer<Utf8>)>('mamadvpn_init');
    _nativeStart = _lib.lookupFunction<Int32 Function(), int Function()>(
        'mamadvpn_start');
    _nativeStop = _lib.lookupFunction<Int32 Function(), int Function()>(
        'mamadvpn_stop');
    _nativeShutdown = _lib.lookupFunction<Void Function(), void Function()>(
        'mamadvpn_shutdown');
    _nativeUpdateConfig = _lib.lookupFunction<
        Int32 Function(Pointer<Utf8>),
        int Function(Pointer<Utf8>)>('mamadvpn_update_config');
    _nativeParseTrojanUrl = _lib.lookupFunction<
        Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Int32),
        int Function(Pointer<Utf8>, Pointer<Utf8>, int)>(
        'mamadvpn_parse_trojan_url');
    _nativeGetStats = _lib.lookupFunction<
        Int32 Function(Pointer<NativeStats>),
        int Function(Pointer<NativeStats>)>('mamadvpn_get_stats');
    _nativeGetStatus = _lib.lookupFunction<
        Int32 Function(Pointer<Utf8>, Int32),
        int Function(Pointer<Utf8>, int)>('mamadvpn_get_status');
    _nativeGetLogs = _lib.lookupFunction<
        Int32 Function(Pointer<Utf8>, Int32),
        int Function(Pointer<Utf8>, int)>('mamadvpn_get_logs');
    _nativeClearLogs =
        _lib.lookupFunction<Int32 Function(), int Function()>(
            'mamadvpn_clear_logs');
    _nativeSetTunFd = _lib.lookupFunction<Int32 Function(Int32), int Function(int)>(
        'mamadvpn_set_tun_fd');
  }

  static MamadVPNFFI get instance {
    _instance ??= MamadVPNFFI._();
    return _instance!;
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libmamadvpn_api.so');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libmamadvpn_api.so');
    } else if (Platform.isMacOS) {
      return DynamicLibrary.open('libmamadvpn_api.dylib');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('mamadvpn_api.dll');
    }
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }

  // ── Lifecycle ─────────────────────────────────────────────────

  /// Initialize the engine with a JSON config string.
  /// Returns 0 on success, -1 on failure.
  int init(String configJson) {
    final ptr = configJson.toNativeUtf8();
    try {
      return _nativeInit(ptr);
    } finally {
      calloc.free(ptr);
    }
  }

  /// Start the engine.
  int start() => _nativeStart();

  /// Stop the engine gracefully.
  int stop() => _nativeStop();

  /// Full shutdown — releases all resources.
  void shutdown() => _nativeShutdown();

  // ── Configuration ──────────────────────────────────────────────

  /// Update config at runtime.
  int updateConfig(String configJson) {
    final ptr = configJson.toNativeUtf8();
    try {
      return _nativeUpdateConfig(ptr);
    } finally {
      calloc.free(ptr);
    }
  }

  /// Parse a Trojan URL and return the config JSON.
  String? parseTrojanUrl(String url) {
    final urlPtr = url.toNativeUtf8();
    final outBuf = calloc<Utf8>(4096);
    try {
      final len = _nativeParseTrojanUrl(urlPtr, outBuf, 4096);
      if (len < 0) return null;
      return outBuf.toDartString();
    } finally {
      calloc.free(urlPtr);
      calloc.free(outBuf);
    }
  }

  // ── Stats & Status ─────────────────────────────────────────────

  /// Get engine stats.
  NativeStats? getStats() {
    final ptr = calloc<NativeStats>();
    try {
      final result = _nativeGetStats(ptr);
      if (result < 0) return null;
      return ptr.ref;
    } finally {
      calloc.free(ptr);
    }
  }

  /// Get engine status as JSON.
  String? getStatus() {
    final outBuf = calloc<Utf8>(1024);
    try {
      final len = _nativeGetStatus(outBuf, 1024);
      if (len < 0) return null;
      return outBuf.toDartString();
    } finally {
      calloc.free(outBuf);
    }
  }

  // ── Logs ───────────────────────────────────────────────────────

  /// Get recent logs as a JSON array string.
  String? getLogs() {
    final outBuf = calloc<Utf8>(16384);
    try {
      final len = _nativeGetLogs(outBuf, 16384);
      if (len < 0) return null;
      return outBuf.toDartString();
    } finally {
      calloc.free(outBuf);
    }
  }

  /// Clear log buffer.
  int clearLogs() => _nativeClearLogs();

  // ── Platform (TUN) ─────────────────────────────────────────────

  /// Set the TUN file descriptor from Android's VpnService.
  int setTunFd(int fd) => _nativeSetTunFd(fd);
}

/// FFI-safe stats struct mirroring Rust's MamadVPNStats
final class NativeStats extends Struct {
  @Uint64()
  external int txBytes;

  @Uint64()
  external int rxBytes;

  @Uint64()
  external int packetsIntercepted;

  @Uint64()
  external int packetsInjected;

  @Uint64()
  external int unexpectedPackets;

  @Uint32()
  external int activeConnections;

  @Uint64()
  external int uptimeSeconds;
}
