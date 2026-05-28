import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import '../ffi/native_bridge.dart';
import '../models/app_state.dart';

/// Application-level service that wraps the FFI layer and provides
/// a clean async API for the UI.
class AppService {
  static AppService? _instance;

  MamadVPNFFI? _ffi;

  // ── State streams ──────────────────────────────────────────────

  final _vpnStateController = StreamController<VpnState>.broadcast();
  Stream<VpnState> get vpnStateStream => _vpnStateController.stream;

  final _statsController = StreamController<EngineStats>.broadcast();
  Stream<EngineStats> get statsStream => _statsController.stream;

  final _logsController = StreamController<List<String>>.broadcast();
  Stream<List<String>> get logsStream => _logsController.stream;

  // ── Current state ──────────────────────────────────────────────

  VpnState _vpnState = VpnState.disconnected;
  VpnState get vpnState => _vpnState;

  AppConfig _config = AppConfig();
  AppConfig get config => _config;

  List<String> _logs = [];
  List<String> get currentLogs => List.unmodifiable(_logs);
  Timer? _pollTimer;

  // ── Method channel for Android VpnService ──────────────────────

  static const _channel = MethodChannel('com.mamadvpn/vpn');

  // ── TUN fd synchronization ──────────────────────────────────────
  // The TUN fd arrives asynchronously via the onTunFd MethodChannel
  // callback.  We use a Completer to wait for it before calling start().
  Completer<int>? _tunFdCompleter;
  bool _stopRequestedByUser = false;

  AppService._() {
    _channel.setMethodCallHandler(_handleMethodCall);
  }

  static AppService get instance {
    _instance ??= AppService._();
    return _instance!;
  }

  Future<void> initialize() async {
    try {
      final ffi = MamadVPNFFI.instance;
      _ffi = ffi;
      _addLog('Native library loaded successfully');

      // Load config from asset or use default
      _config = AppConfig();

      // Try loading from app data directory
      final file = File('${(await _getDocumentsDir())}/config.json');
      if (await file.exists()) {
        final json = jsonDecode(await file.readAsString());
        _config = AppConfig.fromJson(json);
        _addLog('Loaded persistent config');
      }
    } catch (e) {
      _addLog('Initialization error: $e');
      // _ffi will remain null — startVpn() will detect this
    }
  }

  Future<String> _getDocumentsDir() async {
    // On Android, use the app's data directory
    if (Platform.isAndroid) {
      final dir = Directory('/data/data/com.mamadvpn.mamadvpn/files');
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
      return dir.path;
    }
    return Directory.systemTemp.path;
  }

  // ── Lifecycle ──────────────────────────────────────────────────

  Future<bool> startVpn() async {
    _stopRequestedByUser = false;
    _updateState(VpnState.connecting);

    // ── Guard: ensure native library is loaded ────────────────
    final ffi = _ffi;
    if (ffi == null) {
      _updateState(VpnState.error);
      _addLog('Native library not loaded — initialization failed');
      return false;
    }

    try {
      // ── Step 1: Initialize the Rust engine ──────────────────
      _addLog('Initializing engine...');
      final configJson = _config.toJsonString();
      _addLog('Config: $configJson');
      final initResult = ffi.init(configJson);
      if (initResult != 0) {
        _updateState(VpnState.error);
        _addLog('Engine init failed (code: $initResult)');
        // Try to get Rust-side logs for more detail
        try {
          final logsJson = ffi.getLogs();
          if (logsJson != null && logsJson.isNotEmpty) {
            _addLog('Rust logs: $logsJson');
          }
        } catch (_) {}
        return false;
      }
      _addLog('Engine initialized successfully');

      // ── Step 2: Start VpnService (Android only) ────────────
      // This is async — the TUN fd arrives later via onTunFd callback.
      if (Platform.isAndroid) {
        // Save config to SharedPreferences before requesting VPN
        _addLog('Saving config to SharedPreferences...');
        try {
          await _channel.invokeMethod('saveConfig', configJson);
          _addLog('Config saved');
        } catch (e) {
          _updateState(VpnState.error);
          _addLog('Failed to save config: $e');
          ffi.shutdown();
          return false;
        }

        // Create completer to wait for TUN fd
        _tunFdCompleter = Completer<int>();

        // Request VPN permission — starts VpnService
        _addLog('Requesting VPN permission...');
        try {
          final granted = await _channel
              .invokeMethod<bool>('requestVpn', {'config': configJson});

          if (granted != true) {
            _updateState(VpnState.error);
            _addLog('VPN permission denied');
            ffi.shutdown(); // Clean up engine
            return false;
          }
        } catch (e) {
          _updateState(VpnState.error);
          _addLog('VPN permission request failed: $e');
          ffi.shutdown();
          return false;
        }

        _addLog('VPN permission granted, waiting for TUN interface...');

        // ── Step 3: Wait for TUN fd ──────────────────────────
        try {
          final tunFd = await _tunFdCompleter!.future
              .timeout(const Duration(seconds: 15));
          _addLog('TUN fd received: $tunFd');

          // ── Step 4: Set TUN fd on engine ───────────────────
          _addLog('Setting TUN fd on engine...');
          final setResult = ffi.setTunFd(tunFd);
          if (setResult != 0) {
            _updateState(VpnState.error);
            if (setResult == -2) {
              _addLog(
                  'Android full-VPN packet forwarding is not available in this build');
            } else {
              _addLog('Failed to set TUN fd ($setResult)');
            }
            try {
              await _channel.invokeMethod('stopVpn');
            } catch (_) {}
            ffi.shutdown();
            return false;
          }
          _addLog('TUN fd set successfully');
        } on TimeoutException {
          _updateState(VpnState.error);
          _addLog('Timed out waiting for TUN interface');
          try {
            await _channel.invokeMethod('stopVpn');
          } catch (_) {}
          ffi.shutdown();
          return false;
        } catch (e) {
          _updateState(VpnState.error);
          _addLog('TUN fd error: $e');
          try {
            await _channel.invokeMethod('stopVpn');
          } catch (_) {}
          ffi.shutdown();
          return false;
        }
      }

      // ── Step 5: Start the engine ───────────────────────────
      _addLog('Starting engine...');
      final startResult = ffi.start();
      if (startResult != 0) {
        _updateState(VpnState.error);
        _addLog('Engine start failed ($startResult)');
        return false;
      }
      _addLog('Engine started');

      _updateState(VpnState.connected);
      _addLog('VPN started (${_config.connectionMode.displayName})');

      // Start polling stats
      _startPolling();
      return true;
    } catch (e) {
      _updateState(VpnState.error);
      _addLog('Start error: $e');
      return false;
    }
  }

  Future<void> stopVpn() async {
    _stopRequestedByUser = true;
    _updateState(VpnState.disconnecting);

    try {
      _stopPolling();

      // Stop the Rust engine first (signals the interceptor loop to exit)
      final ffi = _ffi;
      if (ffi != null) {
        _addLog('Stopping engine...');
        ffi.stop();
        ffi.shutdown();
      }

      // Then stop the VpnService (closes the TUN fd)
      if (Platform.isAndroid) {
        await _channel.invokeMethod('stopVpn');
      }

      _updateState(VpnState.disconnected);
      _addLog('VPN stopped');
    } catch (e) {
      _updateState(VpnState.disconnected);
      _addLog('Stop error: $e');
    }
  }

  // ── Configuration ──────────────────────────────────────────────

  Future<void> updateConfig(AppConfig config) async {
    _config = config;
    _addLog('Config updated: ${config.connectionMode.displayName}');

    // Persist
    try {
      final file = File('${(await _getDocumentsDir())}/config.json');
      await file.writeAsString(jsonEncode(config.toJson()));
    } catch (e) {
      _addLog('Failed to save config: $e');
    }

    // Update running engine if connected
    if (_vpnState == VpnState.connected && _ffi != null) {
      _ffi!.updateConfig(config.toJsonString());
    }
  }

  AppConfig parseTrojanUrl(String url) {
    return AppConfig.fromTrojanUrl(url);
  }

  Future<void> importConfigFromJson(String jsonString) async {
    try {
      final json = jsonDecode(jsonString);
      final config = AppConfig.fromJson(json);
      await updateConfig(config);
    } catch (e) {
      _addLog('Config import error: $e');
    }
  }

  // ── Event handlers ─────────────────────────────────────────────

  void _updateState(VpnState state) {
    _vpnState = state;
    _vpnStateController.add(state);
  }

  void _addLog(String message) {
    final timestamp = DateTime.now().toIso8601String().substring(11, 19);
    _logs.insert(0, '[$timestamp] $message');
    if (_logs.length > 200) _logs.removeLast();
    _logsController.add(List.from(_logs));
  }

  // ── Polling ────────────────────────────────────────────────────

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 2), (_) async {
      final ffi = _ffi;
      if (ffi == null) return;
      try {
        final nativeStats = ffi.getStats();
        if (nativeStats != null) {
          _statsController.add(EngineStats(
            txBytes: nativeStats.txBytes,
            rxBytes: nativeStats.rxBytes,
            packetsIntercepted: nativeStats.packetsIntercepted,
            packetsInjected: nativeStats.packetsInjected,
            unexpectedPackets: nativeStats.unexpectedPackets,
            activeConnections: nativeStats.activeConnections,
            uptimeSeconds: nativeStats.uptimeSeconds,
          ));
        }
      } catch (_) {}

      // Update logs
      final ffi2 = _ffi;
      if (ffi2 == null) return;
      try {
        final logsJson = ffi2.getLogs();
        if (logsJson != null && logsJson.isNotEmpty) {
          try {
            final parsed = jsonDecode(logsJson) as List;
            final logLines = parsed.map((e) => e.toString()).toList();
            if (logLines.isNotEmpty) {
              _logs = logLines;
              _logsController.add(List.from(_logs));
            }
          } catch (_) {
            // Ignore parse errors
          }
        }
      } catch (_) {}
    });
  }

  void _stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  // ── Method channel handler (called from Kotlin) ────────────────

  Future<dynamic> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onTunFd':
        final fd = call.arguments as int;
        // Complete the completer so startVpn() can proceed with setTunFd + start
        _tunFdCompleter?.complete(fd);
        _tunFdCompleter = null;
        _addLog('TUN fd received');
        break;
      case 'onVpnState':
        final state = call.arguments as String;
        _addLog('VPN state: $state');
        break;
      case 'onDisconnected':
        if (_stopRequestedByUser || _vpnState == VpnState.connected) {
          _updateState(VpnState.disconnected);
        }
        _addLog('VPN disconnected by system');
        break;
    }
  }

  void dispose() {
    _stopPolling();
    _vpnStateController.close();
    _statsController.close();
    _logsController.close();
  }
}
