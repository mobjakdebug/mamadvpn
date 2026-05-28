import 'dart:convert';

/// Maps to Rust's ConnectionMode enum
enum ConnectionMode {
  sniOnly,
  trojan,
  warp,
  psiphon;

  String get displayName {
    switch (this) {
      case ConnectionMode.sniOnly:
        return 'SNI Only';
      case ConnectionMode.trojan:
        return 'Trojan';
      case ConnectionMode.warp:
        return 'WARP';
      case ConnectionMode.psiphon:
        return 'Psiphon';
    }
  }

  String get rustName {
    switch (this) {
      case ConnectionMode.sniOnly:
        return 'sni_only';
      case ConnectionMode.trojan:
        return 'trojan';
      case ConnectionMode.warp:
        return 'warp';
      case ConnectionMode.psiphon:
        return 'psiphon';
    }
  }

  static ConnectionMode fromString(String s) {
    switch (s.toLowerCase()) {
      case 'sni_only':
      case 'sni only':
        return ConnectionMode.sniOnly;
      case 'trojan':
        return ConnectionMode.trojan;
      case 'warp':
        return ConnectionMode.warp;
      case 'psiphon':
        return ConnectionMode.psiphon;
      default:
        return ConnectionMode.sniOnly;
    }
  }
}

/// Maps to Rust's BypassMethod enum
enum BypassMode {
  wrongSeq,
  badChecksum,
  fragmentation,
  delayedAck,
  fakeRst;

  String get displayName {
    switch (this) {
      case BypassMode.wrongSeq:
        return 'Wrong Seq';
      case BypassMode.badChecksum:
        return 'Bad Checksum';
      case BypassMode.fragmentation:
        return 'Fragmentation';
      case BypassMode.delayedAck:
        return 'Delayed ACK';
      case BypassMode.fakeRst:
        return 'Fake RST';
    }
  }

  static BypassMode fromString(String s) {
    switch (s.toLowerCase()) {
      case 'wrong_seq':
      case 'wrongseq':
        return BypassMode.wrongSeq;
      case 'bad_checksum':
      case 'badchecksum':
        return BypassMode.badChecksum;
      case 'fragmentation':
        return BypassMode.fragmentation;
      case 'delayed_ack':
      case 'delayedack':
        return BypassMode.delayedAck;
      case 'fake_rst':
      case 'fakerst':
        return BypassMode.fakeRst;
      default:
        return BypassMode.wrongSeq;
    }
  }
}

/// Maps to Rust's DataMode enum
enum DataMode { tls, http;

  String get displayName {
    switch (this) {
      case DataMode.tls:
        return 'TLS';
      case DataMode.http:
        return 'HTTP';
    }
  }

  static DataMode fromString(String s) {
    switch (s.toLowerCase()) {
      case 'tls':
        return DataMode.tls;
      case 'http':
        return DataMode.http;
      default:
        return DataMode.tls;
    }
  }
}

/// Maps to Rust's TrojanTransport enum
enum TrojanTransport { tcp, ws, grpc;

  String get displayName {
    switch (this) {
      case TrojanTransport.tcp:
        return 'TCP';
      case TrojanTransport.ws:
        return 'WebSocket';
      case TrojanTransport.grpc:
        return 'gRPC';
    }
  }

  String get rustName {
    switch (this) {
      case TrojanTransport.tcp:
        return 'tcp';
      case TrojanTransport.ws:
        return 'ws';
      case TrojanTransport.grpc:
        return 'grpc';
    }
  }

  static TrojanTransport fromString(String s) {
    switch (s.toLowerCase()) {
      case 'tcp':
        return TrojanTransport.tcp;
      case 'ws':
      case 'websocket':
        return TrojanTransport.ws;
      case 'grpc':
        return TrojanTransport.grpc;
      default:
        return TrojanTransport.tcp;
    }
  }
}

/// Maps to Rust's TlsConnectorBackend
enum TlsConnectorBackend { rustls, custom;

  String get displayName {
    switch (this) {
      case TlsConnectorBackend.rustls:
        return 'Rustls';
      case TlsConnectorBackend.custom:
        return 'Custom (JA3)';
    }
  }

  String get rustName {
    switch (this) {
      case TlsConnectorBackend.rustls:
        return 'rustls';
      case TlsConnectorBackend.custom:
        return 'custom';
    }
  }

  static TlsConnectorBackend fromString(String s) {
    switch (s.toLowerCase()) {
      case 'rustls':
        return TlsConnectorBackend.rustls;
      case 'custom':
        return TlsConnectorBackend.custom;
      default:
        return TlsConnectorBackend.custom;
    }
  }
}

/// Maps to Rust's TlsFingerprintKind
enum TlsFingerprintKind { chrome, firefox, android, random;

  String get displayName {
    switch (this) {
      case TlsFingerprintKind.chrome:
        return 'Chrome';
      case TlsFingerprintKind.firefox:
        return 'Firefox';
      case TlsFingerprintKind.android:
        return 'Android';
      case TlsFingerprintKind.random:
        return 'Random';
    }
  }

  String get rustName {
    switch (this) {
      case TlsFingerprintKind.chrome:
        return 'chrome';
      case TlsFingerprintKind.firefox:
        return 'firefox';
      case TlsFingerprintKind.android:
        return 'android';
      case TlsFingerprintKind.random:
        return 'random';
    }
  }

  static TlsFingerprintKind fromString(String s) {
    switch (s.toLowerCase()) {
      case 'chrome':
        return TlsFingerprintKind.chrome;
      case 'firefox':
        return TlsFingerprintKind.firefox;
      case 'android':
        return TlsFingerprintKind.android;
      case 'random':
        return TlsFingerprintKind.random;
      default:
        return TlsFingerprintKind.chrome;
    }
  }
}

/// Full app configuration matching Rust's AppConfig

class AppConfig {
  ConnectionMode connectionMode;
  BypassMode bypassMode;
  DataMode dataMode;
  String listenHost;
  int listenPort;
  String connectHost;
  int connectPort;
  String fakeSni;
  int socksPort;
  int httpPort;
  String trojanPassword;
  String trojanSni;
  TrojanTransport trojanTransport;
  String trojanPath;
  String trojanHost;
  String warpEndpoint;
  String warpLicense;
  String psiphonCountry;
  String psiphonEndpoint;
  String psiphonLicense;
  bool tlsEnabled;
  bool tlsVerifyCerts;
  String tlsAlpn;
  TlsConnectorBackend tlsConnector;
  TlsFingerprintKind tlsFingerprint;
  String? tlsSni;

  AppConfig({
    this.connectionMode = ConnectionMode.sniOnly,
    this.bypassMode = BypassMode.wrongSeq,
    this.dataMode = DataMode.tls,
    this.listenHost = '0.0.0.0',
    this.listenPort = 40443,
    this.connectHost = '104.19.229.21',
    this.connectPort = 443,
    this.fakeSni = 'hcaptcha.com',
    this.socksPort = 10808,
    this.httpPort = 10809,
    this.trojanPassword = '',
    this.trojanSni = '',
    this.trojanTransport = TrojanTransport.tcp,
    this.trojanPath = '',
    this.trojanHost = '',
    this.warpEndpoint = '162.159.192.1',
    this.warpLicense = '',
    this.psiphonCountry = 'US',
    this.psiphonEndpoint = '162.159.192.1',
    this.psiphonLicense = '',
    this.tlsEnabled = true,
    this.tlsVerifyCerts = true,
    this.tlsAlpn = 'h2,http/1.1',
    this.tlsConnector = TlsConnectorBackend.custom,
    this.tlsFingerprint = TlsFingerprintKind.chrome,
    this.tlsSni,
  });

  factory AppConfig.fromJson(Map<String, dynamic> json) {
    return AppConfig(
      connectionMode: ConnectionMode.fromString(
          json['connection_mode'] as String? ??
          json['CONNECTION_MODE'] as String? ??
          'SNI Only'),
      bypassMode: BypassMode.fromString(
          json['bypass_mode'] as String? ??
          json['BYPASS_MODE'] as String? ??
          'wrong_seq'),
      dataMode: DataMode.fromString(
          json['data_mode'] as String? ??
          json['DATA_MODE'] as String? ??
          'tls'),
      listenHost: json['listen_host'] as String? ??
          json['LISTEN_HOST'] as String? ??
          '0.0.0.0',
      listenPort: json['listen_port'] as int? ??
          json['LISTEN_PORT'] as int? ??
          40443,
      connectHost: json['connect_host'] as String? ??
          json['connectHost'] as String? ??
          json['CONNECT_IP'] as String? ??
          '104.19.229.21',
      connectPort: json['connect_port'] as int? ??
          json['CONNECT_PORT'] as int? ??
          443,
      fakeSni: json['fake_sni'] as String? ??
          json['FAKE_SNI'] as String? ??
          'hcaptcha.com',
      socksPort: json['socks_port'] as int? ??
          json['SOCKS_PORT'] as int? ??
          10808,
      httpPort: json['http_port'] as int? ??
          json['HTTP_PORT'] as int? ??
          10809,
      trojanPassword: json['trojan_password'] as String? ??
          json['TROJAN_PASSWORD'] as String? ??
          '',
      trojanSni: json['trojan_sni'] as String? ??
          json['TROJAN_SNI'] as String? ??
          '',
      trojanTransport: TrojanTransport.fromString(
          json['trojan_transport'] as String? ??
          json['TROJAN_TRANSPORT'] as String? ??
          'tcp'),
      trojanPath: json['trojan_path'] as String? ??
          json['TROJAN_PATH'] as String? ??
          '',
      trojanHost: json['trojan_host'] as String? ??
          json['TROJAN_HOST'] as String? ??
          '',
      warpEndpoint: json['warp_endpoint'] as String? ??
          json['WARP_ENDPOINT'] as String? ??
          '162.159.192.1',
      warpLicense: json['warp_license'] as String? ??
          json['WARP_LICENSE'] as String? ??
          '',
      psiphonCountry: json['psiphon_country'] as String? ??
          json['PSIPHON_COUNTRY'] as String? ??
          'US',
      psiphonEndpoint: json['psiphon_endpoint'] as String? ??
          json['PSIPHON_ENDPOINT'] as String? ??
          '162.159.192.1',
      psiphonLicense: json['psiphon_license'] as String? ??
          json['PSIPHON_LICENSE'] as String? ??
          '',
      tlsEnabled: json['tls_enabled'] as bool? ??
          json['TLS_ENABLED'] as bool? ??
          true,
      tlsVerifyCerts: json['tls_verify_certs'] as bool? ??
          json['TLS_VERIFY_CERTS'] as bool? ??
          true,
      tlsAlpn: json['tls_alpn'] as String? ??
          json['TLS_ALPN'] as String? ??
          'h2,http/1.1',
      tlsConnector: TlsConnectorBackend.fromString(
          json['tls_connector'] as String? ??
          json['TLS_CONNECTOR'] as String? ??
          'custom'),
      tlsFingerprint: TlsFingerprintKind.fromString(
          json['tls_fingerprint'] as String? ??
          json['TLS_FINGERPRINT'] as String? ??
          'chrome'),
      tlsSni: json['tls_sni'] as String? ??
          json['TLS_SNI'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
    'connection_mode': connectionMode.rustName,
    'bypass_mode': bypassMode.displayName.replaceAll(' ', '_').toLowerCase(),
    'data_mode': dataMode.displayName.toLowerCase(),
    'LISTEN_HOST': listenHost,
    'LISTEN_PORT': listenPort,
    'CONNECT_IP': connectHost,
    'CONNECT_PORT': connectPort,
    'FAKE_SNI': fakeSni,
    'socks_port': socksPort,
    'http_port': httpPort,
    'trojan_password': trojanPassword,
    'trojan_sni': trojanSni,
    'trojan_transport': trojanTransport.rustName,
    'trojan_path': trojanPath,
    'trojan_host': trojanHost,
    'warp_endpoint': warpEndpoint,
    'warp_license': warpLicense,
    'psiphon_country': psiphonCountry,
    'psiphon_endpoint': psiphonEndpoint,
    'psiphon_license': psiphonLicense,
    'tls_enabled': tlsEnabled,
    'tls_verify_certs': tlsVerifyCerts,
    'tls_alpn': tlsAlpn,
    'tls_connector': tlsConnector.rustName,
    'tls_fingerprint': tlsFingerprint.rustName,
    'tls_sni': tlsSni,
  };

  String toJsonString() => jsonEncode(toJson());

  /// Create a copy with selected fields replaced.
  AppConfig copyWith({
    ConnectionMode? connectionMode,
    BypassMode? bypassMode,
    DataMode? dataMode,
    String? listenHost,
    int? listenPort,
    String? connectHost,
    int? connectPort,
    String? fakeSni,
    int? socksPort,
    int? httpPort,
    String? trojanPassword,
    String? trojanSni,
    TrojanTransport? trojanTransport,
    String? trojanPath,
    String? trojanHost,
    String? warpEndpoint,
    String? warpLicense,
    String? psiphonCountry,
    String? psiphonEndpoint,
    String? psiphonLicense,
    bool? tlsEnabled,
    bool? tlsVerifyCerts,
    String? tlsAlpn,
    TlsConnectorBackend? tlsConnector,
    TlsFingerprintKind? tlsFingerprint,
    String? tlsSni,
  }) {
    return AppConfig(
      connectionMode: connectionMode ?? this.connectionMode,
      bypassMode: bypassMode ?? this.bypassMode,
      dataMode: dataMode ?? this.dataMode,
      listenHost: listenHost ?? this.listenHost,
      listenPort: listenPort ?? this.listenPort,
      connectHost: connectHost ?? this.connectHost,
      connectPort: connectPort ?? this.connectPort,
      fakeSni: fakeSni ?? this.fakeSni,
      socksPort: socksPort ?? this.socksPort,
      httpPort: httpPort ?? this.httpPort,
      trojanPassword: trojanPassword ?? this.trojanPassword,
      trojanSni: trojanSni ?? this.trojanSni,
      trojanTransport: trojanTransport ?? this.trojanTransport,
      trojanPath: trojanPath ?? this.trojanPath,
      trojanHost: trojanHost ?? this.trojanHost,
      warpEndpoint: warpEndpoint ?? this.warpEndpoint,
      warpLicense: warpLicense ?? this.warpLicense,
      psiphonCountry: psiphonCountry ?? this.psiphonCountry,
      psiphonEndpoint: psiphonEndpoint ?? this.psiphonEndpoint,
      psiphonLicense: psiphonLicense ?? this.psiphonLicense,
      tlsEnabled: tlsEnabled ?? this.tlsEnabled,
      tlsVerifyCerts: tlsVerifyCerts ?? this.tlsVerifyCerts,
      tlsAlpn: tlsAlpn ?? this.tlsAlpn,
      tlsConnector: tlsConnector ?? this.tlsConnector,
      tlsFingerprint: tlsFingerprint ?? this.tlsFingerprint,
      tlsSni: tlsSni ?? this.tlsSni,
    );
  }

  factory AppConfig.fromTrojanUrl(String url) {
    final stripped = url.startsWith('trojan://') ? url.substring(9) : url;

    final withoutFragment = stripped.contains('#')
        ? stripped.substring(0, stripped.indexOf('#'))
        : stripped;

    final atIndex = withoutFragment.indexOf('@');
    if (atIndex < 0) return AppConfig();

    final password = withoutFragment.substring(0, atIndex);
    final afterAt = withoutFragment.substring(atIndex + 1);

    String host = afterAt;
    int port = 443;
    final queryIndex = afterAt.indexOf('?');
    String query = '';
    if (queryIndex >= 0) {
      host = afterAt.substring(0, queryIndex);
      query = afterAt.substring(queryIndex + 1);
    }

    final colonIndex = host.indexOf(':');
    if (colonIndex >= 0) {
      port = int.tryParse(host.substring(colonIndex + 1)) ?? 443;
      host = host.substring(0, colonIndex);
    }

    final config = AppConfig(
      connectionMode: ConnectionMode.trojan,
      trojanPassword: password,
      trojanSni: host,
      trojanHost: host,
      listenHost: '127.0.0.1',
      listenPort: 40443,
      connectHost: '127.0.0.1',
      connectPort: port,
      fakeSni: host,
    );

    for (final pair in query.split('&')) {
      final eqIndex = pair.indexOf('=');
      if (eqIndex < 0) continue;
      final k = pair.substring(0, eqIndex);
      final v = pair.substring(eqIndex + 1);
      switch (k) {
        case 'sni':
          config.trojanSni = v;
          config.trojanHost = v;
          break;
        case 'security':
          config.tlsEnabled = v == 'tls';
          break;
        case 'type':
          config.trojanTransport = TrojanTransport.fromString(v);
          break;
        case 'path':
          config.trojanPath = Uri.decodeComponent(v);
          break;
        case 'host':
          config.trojanHost = v;
          break;
        case 'insecure':
        case 'allowInsecure':
          config.tlsVerifyCerts = v != '1' && v != 'true';
          break;
      }
    }

    return config;
  }
}

/// VPN service state
enum VpnState { disconnected, connecting, connected, disconnecting, error }

/// Engine stats matching Rust's MamadVPNStats struct
class EngineStats {
  final int txBytes;
  final int rxBytes;
  final int packetsIntercepted;
  final int packetsInjected;
  final int unexpectedPackets;
  final int activeConnections;
  final int uptimeSeconds;

  EngineStats({
    this.txBytes = 0,
    this.rxBytes = 0,
    this.packetsIntercepted = 0,
    this.packetsInjected = 0,
    this.unexpectedPackets = 0,
    this.activeConnections = 0,
    this.uptimeSeconds = 0,
  });

  String get formattedTx {
    if (txBytes < 1024) return '$txBytes B';
    if (txBytes < 1024 * 1024) return '${(txBytes / 1024).toStringAsFixed(1)} KB';
    return '${(txBytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  String get formattedRx {
    if (rxBytes < 1024) return '$rxBytes B';
    if (rxBytes < 1024 * 1024) return '${(rxBytes / 1024).toStringAsFixed(1)} KB';
    return '${(rxBytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  String get formattedUptime {
    final hours = uptimeSeconds ~/ 3600;
    final minutes = (uptimeSeconds % 3600) ~/ 60;
    final seconds = uptimeSeconds % 60;
    if (hours > 0) return '${hours}h ${minutes}m ${seconds}s';
    if (minutes > 0) return '${minutes}m ${seconds}s';
    return '${seconds}s';
  }
}
