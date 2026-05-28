import 'dart:async';

import 'package:flutter/material.dart';
import '../models/app_state.dart';
import '../services/app_service.dart';
import '../widgets/stats_card.dart';
import 'config_screen.dart';
import 'logs_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final _service = AppService.instance;
  VpnState _vpnState = VpnState.disconnected;
  EngineStats _stats = EngineStats();
  late StreamSubscription _vpnSub;
  late StreamSubscription _statsSub;

  @override
  void initState() {
    super.initState();
    _vpnSub = _service.vpnStateStream.listen((state) {
      if (mounted) setState(() => _vpnState = state);
    });
    _statsSub = _service.statsStream.listen((stats) {
      if (mounted) setState(() => _stats = stats);
    });
  }

  @override
  void dispose() {
    _vpnSub.cancel();
    _statsSub.cancel();
    super.dispose();
  }

  Future<void> _toggleVpn() async {
    if (_vpnState == VpnState.connected) {
      await _service.stopVpn();
    } else {
      await _service.startVpn();
    }
  }

  Color _statusColor() {
    switch (_vpnState) {
      case VpnState.connected:
        return const Color(0xFF00E676);
      case VpnState.connecting:
      case VpnState.disconnecting:
        return const Color(0xFFFFD740);
      case VpnState.error:
        return const Color(0xFFFF5252);
      case VpnState.disconnected:
        return const Color(0xFF9E9E9E);
    }
  }

  String _statusText() {
    switch (_vpnState) {
      case VpnState.connected:
        return 'Connected';
      case VpnState.connecting:
        return 'Connecting...';
      case VpnState.disconnecting:
        return 'Disconnecting...';
      case VpnState.error:
        return 'Error';
      case VpnState.disconnected:
        return 'Disconnected';
    }
  }

  IconData _statusIcon() {
    switch (_vpnState) {
      case VpnState.connected:
        return Icons.shield;
      case VpnState.connecting:
      case VpnState.disconnecting:
        return Icons.hourglass_top;
      case VpnState.error:
        return Icons.error_outline;
      case VpnState.disconnected:
        return Icons.shield_outlined;
    }
  }

  @override
  Widget build(BuildContext context) {
    final isRunning = _vpnState == VpnState.connected;
    final isBusy = _vpnState == VpnState.connecting ||
        _vpnState == VpnState.disconnecting;

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFF00E676).withOpacity(0.15),
                borderRadius: BorderRadius.circular(12),
              ),
              child: const Icon(
                Icons.security,
                color: Color(0xFF00E676),
                size: 20,
              ),
            ),
            const SizedBox(width: 12),
            const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'MamadVPN',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                    color: Colors.white,
                  ),
                ),
                Text(
                  'TCP Desync Bypass',
                  style: TextStyle(
                    fontSize: 11,
                    color: Color(0xFF8B949E),
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.tune, color: Color(0xFF8B949E)),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ConfigScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.terminal, color: Color(0xFF8B949E)),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const LogsScreen()),
            ),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // ── Connection status card ──────────────────────────
          Container(
            padding: const EdgeInsets.all(28),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  const Color(0xFF1A2332),
                  const Color(0xFF161B22),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: _statusColor().withOpacity(0.3),
                width: 1,
              ),
            ),
            child: Column(
              children: [
                // Mode indicator
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                  decoration: BoxDecoration(
                    color: const Color(0xFF30363D),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(
                    _service.config.connectionMode.displayName,
                    style: const TextStyle(
                      color: Color(0xFF8B949E),
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Power button
                SizedBox(
                  width: 88,
                  height: 88,
                  child: GestureDetector(
                    onTap: isBusy ? null : _toggleVpn,
                    child: AnimatedContainer(
                      duration: const Duration(milliseconds: 300),
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: isRunning
                            ? const Color(0xFF00E676).withOpacity(0.15)
                            : const Color(0xFF30363D),
                        border: Border.all(
                          color: _statusColor().withOpacity(0.5),
                          width: 3,
                        ),
                        boxShadow: isRunning
                            ? [
                                BoxShadow(
                                  color: const Color(0xFF00E676)
                                      .withOpacity(0.3),
                                  blurRadius: 20,
                                  spreadRadius: 2,
                                ),
                              ]
                            : [],
                      ),
                      child: Icon(
                        _statusIcon(),
                        color: _statusColor(),
                        size: 40,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                Text(
                  _statusText(),
                  style: TextStyle(
                    color: _statusColor(),
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                if (isRunning)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text(
                      _stats.formattedUptime,
                      style: const TextStyle(
                        color: Color(0xFF8B949E),
                        fontSize: 13,
                      ),
                    ),
                  ),
                const SizedBox(height: 20),

                // Connection details
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0D1117).withOpacity(0.6),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      _detailChip(Icons.arrow_downward, 'Local',
                          '${_service.config.listenHost}:${_service.config.listenPort}'),
                      const Padding(
                        padding: EdgeInsets.symmetric(horizontal: 12),
                        child: Icon(Icons.arrow_forward,
                            color: Color(0xFF30363D), size: 18),
                      ),
                      _detailChip(Icons.public, 'Remote',
                          '${_service.config.connectHost}:${_service.config.connectPort}'),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),

          // ── Stats grid ──────────────────────────────────────
          Row(
            children: [
              Expanded(
                child: StatsCard(
                  title: 'TX',
                  value: _stats.formattedTx,
                  icon: Icons.upload,
                  color: const Color(0xFF58A6FF),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: StatsCard(
                  title: 'RX',
                  value: _stats.formattedRx,
                  icon: Icons.download,
                  color: const Color(0xFF00E676),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: StatsCard(
                  title: 'Intercepted',
                  value: '${_stats.packetsIntercepted}',
                  icon: Icons.traffic,
                  color: const Color(0xFFFFD740),
                  valueSize: 20,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: StatsCard(
                  title: 'Injected',
                  value: '${_stats.packetsInjected}',
                  icon: Icons.send,
                  color: const Color(0xFFFF5252),
                  valueSize: 20,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // ── Quick config info ────────────────────────────────
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: const Color(0xFF30363D),
                width: 1,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.info_outline,
                        color: Color(0xFF8B949E), size: 16),
                    SizedBox(width: 8),
                    Text(
                      'Connection Info',
                      style: TextStyle(
                        color: Color(0xFF8B949E),
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                _infoRow('Mode', _service.config.connectionMode.displayName),
                _infoRow('Fake SNI', _service.config.fakeSni),
                _infoRow('SOCKS', '127.0.0.1:${_service.config.socksPort}'),
                _infoRow('HTTP', '127.0.0.1:${_service.config.httpPort}'),
                if (_service.config.connectionMode == ConnectionMode.trojan) ...[
                  const Divider(color: Color(0xFF30363D), height: 16),
                  _infoRow('Trojan', _service.config.trojanSni),
                  _infoRow('Transport',
                      _service.config.trojanTransport.displayName),
                  if (_service.config.trojanPath.isNotEmpty)
                    _infoRow('Path', _service.config.trojanPath),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _detailChip(IconData icon, String label, String value) {
    return Column(
      children: [
        Icon(icon, color: const Color(0xFF8B949E), size: 16),
        const SizedBox(height: 4),
        Text(
          label,
          style: const TextStyle(
            color: Color(0xFF8B949E),
            fontSize: 11,
          ),
        ),
        Text(
          value,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(
              color: Color(0xFF8B949E),
              fontSize: 13,
            ),
          ),
          Text(
            value,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }
}
