import 'dart:convert';

import 'package:flutter/material.dart';
import '../models/app_state.dart';
import '../services/app_service.dart';

class ConfigScreen extends StatefulWidget {
  const ConfigScreen({super.key});

  @override
  State<ConfigScreen> createState() => _ConfigScreenState();
}

class _ConfigScreenState extends State<ConfigScreen> {
  final _service = AppService.instance;
  late AppConfig _config;
  bool _saving = false;

  // Trojan URL import
  final _trojanUrlController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _config = _service.config;
  }

  @override
  void dispose() {
    _trojanUrlController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    await _service.updateConfig(_config);
    setState(() => _saving = false);
    if (mounted) Navigator.pop(context);
  }

  void _importFromTrojanUrl() {
    final url = _trojanUrlController.text.trim();
    if (url.isEmpty) return;
    final parsed = _service.parseTrojanUrl(url);
    // Merge: preserve existing proxy port and bypass settings,
    // only override Trojan-specific fields + connection mode
    final merged = _config.copyWith(
      connectionMode: parsed.connectionMode,
      trojanPassword: parsed.trojanPassword,
      trojanSni: parsed.trojanSni,
      trojanTransport: parsed.trojanTransport,
      trojanPath: parsed.trojanPath,
      trojanHost: parsed.trojanHost,
      listenHost: parsed.listenHost,
      listenPort: parsed.listenPort,
      connectHost: parsed.connectHost,
      connectPort: parsed.connectPort,
      fakeSni: parsed.fakeSni,
      tlsEnabled: parsed.tlsEnabled,
      tlsVerifyCerts: parsed.tlsVerifyCerts,
    );
    setState(() => _config = merged);
    _trojanUrlController.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        elevation: 0,
        title: const Text(
          'Configuration',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          TextButton(
            onPressed: _saving ? null : _save,
            child: _saving
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: Color(0xFF00E676)),
                  )
                : const Text(
                    'Save',
                    style: TextStyle(
                        color: Color(0xFF00E676),
                        fontWeight: FontWeight.bold,
                        fontSize: 15),
                  ),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Connection Mode ────────────────────────────────
          _sectionHeader('Connection Mode'),
          const SizedBox(height: 8),
          _modeSelector(),
          const SizedBox(height: 24),

          // ── Network ─────────────────────────────────────────
          _sectionHeader('Network'),
          const SizedBox(height: 8),
          _configField('Listen Host', _config.listenHost, (v) {
            setState(() => _config.listenHost = v);
          }),
          _configField('Listen Port', _config.listenPort.toString(), (v) {
            setState(() => _config.listenPort = int.tryParse(v) ?? 40443);
          }, keyboardType: TextInputType.number),
          _configField('Connect Host', _config.connectHost, (v) {
            setState(() => _config.connectHost = v);
          }),
          _configField('Connect Port', _config.connectPort.toString(), (v) {
            setState(() => _config.connectPort = int.tryParse(v) ?? 443);
          }, keyboardType: TextInputType.number),
          _configField('Fake SNI', _config.fakeSni, (v) {
            setState(() => _config.fakeSni = v);
          }),
          const SizedBox(height: 24),

          // ── Proxy Ports ─────────────────────────────────────
          _sectionHeader('Proxy Ports'),
          const SizedBox(height: 8),
          _configField('SOCKS5 Port', _config.socksPort.toString(), (v) {
            setState(() => _config.socksPort = int.tryParse(v) ?? 10808);
          }, keyboardType: TextInputType.number),
          _configField('HTTP Port', _config.httpPort.toString(), (v) {
            setState(() => _config.httpPort = int.tryParse(v) ?? 10809);
          }, keyboardType: TextInputType.number),
          const SizedBox(height: 24),

          // ── Trojan Settings ─────────────────────────────────
          if (_config.connectionMode == ConnectionMode.trojan) ...[
            _sectionHeader('Trojan'),
            const SizedBox(height: 8),
            _configField('Password', _config.trojanPassword, (v) {
              setState(() => _config.trojanPassword = v);
            }, obscure: true),
            _configField('SNI', _config.trojanSni, (v) {
              setState(() => _config.trojanSni = v);
            }),
            _trojanTransportSelector(),
            _configField('WebSocket Path', _config.trojanPath, (v) {
              setState(() => _config.trojanPath = v);
            }),
            _configField('WebSocket Host', _config.trojanHost, (v) {
              setState(() => _config.trojanHost = v);
            }),
            const SizedBox(height: 16),

            // Trojan URL import
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF1A2332),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Import from Trojan URL',
                    style: TextStyle(
                        color: Color(0xFF8B949E),
                        fontSize: 13,
                        fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _trojanUrlController,
                          style: const TextStyle(
                              color: Colors.white, fontSize: 13),
                          decoration: InputDecoration(
                            hintText: 'trojan://...',
                            hintStyle:
                                const TextStyle(color: Color(0xFF484F58)),
                            filled: true,
                            fillColor: const Color(0xFF0D1117),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: const BorderSide(
                                  color: Color(0xFF30363D)),
                            ),
                            contentPadding: const EdgeInsets.symmetric(
                                horizontal: 12, vertical: 10),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      ElevatedButton(
                        onPressed: _importFromTrojanUrl,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF30363D),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 12),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                        ),
                        child: const Text(
                          'Import',
                          style: TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.w600),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),
          ],

          // ── TLS Settings ────────────────────────────────────
          _sectionHeader('TLS'),
          const SizedBox(height: 8),
          SwitchListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 4),
            title: const Text(
              'Enable TLS',
              style: TextStyle(color: Colors.white, fontSize: 14),
            ),
            subtitle: const Text(
              'Wrap outbound relay in TLS',
              style: TextStyle(color: Color(0xFF8B949E), fontSize: 12),
            ),
            value: _config.tlsEnabled,
            activeColor: const Color(0xFF00E676),
            onChanged: (v) => setState(() => _config.tlsEnabled = v),
          ),
          SwitchListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 4),
            title: const Text(
              'Verify Certificates',
              style: TextStyle(color: Colors.white, fontSize: 14),
            ),
            subtitle: const Text(
              'Validate server TLS certificates',
              style: TextStyle(color: Color(0xFF8B949E), fontSize: 12),
            ),
            value: _config.tlsVerifyCerts,
            activeColor: const Color(0xFF00E676),
            onChanged: (v) => setState(() => _config.tlsVerifyCerts = v),
          ),
          _configField('ALPN', _config.tlsAlpn, (v) {
            setState(() => _config.tlsAlpn = v);
          }),
          const SizedBox(height: 24),

          // ── WARP Settings ───────────────────────────────────
          if (_config.connectionMode == ConnectionMode.warp) ...[
            _sectionHeader('WARP'),
            const SizedBox(height: 8),
            _configField('Endpoint', _config.warpEndpoint, (v) {
              setState(() => _config.warpEndpoint = v);
            }),
            _configField('License', _config.warpLicense, (v) {
              setState(() => _config.warpLicense = v);
            }, obscure: true),
            const SizedBox(height: 24),
          ],

          // ── Psiphon Settings ────────────────────────────────
          if (_config.connectionMode == ConnectionMode.psiphon) ...[
            _sectionHeader('Psiphon'),
            const SizedBox(height: 8),
            _configField('Country', _config.psiphonCountry, (v) {
              setState(() => _config.psiphonCountry = v);
            }),
            _configField('Endpoint', _config.psiphonEndpoint, (v) {
              setState(() => _config.psiphonEndpoint = v);
            }),
            _configField('License', _config.psiphonLicense, (v) {
              setState(() => _config.psiphonLicense = v);
            }, obscure: true),
            const SizedBox(height: 24),
          ],

          const SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _sectionHeader(String title) {
    return Text(
      title.toUpperCase(),
      style: const TextStyle(
        color: Color(0xFF58A6FF),
        fontSize: 12,
        fontWeight: FontWeight.w700,
        letterSpacing: 1.2,
      ),
    );
  }

  Widget _modeSelector() {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF30363D)),
      ),
      child: Row(
        children: ConnectionMode.values.map((mode) {
          final isSelected = _config.connectionMode == mode;
          return Expanded(
            child: GestureDetector(
              onTap: () => setState(() => _config.connectionMode = mode),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                padding: const EdgeInsets.symmetric(vertical: 10),
                decoration: BoxDecoration(
                  color: isSelected
                      ? const Color(0xFF00E676).withOpacity(0.15)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  mode.displayName,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: isSelected
                        ? const Color(0xFF00E676)
                        : const Color(0xFF8B949E),
                    fontSize: 13,
                    fontWeight:
                        isSelected ? FontWeight.w600 : FontWeight.normal,
                  ),
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _trojanTransportSelector() {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          const SizedBox(
            width: 120,
            child: Text(
              'Transport',
              style: TextStyle(
                  color: Color(0xFF8B949E),
                  fontSize: 14,
                  fontWeight: FontWeight.w500),
            ),
          ),
          const Spacer(),
          SegmentedButton<TrojanTransport>(
            segments: [
              ButtonSegment(
                  value: TrojanTransport.tcp,
                  label: const Text('TCP', style: TextStyle(fontSize: 12))),
              ButtonSegment(
                  value: TrojanTransport.ws,
                  label: const Text('WS', style: TextStyle(fontSize: 12))),
              ButtonSegment(
                  value: TrojanTransport.grpc,
                  label: const Text('gRPC', style: TextStyle(fontSize: 11))),
            ],
            selected: {_config.trojanTransport},
            onSelectionChanged: (v) {
              setState(() => _config.trojanTransport = v.first);
            },
            style: ButtonStyle(
              backgroundColor: WidgetStateProperty.resolveWith((states) {
                if (states.contains(WidgetState.selected)) {
                  return const Color(0xFF1A2332);
                }
                return const Color(0xFF0D1117);
              }),
              foregroundColor: WidgetStateProperty.resolveWith((states) {
                if (states.contains(WidgetState.selected)) {
                  return const Color(0xFF00E676);
                }
                return const Color(0xFF8B949E);
              }),
              side: WidgetStateProperty.all(
                  const BorderSide(color: Color(0xFF30363D))),
            ),
          ),
        ],
      ),
    );
  }

  Widget _configField(
    String label,
    String value,
    void Function(String) onChanged, {
    TextInputType? keyboardType,
    bool obscure = false,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: const TextStyle(
                  color: Color(0xFF8B949E),
                  fontSize: 14,
                  fontWeight: FontWeight.w500),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: TextField(
              controller: TextEditingController(text: value)
                ..selection = TextSelection.fromPosition(
                    TextPosition(offset: value.length)),
              onChanged: onChanged,
              keyboardType: keyboardType,
              obscureText: obscure,
              style: const TextStyle(
                  color: Colors.white, fontSize: 14, fontFamily: 'monospace'),
              decoration: InputDecoration(
                isDense: true,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                filled: true,
                fillColor: const Color(0xFF0D1117),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: Color(0xFF30363D)),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: Color(0xFF30363D)),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide:
                      const BorderSide(color: Color(0xFF58A6FF), width: 1.5),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
