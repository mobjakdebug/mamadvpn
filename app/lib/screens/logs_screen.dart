import 'dart:async';

import 'package:flutter/material.dart';
import '../services/app_service.dart';

class LogsScreen extends StatefulWidget {
  const LogsScreen({super.key});

  @override
  State<LogsScreen> createState() => _LogsScreenState();
}

class _LogsScreenState extends State<LogsScreen> {
  final _service = AppService.instance;
  List<String> _logs = [];
  final _scrollController = ScrollController();
  late StreamSubscription _logSub;

  @override
  void initState() {
    super.initState();
    _logs = _service.currentLogs; // access current logs via public getter
    _logSub = _service.logsStream.listen((logs) {
      if (mounted) setState(() => _logs = logs);
    });
  }

  @override
  void dispose() {
    _logSub.cancel();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        elevation: 0,
        title: const Row(
          children: [
            Icon(Icons.terminal, color: Color(0xFF00E676), size: 20),
            SizedBox(width: 10),
            Text(
              'Logs',
              style: TextStyle(
                  color: Colors.white, fontWeight: FontWeight.bold),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline,
                color: Color(0xFF8B949E)),
            onPressed: () {
              // Clear local; will also get cleared from Rust on next poll
              setState(() => _logs = []);
            },
          ),
        ],
        leading: IconButton(
          icon:
              const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: _logs.isEmpty
          ? const Center(
              child: Text(
                'No logs yet.\nStart the VPN connection to see activity.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Color(0xFF484F58),
                  fontSize: 14,
                ),
              ),
            )
          : ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(12),
              itemCount: _logs.length,
              itemBuilder: (context, index) {
                final log = _logs[index];
                Color color = const Color(0xFF8B949E);

                if (log.contains('error') || log.contains('failed')) {
                  color = const Color(0xFFFF5252);
                } else if (log.contains('warning') ||
                    log.contains('warn')) {
                  color = const Color(0xFFFFD740);
                } else if (log.contains('started') ||
                    log.contains('connected') ||
                    log.contains('complete')) {
                  color = const Color(0xFF00E676);
                }

                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Text(
                    log,
                    style: TextStyle(
                      color: color,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                );
              },
            ),
    );
  }
}
