#!/usr/bin/env node
//Ce fichier lance le projet
const fs   = require('fs');
const path = require('path');
const { DynamicBehaviorProfiler } = require('./profiler');
const { AnomalyDetector }         = require('./anomaly-detector');

const verbose  = process.argv.includes('--verbose');
const profiler = new DynamicBehaviorProfiler({ verbose });
const detector = new AnomalyDetector();

console.log('\n══════════════════════════════════════════════════');
console.log('  Dynamic Behavior Profiler — Runtime Analysis');
console.log('══════════════════════════════════════════════════\n');

profiler.collectNetworkRequest('https://api.myapp.com/v1/user', 'GET', 200, 210);
profiler.collectNetworkRequest('https://api.myapp.com/v1/feed', 'GET', 200, 340);
profiler.collectLog('INFO', 'User session started', 'AuthManager');
profiler.collectTiming('screen_load', 450, { screen: 'HomeActivity' });

for (let i = 0; i < 5; i++) {
  profiler.collectNetworkRequest('https://api.myapp.com/auth/token', 'POST', 401, 120, i > 0);
}

for (let i = 0; i < 15; i++) {
  profiler.collectNetworkRequest('https://api.myapp.com/v1/status', 'GET', 200, 50);
}

profiler.collectLog('DEBUG', 'Login successful — token=eyJhbGciOiJIUzI1NiJ9.abc123', 'NetworkManager');
profiler.collectLog('DEBUG', 'User password=hunter2 cached for auto-login', 'AuthCache');

profiler.collectFileAccess('/data/data/com.myapp/shared_prefs/credentials.xml', 'READ', 1234);
profiler.collectFileAccess('/proc/net/tcp', 'READ', 1234);

profiler.collectNetworkRequest('https://api.myapp.com/v1/heavy-query', 'POST', 200, 5200);
profiler.collectNetworkRequest('https://api.myapp.com/v1/heavy-query', 'POST', 504, 8100);

profiler.collectError(
  'NullPointerException',
  'Attempt to invoke method on null object',
  'at com.myapp.ui.HomeFragment.onResume(HomeFragment.java:87)'
);

profiler.collectNetworkRequest('https://api.myapp.com/v1/settings', 'GET', 200, 180);
profiler.collectLog('INFO', 'Preferences loaded', 'SettingsManager');
profiler.collectTiming('image_decode', 120, { format: 'webp' });

const analysis = detector.analyze(profiler.signals, { isDevDevice: false, isTestEnv: false });
const report   = profiler.generateReport();

report.detectorAnalysis = analysis;

console.log('══════════════════════════════════════════════════');
console.log('  ANALYSIS RESULTS');
console.log('══════════════════════════════════════════════════');
console.log(`  Session ID   : ${report.sessionId}`);
console.log(`  Total Signals: ${report.summary.totalSignals}`);
console.log(`  Anomalies    : ${report.summary.totalAnomalies}`);
console.log(`  Error Rate   : ${report.summary.errorRate}`);
console.log(`  Risk Score   : ${analysis.adjustedScore}/100`);
console.log(`  Risk Level   : ${analysis.classification.emoji} ${analysis.classification.level}`);
console.log('');
console.log('  Root Cause Hypotheses:');
report.rootCauseHypotheses.forEach((h, i) => {
  console.log(`  ${i + 1}. [${h.severity}] ${h.description}`);
  console.log(`     → ${h.recommendation}`);
});
console.log('');
console.log('  Detector Explanation:');
analysis.explanation.forEach(e => console.log(`  • ${e}`));
console.log('══════════════════════════════════════════════════\n');

const reportPath = path.join(__dirname, '../reports/analysis_report.json');
fs.mkdirSync(path.dirname(reportPath), { recursive: true });
fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
console.log(`[✓] Full report saved → ${reportPath}\n`);
