//Collecte des signaux ,Détection des comportements suspects, Génération du report
const EventEmitter = require('events');   //Il sert à gérer les événements/signaux requête réseau,erreur,crash détectée
const SIGNAL_TYPES = {      //définis tous les types de signaux que le profiler peut surveiller
  NETWORK_REQUEST: 'network_request',
  FILE_ACCESS: 'file_access',
  APP_LOG: 'app_log',
  ERROR: 'error',
  CRASH: 'crash',
  STORAGE_ACCESS: 'storage_access',
  TIMING: 'timing',
};
const THRESHOLDS = {               //définis les limites de sécurité
  MAX_REQUESTS_PER_SECOND: 10,
  MAX_RETRY_COUNT: 5,
  MAX_ERROR_RATE: 0.3,
  SLOW_REQUEST_MS: 3000,
  SUSPICIOUS_ENDPOINTS: [      //Le profiler surveille des endpoints(adresse/API) sensibles
    /\/admin/i,
    /\/internal/i,
    /\/debug/i,
    /localhost/i,
  ],
  SENSITIVE_FILE_PATTERNS: [         //surveilles les fichiers sensibles
    /\/proc\//,
    /\/etc\/passwd/,
    /\.key$/,
    /\.pem$/,
    /shared_prefs/i,
  ],
};
//Cette classe représente un événement détecté
class Signal {
  constructor(type, data) {
    this.id = `sig_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    this.type = type;
    this.timestamp = Date.now();  //Sauvegarde l’heure exacte du signa
    this.data = data;
    this.anomalyScore = 0;
    this.anomalyReasons = [];
  }
}
class DynamicBehaviorProfiler extends EventEmitter {  //C’est le moteur principal collecte even analyse calcule score genere report 

  constructor(options = {}) {
    super();
    this.sessionId = `session_${Date.now()}`;
    this.startTime = Date.now();
    this.signals = [];
    this.anomalies = [];
    this.requestCounts = {};
    this.retryCounts = {};
    this.errorCount = 0;
    this.totalRequests = 0;
    this.options = {
      verbose: options.verbose ?? false,
      ...options,
    };

    this._log(`[Profiler] Session started: ${this.sessionId}`);
  }

  collectNetworkRequest(url, method, statusCode, durationMs, isRetry = false) {
    this.totalRequests++;
    const signal = new Signal(SIGNAL_TYPES.NETWORK_REQUEST, {
      url, method, statusCode, durationMs, isRetry,
    });

    if (statusCode >= 400) this.errorCount++;
    if (isRetry) {
      this.retryCounts[url] = (this.retryCounts[url] || 0) + 1;
    }

    if (!this.requestCounts[url]) this.requestCounts[url] = [];
    this.requestCounts[url].push(Date.now());

    this._scoreNetworkSignal(signal);
    this._store(signal);
    return signal;
  }

  collectFileAccess(path, operation, appPid) {
    const signal = new Signal(SIGNAL_TYPES.FILE_ACCESS, { path, operation, appPid });
    this._scoreFileSignal(signal);
    this._store(signal);
    return signal;
  }

  collectLog(level, message, tag = 'APP') {
    const signal = new Signal(SIGNAL_TYPES.APP_LOG, { level, message, tag });
    this._scoreLogSignal(signal);
    this._store(signal);
    return signal;
  }

  collectError(errorType, message, stackTrace = null) {
    const signal = new Signal(SIGNAL_TYPES.ERROR, { errorType, message, stackTrace });
    signal.anomalyScore += 20;
    signal.anomalyReasons.push('Error signal');
    this._store(signal);
    return signal;
  }

  collectCrash(reason, threadDump = null) {
    const signal = new Signal(SIGNAL_TYPES.CRASH, { reason, threadDump });
    signal.anomalyScore = 100;
    signal.anomalyReasons.push('App crash');
    this.anomalies.push(signal);
    this.emit('anomaly', signal);
    this._store(signal);
    return signal;
  }

  collectTiming(operation, durationMs, context = {}) {
    const signal = new Signal(SIGNAL_TYPES.TIMING, { operation, durationMs, ...context });
    if (durationMs > THRESHOLDS.SLOW_REQUEST_MS) {
      signal.anomalyScore += 30;
      signal.anomalyReasons.push(`Slow operation: ${durationMs}ms`);
    }
    this._store(signal);
    return signal;
  }

  _scoreNetworkSignal(signal) {
    const { url, statusCode, durationMs } = signal.data;

    if (THRESHOLDS.SUSPICIOUS_ENDPOINTS.some(rx => rx.test(url))) {
      signal.anomalyScore += 40;
      signal.anomalyReasons.push(`Suspicious endpoint: ${url}`);
    }

    const now = Date.now();
    const recent = (this.requestCounts[url] || []).filter(t => now - t < 1000);
    if (recent.length > THRESHOLDS.MAX_REQUESTS_PER_SECOND) {
      signal.anomalyScore += 60;
      signal.anomalyReasons.push(`Request spam: ${recent.length} req/sec to ${url}`);
    }

    const retries = this.retryCounts[url] || 0;
    if (retries >= THRESHOLDS.MAX_RETRY_COUNT) {
      signal.anomalyScore += 50;
      signal.anomalyReasons.push(`Infinite retry loop: ${retries} retries on ${url}`);
    }

    if (durationMs > THRESHOLDS.SLOW_REQUEST_MS) {
      signal.anomalyScore += 25;
      signal.anomalyReasons.push(`Slow request: ${durationMs}ms`);
    }

    const errorRate = this.totalRequests > 0 ? this.errorCount / this.totalRequests : 0;
    if (errorRate > THRESHOLDS.MAX_ERROR_RATE && statusCode >= 400) {
      signal.anomalyScore += 30;
      signal.anomalyReasons.push(`High error rate: ${(errorRate * 100).toFixed(1)}%`);
    }

    this._checkAnomaly(signal);
  }

  _scoreFileSignal(signal) {
    const { path } = signal.data;
    if (THRESHOLDS.SENSITIVE_FILE_PATTERNS.some(rx => rx.test(path))) {
      signal.anomalyScore += 55;
      signal.anomalyReasons.push(`Sensitive file access: ${path}`);
    }
    this._checkAnomaly(signal);
  }

  _scoreLogSignal(signal) {
    const { level, message } = signal.data;
    const sensitivePatterns = [/password/i, /token/i, /secret/i, /api[_-]?key/i, /private[_-]?key/i];
    if (sensitivePatterns.some(rx => rx.test(message))) {
      signal.anomalyScore += 70;
      signal.anomalyReasons.push('Sensitive data in log output');
    }
    if (level === 'ERROR' || level === 'FATAL') {
      signal.anomalyScore += 15;
      signal.anomalyReasons.push(`Log level: ${level}`);
    }
    this._checkAnomaly(signal);
  }

  _checkAnomaly(signal) {
    if (signal.anomalyScore >= 40) {
      this.anomalies.push(signal);
      this.emit('anomaly', signal);
      this._log(`[ANOMALY] Score ${signal.anomalyScore} — ${signal.anomalyReasons.join(', ')}`);
    }
  }

  _store(signal) {
    this.signals.push(signal);
    if (this.options.verbose) {
      this._log(`[Signal] ${signal.type} | score=${signal.anomalyScore}`);
    }
  }

  generateRootCauseHypotheses() {
    const hypotheses = [];
    const networkAnomalies = this.anomalies.filter(s => s.type === SIGNAL_TYPES.NETWORK_REQUEST);
    const fileAnomalies = this.anomalies.filter(s => s.type === SIGNAL_TYPES.FILE_ACCESS);
    const logAnomalies = this.anomalies.filter(s => s.type === SIGNAL_TYPES.APP_LOG);

    const retryHeavy = Object.entries(this.retryCounts).filter(([, c]) => c >= THRESHOLDS.MAX_RETRY_COUNT);
    if (retryHeavy.length > 0) {
      hypotheses.push({
        type: 'infinite_retry',
        severity: 'HIGH',
        description: `Retry loop detected on ${retryHeavy.length} endpoint(s)`,
        endpoints: retryHeavy.map(([url]) => url),
        recommendation: 'Add exponential backoff with max retry cap (e.g., 3 retries).',
      });
    }

    const authRequests = networkAnomalies.filter(s =>
      /login|auth|token/i.test(s.data.url)
    );
    if (authRequests.length > 3) {
      hypotheses.push({
        type: 'login_loop',
        severity: 'CRITICAL',
        description: `Possible login loop: ${authRequests.length} auth requests detected`,
        recommendation: 'Check token refresh logic — may be re-authenticating on every call.',
      });
    }

    const slowRequests = networkAnomalies.filter(s => s.data.durationMs > THRESHOLDS.SLOW_REQUEST_MS);
    if (slowRequests.length > 2) {
      hypotheses.push({
        type: 'timeout_cascade',
        severity: 'MEDIUM',
        description: `${slowRequests.length} slow network calls (>${THRESHOLDS.SLOW_REQUEST_MS}ms)`,
        recommendation: 'Check backend health, add connection timeout (e.g., 10s), implement circuit breaker.',
      });
    }

    if (logAnomalies.length > 0) {
      hypotheses.push({
        type: 'data_leakage',
        severity: 'CRITICAL',
        description: 'Sensitive data (tokens, passwords) written to logs',
        count: logAnomalies.length,
        recommendation: 'Strip sensitive fields from log output. Use ProGuard rules to remove debug logs in release builds.',
      });
    }

    if (fileAnomalies.length > 0) {
      hypotheses.push({
        type: 'sensitive_file_access',
        severity: 'HIGH',
        description: `Access to ${fileAnomalies.length} sensitive path(s)`,
        paths: fileAnomalies.map(s => s.data.path),
        recommendation: 'Review file access patterns. Restrict access using Android FileProvider.',
      });
    }

    return hypotheses;
  }

  generateReport() {
    const duration = Date.now() - this.startTime;
    const hypotheses = this.generateRootCauseHypotheses();
    const errorRate = this.totalRequests > 0
      ? ((this.errorCount / this.totalRequests) * 100).toFixed(1)
      : '0.0';

    return {
      sessionId: this.sessionId,
      duration,
      summary: {
        totalSignals: this.signals.length,
        totalAnomalies: this.anomalies.length,
        totalRequests: this.totalRequests,
        errorRate: `${errorRate}%`,
        anomalyRate: this.signals.length > 0
          ? `${((this.anomalies.length / this.signals.length) * 100).toFixed(1)}%`
          : '0%',
      },
      signalBreakdown: this._countByType(),
      anomalies: this.anomalies.map(s => ({
        id: s.id,
        type: s.type,
        timestamp: new Date(s.timestamp).toISOString(),
        score: s.anomalyScore,
        reasons: s.anomalyReasons,
        data: s.data,
      })),
      rootCauseHypotheses: hypotheses,
      recommendations: hypotheses.map(h => ({
        type: h.type,
        severity: h.severity,
        action: h.recommendation,
      })),
    };
  }

  _countByType() {
    return this.signals.reduce((acc, s) => {
      acc[s.type] = (acc[s.type] || 0) + 1;
      return acc;
    }, {});
  }

  _log(msg) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${msg}`);
  }
}

module.exports = { DynamicBehaviorProfiler, SIGNAL_TYPES, THRESHOLDS };
