 //Analyse intelligente ,Calcul du score final
 class AnomalyDetector {
  constructor() {
    this.weights = {
      requestFrequency: 0.25,       //Les requêtes réseau comptent pour 25% du score
      errorRate:        0.20,
      sensitiveAccess:  0.25,
      retryPattern:     0.15,
      timingDeviation:  0.15,
    };
  }

  extractFeatures(signals, windowMs = 60000) {     //analyse les signaux collectés pendant 60 secondes
    const now = Date.now();
    const window = signals.filter(s => now - s.timestamp < windowMs);

    const networkSignals = window.filter(s => s.type === 'network_request');  //Filtre uniquement les requêtes réseau
    const fileSignals    = window.filter(s => s.type === 'file_access');  //Filtre uniquement accès fichiers
    const errorSignals   = window.filter(s => s.data?.statusCode >= 400 || s.type === 'error');
    const retrySignals   = window.filter(s => s.data?.isRetry === true);  //Détecte les retries infinis

    const durations = networkSignals.map(s => s.data?.durationMs || 0);    
    const avgDuration = durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : 0; //Calcule le temps moyen
    const maxDuration = Math.max(...durations, 0);

    return {
      requestFrequency: Math.min(networkSignals.length / 60, 1),
      errorRate: networkSignals.length > 0 ? errorSignals.length / networkSignals.length : 0,
      sensitiveAccess: Math.min(fileSignals.filter(s => s.anomalyScore > 0).length / 5, 1),
      retryPattern: Math.min(retrySignals.length / 10, 1),
      timingDeviation: Math.min(maxDuration / 10000, 1),
      metadata: {
        windowMs,
        signalCount: window.length,
        avgRequestDuration: avgDuration.toFixed(0),
        maxRequestDuration: maxDuration,
      },
    };
  }

  score(features) {
    const raw =
      features.requestFrequency * this.weights.requestFrequency +
      features.errorRate         * this.weights.errorRate        +
      features.sensitiveAccess   * this.weights.sensitiveAccess  +
      features.retryPattern      * this.weights.retryPattern     +
      features.timingDeviation   * this.weights.timingDeviation;

    return Math.round(raw * 100);
  }

  classify(score) {
    if (score >= 70) return { level: 'CRITICAL', color: '#C0392B', emoji: '🔴' };
    if (score >= 40) return { level: 'HIGH',     color: '#E67E22', emoji: '🟠' };
    if (score >= 20) return { level: 'MEDIUM',   color: '#F1C40F', emoji: '🟡' };
    return               { level: 'LOW',      color: '#27AE60', emoji: '🟢' };
  }

  falsePositiveReduction(signals, deviceContext = {}) {
    let factor = 1.0;

    if (deviceContext.isDevDevice) factor *= 0.5;
    if (deviceContext.isTestEnv)   factor *= 0.7;

    const syncSignals = signals.filter(s => /sync|batch|bulk/i.test(s.data?.url || ''));
    if (syncSignals.length > 5) factor *= 0.8;

    return Math.min(factor, 1.0);
  }

  analyze(signals, deviceContext = {}) {
    const features       = this.extractFeatures(signals);
    const rawScore       = this.score(features);
    const fprFactor      = this.falsePositiveReduction(signals, deviceContext);
    const adjustedScore  = Math.round(rawScore * fprFactor);
    const classification = this.classify(adjustedScore);

    return {
      features,
      rawScore,
      adjustedScore,
      fprFactor,
      classification,
      explanation: this._explain(features, adjustedScore),
    };
  }

  _explain(features, score) {
    const lines = [];
    if (features.requestFrequency > 0.5)
      lines.push(`High request frequency (${(features.requestFrequency * 60).toFixed(0)} req/min)`);
    if (features.errorRate > 0.3)
      lines.push(`Elevated error rate (${(features.errorRate * 100).toFixed(1)}%)`);
    if (features.sensitiveAccess > 0)
      lines.push('Sensitive file system access detected');
    if (features.retryPattern > 0.3)
      lines.push('Abnormal retry behavior');
    if (features.timingDeviation > 0.3)
      lines.push(`Timing anomalies detected (max: ${features.metadata.maxRequestDuration}ms)`);
    if (lines.length === 0)
      lines.push('No significant anomalies detected');
    return lines;
  }
}

module.exports = { AnomalyDetector };
