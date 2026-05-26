Profileur de Comportement Dynamique

Vue d’ensemble

Le Profileur de Comportement Dynamique est un outil Node.js léger, sans dépendances externes, qui instrumente et profile le comportement à l’exécution des intégrations backend d’applications mobiles. Il collecte des signaux sur six surfaces observables (réseau, système de fichiers, journaux, erreurs, crashes, temps d’exécution), détecte des anomalies via un moteur de scoring paramétrable, et génère des rapports JSON structurés contenant des hypothèses de causes racines et des recommandations d’action, alignées sur les référentiels OWASP MASVS/MASTG.

Contrairement aux outils d’analyse dynamique traditionnels qui nécessitent des appareils rootés, des ROMs personnalisées ou des agents complexes, ce profileur est conçu pour être intégré directement dans vos pipelines CI/CD ou utilisé comme bibliothèque dans vos environnements Node.js.


               Fonctionnalités principales

- Modèle de signaux unifié – six types de signaux (réseau, fichier, journal, erreur, crash, timing) permettant une corrélation d’anomalies inter‑surfaces
- Scoring d’anomalies par seuils – score additif par signal, avec émission d’événements temps réel via EventEmitter
- Vecteur de caractéristiques pondéré et score de risque global – évaluation de session à cinq dimensions, avec réduction des faux positifs selon l’environnement (facteur α)
- Génération d’hypothèses de causes racines – hypothèses structurées avec niveau de sévérité et mesures correctives référencées OWASP
- Zéro dépendance – n’utilise que la bibliothèque standard de Node.js
- Prêt pour les CI/CD – sortie JSON et code de retour pour intégration fluide
- Mode CLI et bibliothèque – utilisable en ligne de commande ou importé comme module npm


                 Architecture

Le découpage suit un pipeline à trois couches :

Couche de collecte des signaux (profiler.js)
API typée pour instrumenter les événements : collectNetworkRequest, collectFileAccess, collectLog, etc.

Couche de scoring et détection (anomaly-detector.js)
Évalue chaque signal par rapport à des seuils configurables, applique un score additif et émet les anomalies.

Couche de reporting (profiler.js)
Agrège les données de session et produit un rapport JSON structuré avec hypothèses et recommandations.


Installation

Prérequis : Node.js v18 ou supérieur, npm

Depuis GitHub :
git clone https://github.com/bsmaalaoui/dynamic-behavior-profiler.git
cd dynamic-behavior-profiler
npm install

Installation globale (CLI) :
npm install -g dynamic-behavior-profiler

Installation comme bibliothèque locale :
npm install dynamic-behavior-profiler


Utilisation

Mode CLI (simulation intégrée) :
node run.js

Exécute une session de simulation d’application bancaire comportant cinq vulnérabilités injectées, affiche un résumé dans la console et génère le fichier report.json.

Exemple de sortie console :
Session ID   : session_1778377328726
Signaux totaux: 34
Anomalies     : 9
Taux d’erreur : 24,0%
Score de risque : 44/100
Niveau de risque : ÉLEVÉ

Hypothèses de causes racines :
1. [CRITIQUE] Données sensibles (jetons, mots de passe) écrites dans les journaux
   MASVS : MSTG-STORAGE-3
   Recommandation : Supprimer les champs sensibles des sorties log.
2. [ÉLEVÉ] Accès à 2 chemins sensibles
   - /data/data/com.myapp/shared_prefs/credentials.xml
   - /proc/net/tcp
   Recommandation : Vérifier les accès fichiers ; restreindre via FileProvider Android.

Mode bibliothèque (intégration dans votre code) :
const { DynamicBehaviorProfiler } = require('dynamic-behavior-profiler');

const profileur = new DynamicBehaviorProfiler({ 
  deviceContext: 'production'  // 'production', 'staging' ou 'development'
});

profileur.collectNetworkRequest('https://api.myapp.com/v1/user', 'GET', 200, 210);
profileur.collectFileAccess('/data/data/com.myapp/shared_prefs/tokens.xml', 'read');
profileur.collectLog('DEBUG', 'Token: eyJhbGciOiJIUzI1...', 'AuthManager');

const rapport = profileur.generateReport();
console.log(JSON.stringify(rapport, null, 2));

Intégration dans un pipeline CI/CD :
node run.js
NIVEAU_RISQUE=$(jq -r '.riskLevel' report.json)
if [ "$NIVEAU_RISQUE" = "ÉLEVÉ" ] || [ "$NIVEAU_RISQUE" = "CRITIQUE" ]; then
  exit 1
fi


Configuration

Contexte d’environnement (deviceContext) :
- production – α = 1,0 (aucune réduction)
- staging    – α = 0,8 (réduction mineure pour le trafic de test)
- development – α = 0,5 (réduction significative : logs de debug et rafales de requêtes sont attendus)

À définir lors de l’instanciation :
const profileur = new DynamicBehaviorProfiler({ deviceContext: 'staging' });

Seuils de scoring (valeurs par défaut, modifiables dans profiler.js) :
- MAX_REQUEST_PER_SECOND = 10 (spam >10 requêtes/sec)
- MAX_RETRY_COUNT = 5 (boucle de reprise infinie ≥5)
- SLOW_REQUEST_MS = 3000 (réponse lente >3000 ms)
- SENSITIVE_PATH_REGEX : /shared_prefs/,/proc/net/
- CREDENTIAL_REGEX : /token|password|secret/i


Taxonomie des signaux et règles de scoring

Six types de signaux avec scores associés :

Crash : +100

Journal (log) contenant un mot‑clé sensible (token, password) : +70

Requête réseau en spam (>10 par seconde) : +60

Accès fichier vers un chemin sensible : +55

Boucle de reprise infinie (≥5 tentatives) : +50

Requête vers un endpoint suspect : +40

Réponse lente (>3000 ms) : +25

N’importe quelle erreur : +20

Un signal avec un score ≥ 40 est classé comme anomalie et émis via EventEmitter.

Vecteur de caractéristiques et score global de risque

Cinq caractéristiques normalisées, calculées par AnomalyDetector :

- requestFrequency (poids 0,25) : min(nb requêtes / 60, 1)
- errorRate (poids 0,20) : erreurs / requêtes
- sensitiveAccess (poids 0,25) : min(signaux fichiers anormaux / 5, 1)
- retryPattern (poids 0,15) : min(reprises / 10, 1)
- timingDeviation (poids 0,15) : min(durée max / 10000, 1)

Score brut : S = 100 × Σ (poids × fk)
Score ajusté par l’environnement : S′ = α × S

Niveaux de risque :
- CRITIQUE : 70 à 100
- ÉLEVÉ   : 40 à 69
- MOYEN   : 20 à 39
- FAIBLE  : 0 à 19


Exemple de sortie JSON

{
  "sessionId": "session_1778377328726",
  "riskScore": 44,
  "riskLevel": "ÉLEVÉ",
  "signals": {
    "network_request": 25,
    "app_log": 4,
    "timing": 2,
    "file_access": 2,
    "error": 1
  },
  "anomalies": [
    {
      "type": "app_log",
      "score": 70,
      "severity": "CRITIQUE",
      "message": "JWT token écrit dans le log de debug"
    }
  ],
  "hypotheses": [
    {
      "type": "data_leakage",
      "severity": "CRITIQUE",
      "recommendation": "Supprimer les champs sensibles des logs"
    }
  ],
  "recommendations": [
    "Supprimer les champs sensibles des logs avec les règles ProGuard",
    "Vérifier les accès fichiers ; restreindre via FileProvider Android",
    "Implémenter un backoff exponentiel avec jitter pour /auth/token"
  ]
}


Assurance qualité

- Environ 450 lignes de code source (3 fichiers)
- 0 dépendance externe d’exécution
- Couverture de code : 87% (lignes)
- Duplication : <5%
- Versions Node.js testées : v18, v20, v22
- Licence : MIT

Exécution des tests :
npm test                 # tests unitaires + intégration
npm run test:coverage    # rapport de couverture


Limitations (version actuelle)

- Instrumentation au niveau source uniquement – pas d’agent Android natif ; nécessite une intégration dans le code.
- Pas de proxy HTTP temps réel – impossible d’intercepter le trafic réseau sans instrumentation.
- Validation sur traces synthétiques – pas encore évalué sur des APK réels avec étiquettes de vérité terrain.


               Travaux futurs

1. Mode proxy HTTP pour intercepter le trafic réel sans modification source.
2. Évaluation formelle (précision, rappel, F1) sur des APK Android open source.
3. Stockage persistant des sessions pour analyses de tendances.
4. Extension de la taxonomie des signaux (permissions, ContentProvider).
5. DSL de règles personnalisables sans modification du code source.


Contribution

Les contributions sont les bienvenues. Merci de suivre la procédure standard GitHub (fork, branche, tests, pull request).

Avant de soumettre une pull request, assurez-vous que tous les tests passent :
npm test


Licence

Licence MIT – fichier LICENSE inclus.


Citation

Si vous utilisez cet outil dans un travail de recherche :
@software{alaoui2026dynamic,
  author = {Basma Alaoui},
  title = {Profileur de Comportement Dynamique : Analyse comportementale à l'exécution et détection d'anomalies pour la sécurité des applications mobiles},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/bsmaalaoui/dynamic-behavior-profiler},
  doi = {10.5281/zenodo.XXXXXXXX}
}


Contact

Basma Alaoui – basma.alaoui@emsi.ma
EMSI Marrakech, Maroc

Lien du projet : https://github.com/bsmaalaoui/dynamic-behavior-profiler

Conçu pour la sécurité des applications mobiles.
