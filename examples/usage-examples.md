# Exemples d'utilisation du service Perf-Aggregator

## 🏠 **Environnements disponibles**

### **1. Service de développement (local)**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "http://localhost:5000"
```

### **2. Service de staging**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://staging.perf-aggregator.com"
```

### **3. Service de production (enclave sécurisé)**
```powershell
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com" -Secure
```

## 🔐 **Enregistrement sécurisé (recommandé pour production)**

### **Avec TEE Enclave**
```powershell
# Enregistrement avec chiffrement et enclave sécurisé
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com" -Secure
```

### **Différents types de comptes**
```powershell
# Compte spot
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "spot" -ServiceUrl "https://perf-aggregator.com"

# Compte futures
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "futures" -ServiceUrl "https://perf-aggregator.com"

# Compte margin
.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey "abc123..." -Secret "xyz789..." -AccountType "margin" -ServiceUrl "https://perf-aggregator.com"
```

## 📊 **Consultation des métriques**

### **Résumé global**
```powershell
# PowerShell
$summary = Invoke-RestMethod -Uri "https://perf-aggregator.com/users/trader-john/summary"
Write-Host "Volume: $($summary.summary.totalVolume)"
Write-Host "Return: $($summary.summary.totalReturnPct)%"
```

### **Métriques détaillées**
```powershell
# PowerShell
$metrics = Invoke-RestMethod -Uri "https://perf-aggregator.com/users/trader-john/metrics"
foreach ($metric in $metrics.metrics) {
    Write-Host "$($metric.symbol): $($metric.returnPct)% return"
}
```

### **cURL**
```bash
# Résumé
curl https://perf-aggregator.com/users/trader-john/summary

# Métriques détaillées
curl https://perf-aggregator.com/users/trader-john/metrics
```

## 🌐 **Intégration web**

### **JavaScript**
```javascript
// Récupérer le résumé
const summary = await fetch('https://perf-aggregator.com/users/trader-john/summary')
  .then(r => r.json());

console.log(`Volume: $${summary.summary.totalVolume}`);
console.log(`Return: ${summary.summary.totalReturnPct}%`);
```

### **Python**
```python
import requests

# Récupérer le résumé
response = requests.get('https://perf-aggregator.com/users/trader-john/summary')
summary = response.json()

print(f"Volume: ${summary['summary']['totalVolume']}")
print(f"Return: {summary['summary']['totalReturnPct']}%")
```

## 🔧 **Configuration des variables d'environnement**

### **PowerShell**
```powershell
$env:PERF_AGGREGATOR_URL = "https://perf-aggregator.com"
$env:BINANCE_API_KEY = "votre-api-key"
$env:BINANCE_SECRET = "votre-secret"

.\register-user.ps1 -UserId "trader-john" -Exchange "binance" -ApiKey $env:BINANCE_API_KEY -Secret $env:BINANCE_SECRET -ServiceUrl $env:PERF_AGGREGATOR_URL
```

### **Bash/Linux**
```bash
export PERF_AGGREGATOR_URL="https://perf-aggregator.com"
export BINANCE_API_KEY="votre-api-key"
export BINANCE_SECRET="votre-secret"

# Utiliser avec curl
curl -X POST "$PERF_AGGREGATOR_URL/users" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "trader-john",
    "exchange": "binance",
    "apiKey": "'$BINANCE_API_KEY'",
    "secret": "'$BINANCE_SECRET'",
    "accountType": "spot"
  }'
```

## 🚨 **Sécurité**

### **Recommandations**
- ✅ Utilisez toujours HTTPS en production
- ✅ Activez l'option `-Secure` pour le chiffrement
- ✅ Utilisez des API keys avec permissions limitées
- ✅ Activez le sandbox pour les tests
- ❌ Ne partagez jamais vos credentials
- ❌ N'utilisez pas localhost en production

### **Permissions API recommandées**
- ✅ Lecture des trades
- ✅ Lecture des ordres
- ❌ Trading automatique
- ❌ Retrait de fonds
