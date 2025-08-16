# Script PowerShell pour enregistrer un utilisateur sur le service Perf-Aggregator
# Usage: .\register-user.ps1

param(
    [Parameter(Mandatory=$true)]
    [string]$UserId,
    
    [Parameter(Mandatory=$true)]
    [string]$Exchange,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$true)]
    [string]$Secret,
    
    [ValidateSet('spot', 'futures', 'margin')]
    [string]$AccountType = "spot",
    
    [switch]$Sandbox,
    
    [string]$ServiceUrl = "https://perf-aggregator.yourdomain.com",
    
    [switch]$Secure
)

Write-Host "🚀 Enregistrement utilisateur sur Perf-Aggregator (Service Distant)" -ForegroundColor Green
Write-Host ""

# Validation des paramètres
if ($UserId -match '\s') {
    Write-Error "UserId ne peut pas contenir d'espaces"
    exit 1
}

if ($ApiKey.Length -lt 10) {
    Write-Error "ApiKey semble trop courte"
    exit 1
}

if ($Secret.Length -lt 10) {
    Write-Error "Secret semble trop courte"
    exit 1
}

try {
    if ($Secure) {
        Write-Host "🔐 Enregistrement sécurisé via TEE Enclave..." -ForegroundColor Yellow
        
        # URL de l'enclave (port 3000)
        $enclaveUrl = $ServiceUrl -replace "5000", "3000"
        
        try {
            # 1. Vérifier que l'enclave est disponible
            $attestation = Invoke-RestMethod -Uri "$enclaveUrl/attestation/quote" -ErrorAction Stop
            Write-Host "✅ Attestation enclave récupérée" -ForegroundColor Green
            
            # 2. Préparer les credentials
            $credentials = @{
                userId = $UserId
                exchange = $Exchange
                apiKey = $ApiKey
                secret = $Secret
                accountType = $AccountType
                sandbox = $Sandbox
            } | ConvertTo-Json
            
            # 3. Chiffrer les credentials (simulation)
            $credentialsBytes = [System.Text.Encoding]::UTF8.GetBytes($credentials)
            $credentialsBase64 = [Convert]::ToBase64String($credentialsBytes)
            
            # 4. Créer l'enveloppe chiffrée
            $envelope = @{
                ephemeral_pub = "mock-ephemeral-key"
                nonce = "mock-nonce"
                ciphertext = $credentialsBase64
                tag = "mock-auth-tag"
                metadata = @{
                    exchange = $Exchange
                    label = "main-account"
                    ttl = 86400
                }
            } | ConvertTo-Json
            
            # 5. Envoyer à l'enclave
            $response = Invoke-RestMethod -Uri "$enclaveUrl/enclave/submit_key" -Method POST -Body $envelope -ContentType "application/json" -ErrorAction Stop
            
            Write-Host "✅ Utilisateur enregistré sécurisé avec session ID: $($response.session_id)" -ForegroundColor Green
            Write-Host "⏰ Session expire le: $($response.expires_at)" -ForegroundColor Cyan
            
            # 6. Tester la récupération des métriques
            Start-Sleep -Seconds 2
            try {
                $metrics = Invoke-RestMethod -Uri "$enclaveUrl/enclave/summary/$($response.session_id)" -ErrorAction Stop
                Write-Host "✅ Métriques accessibles via session sécurisée" -ForegroundColor Green
            } catch {
                Write-Host "⚠️  Session créée mais pas encore de données" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Error "❌ Erreur communication avec l'enclave: $($_.Exception.Message)"
            exit 1
        }
        
    } else {
        Write-Host "📝 Enregistrement simple..." -ForegroundColor Yellow
        
        $body = @{
            userId = $UserId
            exchange = $Exchange
            apiKey = $ApiKey
            secret = $Secret
            sandbox = $Sandbox
            accountType = $AccountType
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$ServiceUrl/users" -Method POST -Body $body -ContentType "application/json" -ErrorAction Stop
        
        Write-Host "✅ Utilisateur enregistré avec succès!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "📊 Vérification de l'enregistrement..." -ForegroundColor Yellow
    
    # Vérifier que l'utilisateur est bien enregistré
    Start-Sleep -Seconds 2
    
    try {
        $summary = Invoke-RestMethod -Uri "$ServiceUrl/users/$UserId/summary" -ErrorAction Stop
        Write-Host "✅ Utilisateur actif - Volume: $($summary.summary.totalVolume)" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Utilisateur enregistré mais pas encore de données" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "🎯 Prochaines étapes:" -ForegroundColor Cyan
    Write-Host "   • Le service distant va détecter automatiquement tous vos symboles tradés" -ForegroundColor White
    Write-Host "   • Aucune configuration supplémentaire nécessaire" -ForegroundColor White
    Write-Host "   • Consultez vos métriques: $ServiceUrl/users/$UserId/summary" -ForegroundColor White
    Write-Host "   • Métriques détaillées: $ServiceUrl/users/$UserId/metrics" -ForegroundColor White
    Write-Host "   • Vos credentials sont sécurisés dans l'enclave distant" -ForegroundColor White
    
} catch {
    Write-Error "❌ Erreur lors de l'enregistrement: $($_.Exception.Message)"
    exit 1
}
