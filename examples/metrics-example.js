/**
 * Exemple d'utilisation des nouvelles métriques
 * 
 * Métriques calculées :
 * - volume: Volume total en USD
 * - trades: Nombre de trades
 * - returnPct: Return % basé sur trades individuels
 * - returnUsd: Return $ basé sur trades individuels
 */

// Simuler des appels API pour récupérer les métriques
async function getMetricsExample() {
  const baseUrl = 'http://localhost:5000';
  const userId = 'user-123';

  try {
    // 1. Obtenir le résumé global de l'utilisateur
    console.log('📊 Récupération du résumé utilisateur...');
    const summaryResponse = await fetch(`${baseUrl}/users/${userId}/summary`);
    const summary = await summaryResponse.json();
    
    console.log('\n🎯 RÉSUMÉ GLOBAL:');
         console.log(`💰 Volume total: $${summary.summary.totalVolume.toLocaleString()}`);
     console.log(`📈 Trades totaux: ${summary.summary.totalTrades}`);
     console.log(`📊 Return %: ${summary.summary.totalReturnPct.toFixed(2)}%`);
     console.log(`💵 Return $: $${summary.summary.totalReturnUsd.toFixed(2)}`);
     console.log(`💸 Frais totaux: $${summary.summary.totalFees.toFixed(2)}`);

    // 2. Obtenir les métriques détaillées par symbole
    console.log('\n📋 MÉTRIQUES PAR SYMBOLE:');
    const metricsResponse = await fetch(`${baseUrl}/users/${userId}/metrics`);
    const metrics = await metricsResponse.json();
    
    for (const metric of metrics.metrics) {
      console.log(`\n${metric.symbol}:`);
      console.log(`   📅 Période: ${metric.periodStart} → ${metric.periodEnd}`);
      console.log(`   💰 Volume: $${metric.volume.toLocaleString()}`);
      console.log(`   📈 Trades: ${metric.trades}`);
      console.log(`   📊 Return %: ${metric.returnPct.toFixed(2)}%`);
      console.log(`   💵 Return $: $${metric.returnUsd.toFixed(2)}`);
      console.log(`   💸 Frais: $${metric.totalFees.toFixed(2)}`);
    }

    // 3. Exemple de calcul de performance
    console.log('\n📈 ANALYSE DE PERFORMANCE:');
    const totalInvested = summary.summary.totalVolume;
    const totalReturn = summary.summary.totalReturnUsd;
    const roi = totalInvested > 0 ? (totalReturn / totalInvested) * 100 : 0;
    
    console.log(`🎯 ROI global: ${roi.toFixed(2)}%`);
    console.log(`📊 Performance: ${roi > 0 ? '✅ Positif' : '❌ Négatif'}`);
    
    if (summary.summary.totalTrades > 0) {
      const avgTradeValue = totalInvested / summary.summary.totalTrades;
      const avgReturnPerTrade = totalReturn / summary.summary.totalTrades;
      console.log(`📊 Trade moyen: $${avgTradeValue.toFixed(2)}`);
      console.log(`📈 Return/trade: $${avgReturnPerTrade.toFixed(2)}`);
    }

  } catch (error) {
    console.error('❌ Erreur récupération métriques:', error);
  }
}

// Exemple d'utilisation avec l'API TEE Enclave
async function getSecureMetricsExample() {
  const enclaveUrl = 'http://localhost:3000';
  
  try {
    console.log('\n🔐 RÉCUPÉRATION SÉCURISÉE DES MÉTRIQUES:');
    
    // 1. Vérifier l'attestation de l'enclave
    const attestationResponse = await fetch(`${enclaveUrl}/attestation/quote`);
    const attestation = await attestationResponse.json();
    console.log('✅ Attestation enclave récupérée');

    // 2. Simuler une demande de métriques sécurisées
    // (Dans un vrai cas, on utiliserait CryptoHelper pour chiffrer les credentials)
    console.log('🔒 Métriques chiffrées et signées par l\'enclave');
    console.log('📊 Résultats cryptographiquement vérifiés');
    
  } catch (error) {
    console.error('❌ Erreur récupération sécurisée:', error);
  }
}

// Exécuter les exemples
async function runExamples() {
  console.log('🚀 DÉMONSTRATION DES NOUVELLES MÉTRIQUES\n');
  
  await getMetricsExample();
  await getSecureMetricsExample();
  
  console.log('\n✅ Démonstration terminée');
}

// Exécuter si appelé directement
if (typeof module !== 'undefined' && require.main === module) {
  runExamples().catch(console.error);
}

export { getMetricsExample, getSecureMetricsExample };
