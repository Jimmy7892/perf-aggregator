#!/bin/bash
# Simple API usage example with cURL
# No client library needed - direct HTTP calls

ENCLAVE_URL="https://perf-aggregator.company.com"

echo "🚀 Perf-Aggregator API Example"
echo "================================"

# 1. Submit encrypted credentials
echo -e "\n📝 Submitting encrypted credentials..."
RESPONSE=$(curl -s -X POST "$ENCLAVE_URL/enclave/submit_key" \
  -H "Content-Type: application/json" \
  -d '{
    "ephemeral_pub": "mock-ephemeral-key",
    "nonce": "mock-nonce",
    "ciphertext": "mock-encrypted-credentials",
    "tag": "mock-auth-tag",
    "metadata": {
      "exchange": "binance",
      "label": "main-account",
      "ttl": 86400
    }
  }')

SESSION_ID=$(echo $RESPONSE | jq -r '.session_id')
echo "✅ Session created: $SESSION_ID"

# 2. Get metrics
echo -e "\n📊 Fetching metrics..."
METRICS=$(curl -s "$ENCLAVE_URL/enclave/metrics/$SESSION_ID")

echo -e "\n📈 Performance Metrics:"
echo "$METRICS" | jq '.'

echo -e "\n✅ Example completed!"
