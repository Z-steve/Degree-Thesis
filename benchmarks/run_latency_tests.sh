#!/bin/bash

# Configuration
TEST_DOMAIN="google.com"
ITERATIONS=20

echo "==========================================="
echo "   SDS Performance Benchmark: Latency      "
echo "==========================================="
echo "Testing against: $TEST_DOMAIN"
echo "Iterations: $ITERATIONS"
echo "-------------------------------------------"

# Ensure dependencies are installed
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' is not installed. Install with: sudo apt install dnsutils"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "Error: 'curl' is not installed. Install with: sudo apt install curl"
    exit 1
fi

echo "1. Testing DNS Resolution Time..."
TOTAL_DNS_TIME=0

for i in $(seq 1 $ITERATIONS); do
    # Extract query time in msec
    QUERY_TIME=$(dig $TEST_DOMAIN | grep "Query time" | awk '{print $4}')
    
    if [ -z "$QUERY_TIME" ]; then
        QUERY_TIME=0
    fi
    
    TOTAL_DNS_TIME=$((TOTAL_DNS_TIME + QUERY_TIME))
    echo -ne "   Request $i: ${QUERY_TIME} ms\r"
    sleep 0.1 # Slight delay to not overwhelm the network artificially
done

AVG_DNS=$((TOTAL_DNS_TIME / ITERATIONS))
echo -e "\n-> Average DNS Query Time: ${AVG_DNS} ms"
echo "-------------------------------------------"

echo "2. Testing HTTP Connection Setup (TTFB)..."
TOTAL_CURL_TIME=0

for i in $(seq 1 $ITERATIONS); do
    # Extract time_connect in seconds and convert to ms
    TIME_CONNECT=$(curl -o /dev/null -s -w "%{time_connect}\n" https://$TEST_DOMAIN)
    
    # Use awk to do floating point math and convert to integer ms
    MS_CONNECT=$(echo "$TIME_CONNECT" | awk '{printf "%d", $1 * 1000}')
    
    TOTAL_CURL_TIME=$((TOTAL_CURL_TIME + MS_CONNECT))
    echo -ne "   Request $i: ${MS_CONNECT} ms\r"
    sleep 0.1
done

AVG_CURL=$((TOTAL_CURL_TIME / ITERATIONS))
echo -e "\n-> Average TCP/TLS Connect Time: ${AVG_CURL} ms"
echo "==========================================="
echo "Done. Compare these numbers with SDS ON and OFF."
