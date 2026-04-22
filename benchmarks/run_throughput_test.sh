#!/bin/bash

echo "==========================================="
echo "   SDS Performance Benchmark: Throughput   "
echo "==========================================="

if ! command -v iperf3 &> /dev/null; then
    echo "Error: 'iperf3' is not installed. Install with: sudo apt install iperf3"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: ./run_throughput_test.sh <SERVER_IP>"
    echo ""
    echo "Note: You must run 'iperf3 -s' on a machine OUTSIDE the internal network,"
    echo "or on the gateway VM (VM3) if testing local forwarding limits."
    echo "Example: ./run_throughput_test.sh 192.168.1.100"
    exit 1
fi

SERVER_IP=$1
DURATION=10

echo "Connecting to iperf3 server at $SERVER_IP for $DURATION seconds..."
echo "-------------------------------------------"

# Run iperf3 client and format the output
iperf3 -c $SERVER_IP -t $DURATION -O 2

echo "==========================================="
echo "Done. Compare the Sender/Receiver bandwidth with SDS ON and OFF."
