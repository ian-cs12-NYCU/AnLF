#!/bin/bash
# ==============================================================================
# AnLF eBPF Latency Measurement Tool (Delta Method)
# ==============================================================================
# Purpose: Measure average execution time of XDP program via cumulative stats.
# Target:  Linux Kernel 5.1+ (Requires kernel.bpf_stats_enabled=1)
# ==============================================================================

PROG_NAME="anlf_xdp_main"
DURATION=10

# ------------------------------------------------------------------------------
# 1. Pre-flight Checks
# ------------------------------------------------------------------------------
echo "[*] Checking system configuration..."

# Check if BPF stats are enabled
STATS_ENABLED=$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null)
if [ "$STATS_ENABLED" != "1" ]; then
    echo "[!] Error: kernel.bpf_stats_enabled is not set to 1."
    echo "    Run: sudo sysctl -w kernel.bpf_stats_enabled=1"
    exit 1
fi

# Find Program ID
PROG_ID=$(bpftool prog list | grep "$PROG_NAME" | awk '{print $1}' | tr -d ':')

if [ -z "$PROG_ID" ]; then
    echo "[!] Error: Program '$PROG_NAME' not found."
    exit 1
fi

echo "[+] Target Program ID: $PROG_ID"
echo "[+] Measurement Window: $DURATION seconds"
echo "------------------------------------------------------------------------------"

# ------------------------------------------------------------------------------
# 2. Capture Start State (T0)
# ------------------------------------------------------------------------------
echo "[*] Capturing baseline stats (T0)..."
OUTPUT_START=$(bpftool prog show id $PROG_ID)
START_NS=$(echo "$OUTPUT_START" | grep -o 'run_time_ns [0-9]*' | awk '{print $2}')
START_CNT=$(echo "$OUTPUT_START" | grep -o 'run_cnt [0-9]*' | awk '{print $2}')

# ------------------------------------------------------------------------------
# 3. Wait for Traffic
# ------------------------------------------------------------------------------
echo "[*] Waiting..."
sleep $DURATION

# ------------------------------------------------------------------------------
# 4. Capture End State (T1)
# ------------------------------------------------------------------------------
echo "[*] Capturing final stats (T1)..."
OUTPUT_END=$(bpftool prog show id $PROG_ID)
END_NS=$(echo "$OUTPUT_END" | grep -o 'run_time_ns [0-9]*' | awk '{print $2}')
END_CNT=$(echo "$OUTPUT_END" | grep -o 'run_cnt [0-9]*' | awk '{print $2}')

# ------------------------------------------------------------------------------
# 5. Calculation
# ------------------------------------------------------------------------------
DELTA_NS=$((END_NS - START_NS))
DELTA_CNT=$((END_CNT - START_CNT))

echo "------------------------------------------------------------------------------"
echo "MEASUREMENT RESULTS"
echo "------------------------------------------------------------------------------"
printf "%-25s : %d\n" "Delta Packets (Count)" "$DELTA_CNT"
printf "%-25s : %d ns\n" "Delta Time (Total)" "$DELTA_NS"

if [ "$DELTA_CNT" -eq 0 ]; then
    echo "[!] Warning: No packets processed during the window."
    echo "    Average latency cannot be calculated."
else
    # Calculate average (ns)
    AVG_LATENCY=$(echo "scale=2; $DELTA_NS / $DELTA_CNT" | bc)
    # Calculate average (us) for readability
    AVG_LATENCY_US=$(echo "scale=4; $AVG_LATENCY / 1000" | bc)
    
    # Calculate PPS
    PPS=$(echo "$DELTA_CNT / $DURATION" | bc)

    printf "%-25s : %.2f ns (%.4f us)\n" "Avg Latency per Packet" "$AVG_LATENCY" "$AVG_LATENCY_US"
    printf "%-25s : %d pps\n" "Throughput" "$PPS"
fi
echo "=============================================================================="