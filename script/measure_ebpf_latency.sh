#!/bin/bash

# 設定你的 eBPF 程式名稱 (根據你的 C code 定義)
# 通常 XDP 進入點函數名稱，例如 "xdp_prog_main" 或 "tc_ingress"
PROG_NAME="xdp_parser_func" 

# 測量持續時間 (秒)
DURATION=10

echo "🔍 正在尋找 eBPF 程式: $PROG_NAME ..."

# 自動抓取 Program ID (使用 json 輸出解析較準確，這裡用 grep/awk 做 MVP 處理)
# 注意：如果有這行指令抓不到，請手動 `bpftool prog list` 確認名稱
PROG_ID=$(bpftool prog list | grep $PROG_NAME | awk '{print $1}' | tr -d ':')

if [ -z "$PROG_ID" ]; then
    echo "❌ 找不到名為 $PROG_NAME 的程式，請確認 AnLF 是否已啟動。"
    exit 1
fi

echo "✅ 找到 Program ID: $PROG_ID"
echo "🚀 開始測量 Overhead (持續 $DURATION 秒)... 請確保背景流量 (100 UEs) 正在運行！"

# 執行 Profile 並將結果存入變數
# bpftool 輸出格式範例:
#        8495 run_cnt
#        4782084 run_time_ns
OUTPUT=$(bpftool prog profile id $PROG_ID duration $DURATION 2>&1)

# 解析輸出
RUN_CNT=$(echo "$OUTPUT" | grep "run_cnt" | awk '{print $1}')
RUN_TIME_NS=$(echo "$OUTPUT" | grep "run_time_ns" | awk '{print $1}')

if [ -z "$RUN_CNT" ] || [ "$RUN_CNT" -eq 0 ]; then
    echo "⚠️  警告: run_cnt 為 0。有沒有打流量？eBPF 沒有被觸發。"
    exit 1
fi

# 計算平均延遲 (使用 bc 處理浮點數)
AVG_LATENCY=$(echo "scale=2; $RUN_TIME_NS / $RUN_CNT" | bc)

echo "------------------------------------------------"
echo "📊 測量結果 (100 UEs Load)"
echo "------------------------------------------------"
echo "總執行次數 (Count) : $RUN_CNT"
echo "總執行時間 (ns)    : $RUN_TIME_NS"
echo "------------------------------------------------"
echo "💡 平均單次執行延遲 : $AVG_LATENCY ns"
echo "------------------------------------------------"

# 論文數據解釋建議
AVG_LATENCY_US=$(echo "scale=4; $AVG_LATENCY / 1000" | bc)
echo "📝 論文論述參考:"
echo "在 100 UEs 負載下，eBPF 平均處理延遲僅為 $AVG_LATENCY ns ($AVG_LATENCY_US μs)。"
echo "相較於 1 秒 (1,000,000 μs) 的偵測視窗，Overhead 佔比極低。"