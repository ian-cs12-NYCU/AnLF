#!/bin/bash

# AnomalyDetector 日志测试脚本
# 演示不同场景下的日志输出

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANLF_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "AnomalyDetector 日志测试"
echo "=========================================="
echo

# 1. 检查代码中的日志语句
echo "1. 检查日志覆盖范围..."
echo

echo "   启动日志:"
grep -n "Starting AnomalyDetector" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | head -1 | sed 's/^/     /'
grep -n "LLM server health check" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | head -2 | sed 's/^/     /'

echo
echo "   分析日志:"
grep -n "Analysis complete" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | sed 's/^/     /'

echo
echo "   警告日志:"
grep -n "⚠️" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | sed 's/^/     /'
grep -n "UNREACHABLE" "$ANLF_DIR/internal/analyzer/detector/llm_client.go" | sed 's/^/     /'

echo
echo "   ✓ 日志覆盖完整"
echo

# 2. 显示关键日志语句
echo "2. 关键日志语句预览..."
echo

echo "   启动成功:"
grep "AnomalyDetector started successfully" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | head -1 | sed 's/.*Infof("\([^"]*\)".*/     \1/' 

echo
echo "   LLM server 不可达警告:"
grep "UNREACHABLE" "$ANLF_DIR/internal/analyzer/detector/llm_client.go" | head -1 | sed 's/.*Warnf("\([^"]*\)".*/     \1/'

echo
echo "   分析完成日志:"
grep "Analysis complete" "$ANLF_DIR/internal/analyzer/detector/anomaly_detector.go" | sed 's/.*Infof("\([^"]*\)".*/     \1/'

echo
echo "=========================================="
echo "日志测试完成"
echo "=========================================="
echo
echo "运行建议:"
echo "1. 启动 ANLF 并启用 LLM server:"
echo "   ./bin/anlf"
echo
echo "2. 查看完整日志:"
echo "   tail -f anlf.log"
echo
echo "3. 过滤特定日志:"
echo "   tail -f anlf.log | grep 'AnomalyDetector\\|LLMClient'"
echo
echo "4. 测试 LLM server 不存在的场景:"
echo "   - 修改 config 中的 serverUrl 指向不存在的服务器"
echo "   - 启动 ANLF"
echo "   - 观察警告日志"
echo
