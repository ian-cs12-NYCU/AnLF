# TLS DPI 功能 - 系统测试手册

## 概述

本手册描述如何进行完整的 TLS Client Hello 侧录 (DPI) 功能测试。该功能在 5G UE 流量监控系统 (AnLF) 中实现，能够在维持高效能统计的同时实时捕捉可疑的 TLS 初始化封包。

## 前置条件

1. **环境配置**
   - Linux 系统（需要内核 >= 5.8，支持 eBPF）
   - root 或具有 CAP_BPF 权限
   - Free5GC 网络环境已启动
   - UE 设备（或模拟器）已连接到网络

2. **代码编译**
   ```bash
   cd /home/vagrant/AnLF/anlf
   make clean build
   ```

3. **验证编译成功**
   ```bash
   ls -la bin/anlf
   # 应该看到可执行文件 bin/anlf
   ```

## 测试流程

### Phase 1: 单元测试验证

运行所有 TLS 相关的单元测试以确保核心组件工作正常：

```bash
cd /home/vagrant/AnLF/anlf
go test -v ./internal/monitor -run "Tls"
```

**预期输出**:
- ✓ TestTlsEventCache - PASS
- ✓ TestTlsEventCacheConcurrency - PASS
- ✓ TestTlsEventCStructLayout - PASS
- ✓ TestTlsEventParsePayload - PASS
- ✓ TestIPConversion - PASS
- ✓ TestHexEncoding - PASS

### Phase 2: 启动 AnLF 系统

1. **验证配置文件**
   ```bash
   cat config/anlfcfg.yaml
   ```

   确保以下配置存在：
   - `xdpInterface`: 流量监控接口（通常是 `upfgtp`）
   - `pollInterval`: 收集周期（建议 5-10 秒用于测试）

2. **启动 AnLF**
   ```bash
   cd /home/vagrant/AnLF/anlf
   sudo ./bin/anlf
   ```

   **预期日志输出**:
   ```
   [INFO][ANLF][Manager] Starting ANLF...
   [INFO][ANLF][Manager] Loading eBPF programs...
   [INFO][ANLF][Manager] Attaching XDP program to interface...
   [INFO][ANLF][TrafficMonitor] Starting TrafficMonitor (poll interval: 5s)...
   [INFO][ANLF][Monitor] TLS event reader started
   ```

   **关键检查点**:
   - 无编译或加载错误
   - TrafficMonitor 正常启动
   - TLS event reader 正常启动

### Phase 3: 生成 HTTPS 流量

在另一个终端窗口中，从 UE 生成 HTTPS 请求以触发 TLS 捕获：

```bash
# 从 UE 容器或主机生成 HTTPS 流量
# 示例：
curl -v https://www.google.com
# 或者
curl -v https://www.baidu.com

# 如果使用 UE 模拟器，请连接到该容器并执行上述命令
```

**预期行为**:
- TLS Client Hello 应该被 eBPF 程序捕获
- 在 AnLF 日志中应该看到 TLS 事件处理

### Phase 4: 验证 TLS 采样数据

当收集周期完成时（通常是 5-10 秒后），检查导出的数据：

```bash
# 导出目录应该包含最新的 JSON 文件
ls -lh output/example/

# 查看最新的推理文件（包含 TLS 数据）
tail -100 output/example/inference_*.json | jq . 2>/dev/null || tail -100 output/example/inference_*.json
```

**验证 JSON 中的 TLS 字段**:
```json
{
  "supi": "imsi-208930000000001",
  "ip": "10.60.0.1",
  "ts": 1642345678,
  "packet_count": 1523,
  "has_tls_sample": true,
  "tls_hello_hex": "160301005a01000056030336..."
}
```

**关键字段检查**:
- `has_tls_sample`: 应该为 `true` 当 HTTPS 流量被捕获
- `tls_hello_hex`: 应该包含 TLS 初始字节（通常以 `160301` 开头，表示 TLS 1.2 握手）

### Phase 5: 验证无重复采样

运行多个 HTTPS 请求，验证同一 Flow 的 TLS 只被采样一次：

```bash
# 生成多个请求到同一目标
for i in {1..5}; do
  curl -s https://www.google.com > /dev/null
  sleep 1
done
```

**验证**:
- 检查收集到的 TLS 数据，应该只包含一个 `tls_hello_hex` 样本
- 不应该出现重复的相同 Payload

### Phase 6: 验证高频流量下的性能

生成高频 HTTPS 流量，验证系统性能不受影响：

```bash
# 使用 ab (Apache Bench) 或 wrk 生成并发连接
ab -n 1000 -c 20 https://example.com/

# 或使用 curl 并发
for i in {1..100}; do
  curl -s https://www.google.com > /dev/null &
done
wait
```

**验证**:
- AnLF 进程 CPU 和内存使用正常
- 没有由于 Perf Buffer 满载导致的错误
- 原始流量统计仍然准确（无套件丢弃）

### Phase 7: 查看日志输出

在 AnLF 运行期间，检查是否有 TLS 相关的日志消息：

```bash
# 关键搜索项：
# - "Cached TLS event from"  - 表示成功捕获
# - "Added TLS sample for UE" - 表示成功集成到报告
# - 任何 "Error reading perf" - 表示可能的问题

# 实时查看日志（如果使用日志管理）
# 或检查 AnLF 的标准输出
```

### Phase 8: Fail-Open 验证

验证当 Perf Buffer 满载时系统的行为：

1. **高频生成流量**
   ```bash
   # 生成非常高频的 HTTPS 连接
   while true; do
     curl -s https://www.google.com > /dev/null 2>&1 &
   done
   ```

2. **观察行为**
   - AnLF 应该仍在正常运行
   - 流量统计应该准确
   - 不应该有套件丢弃 (XDP_DROP)
   - TLS 捕获可能失败或丢弃，但不应影响原始流量

## 完整系统测试步骤

### 一次性完整测试脚本

```bash
#!/bin/bash
set -e

echo "=== Phase 1: 单元测试 ==="
cd /home/vagrant/AnLF/anlf
go test -v ./internal/monitor -run "Tls"

echo ""
echo "=== Phase 2: 编译 ==="
make clean build
echo "✓ Build successful"

echo ""
echo "=== Phase 3: 启动 AnLF (后台运行) ==="
sudo nohup ./bin/anlf > anlf.log 2>&1 &
ANLF_PID=$!
echo "AnLF started with PID: $ANLF_PID"
sleep 3

echo ""
echo "=== Phase 4: 生成 HTTPS 流量 ==="
# 生成 HTTPS 请求
for i in {1..3}; do
  echo "Request $i..."
  curl -s -m 5 https://www.google.com > /dev/null || true
  sleep 1
done

echo ""
echo "=== Phase 5: 等待数据收集 ==="
sleep 8

echo ""
echo "=== Phase 6: 检查导出的数据 ==="
if [ -d "output/example" ]; then
  echo "✓ Output directory exists"
  ls -lh output/example/
  echo ""
  echo "Latest inference file content (first 20 lines):"
  LATEST=$(ls -t output/example/inference_*.json 2>/dev/null | head -1)
  if [ -n "$LATEST" ]; then
    head -20 "$LATEST"
  fi
else
  echo "⚠ Output directory not found"
fi

echo ""
echo "=== Phase 7: 停止 AnLF ==="
kill $ANLF_PID || true
wait $ANLF_PID 2>/dev/null || true
echo "✓ AnLF stopped"

echo ""
echo "=== Test Complete ==="
```

## 预期测试结果

### 成功的 TLS 捕获表现

1. **日志中看到**:
   ```
   [DEBUG][ANLF][Monitor] Cached TLS event from 10.60.0.1: 5 bytes
   [DEBUG][ANLF][Monitor] Added TLS sample for UE 10.60.0.1: 10 bytes
   ```

2. **JSON 输出中看到**:
   ```json
   {
     "has_tls_sample": true,
     "tls_hello_hex": "160301..."
   }
   ```

3. **性能指标**:
   - 无额外延迟
   - 内存占用稳定
   - 原始流量统计准确

### 常见问题排查

| 问题 | 症状 | 解决方案 |
|------|------|---------|
| Perf Buffer 未加载 | 日志中无 TLS 消息 | 检查 eBPF 编译，确保 `TlsEvents` map 已生成 |
| 无 HTTPS 流量 | `has_tls_sample` 总是 false | 确认生成了 HTTPS 请求，检查网络连接 |
| 内存泄漏 | 内存持续增长 | 检查 Perf Reader 是否正确清理，确认没有 goroutine 泄漏 |
| Byte Order 错误 | IP 地址错误（如 `1.10.60.0` 而不是 `10.60.0.1`) | 验证 C 端和 Go 端的字节序转换一致 |
| 重复采样 | 同一 Flow 多次出现 TLS 样本 | 检查 Flow State 管理逻辑，确保 Bitmask 正确 |

## 性能基准

在标准配置下（poll interval = 5s）：

- **CPU 使用**: < 5% 增加
- **内存增加**: < 10 MB
- **TLS 捕获延迟**: < 1 ms
- **Perf Buffer 推荐大小**: 4-8 MB
- **支持的最大 Flow**: 65536（LRU 自动回收）

## 测试完成标准

✅ 所有单元测试通过  
✅ AnLF 正常启动，无编译错误  
✅ HTTPS 流量生成时看到 TLS 采样  
✅ JSON 输出中正确包含 `tls_hello_hex` 字段  
✅ 无重复采样现象  
✅ 高频流量下系统性能稳定  
✅ 没有套件丢弃现象  

## 调试建议

如果测试失败，按以下步骤调试：

1. **启用详细日志**
   ```bash
   # 修改 logger 配置以显示 DEBUG 级别日志
   ```

2. **检查 eBPF 验证器输出**
   ```bash
   # 查看 dmesg 中的任何 eBPF 相关错误
   dmesg | grep -i ebpf | tail -20
   ```

3. **验证 Perf Buffer**
   ```bash
   # 检查 /proc/sys/kernel/perf_event_paranoid
   cat /proc/sys/kernel/perf_event_paranoid
   # 应该 <= 1 以允许 perf 事件读取
   ```

4. **监视进程状态**
   ```bash
   # 实时监视 AnLF 进程
   watch -n 1 'ps aux | grep anlf'
   ```

## 完成后的清理

```bash
# 停止 AnLF（如果仍在运行）
sudo pkill -f "bin/anlf"

# 清理输出文件
rm -rf output/*

# 恢复代码（如果进行了调试修改）
git checkout -- .
```

## 相关文档

- [TLS_CAPTURE.md](./TLS_CAPTURE.md) - 功能设计文档
- [TESTING_EBPF.md](./TESTING_EBPF.md) - eBPF 测试指南
- [architecture.md](./architecture.md) - 系统架构文档
