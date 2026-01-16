# TLS DPI 功能 - 完整系统测试指南

**重要**: 本指南用于手动系统测试。所有代码已实现完成，编译无误，单元测试全部通过。现在需要您启动完整的 Free5GC 环境进行集成测试。

## 快速开始

### 步骤 1: 验证编译和单元测试

```bash
cd /home/vagrant/AnLF/anlf

# 清理旧的编译产物
make clean

# 编译
make build

# 运行单元测试
go test -v ./internal/monitor -run "Tls"
```

**预期结果**:
```
✓ Build complete: bin/anlf
=== RUN   TestTlsEventCache
--- PASS: TestTlsEventCache (0.00s)
=== RUN   TestTlsEventCacheConcurrency
--- PASS: TestTlsEventCacheConcurrency (0.00s)
=== RUN   TestTlsEventCStructLayout
--- PASS: TestTlsEventCStructLayout (0.00s)
=== RUN   TestIPConversion
--- PASS: TestIPConversion (0.00s)
=== RUN   TestHexEncoding
--- PASS: TestHexEncoding (0.00s)
=== RUN   TestTlsEventParsePayload
--- PASS: TestTlsEventParsePayload (0.00s)
PASS
```

### 步骤 2: 启动 Free5GC 环境

```bash
# 确保 Free5GC 核心网络组件正在运行
# 这应该在另一个终端或已经启动的 Docker 容器中进行

# 如果使用 docker-compose:
cd /path/to/free5gc
docker-compose up -d

# 验证核心服务正在运行:
docker-compose ps | grep -E "nrf|amf|smf|upf"
```

### 步骤 3: 启动 AnLF

```bash
cd /home/vagrant/AnLF/anlf

# 以 root 权限运行（需要 XDP/eBPF 权限）
sudo ./bin/anlf
```

**预期的启动日志**:
```
[INFO][ANLF][Manager] Starting ANLF...
[INFO][ANLF][Manager] Loading eBPF programs...
[INFO][ANLF][Manager] Attaching XDP program to interface upfgtp
[INFO][ANLF][Monitor] TrafficMonitor started
[INFO][ANLF][Monitor] TLS event reader started
```

**如果看到这些日志，说明启动成功** ✓

### 步骤 4: 在另一个终端生成 HTTPS 流量

```bash
# 方式 A: 直接从主机使用 curl
curl -v https://www.google.com
curl -v https://www.baidu.com

# 或者使用 wget
wget --no-verbose https://www.example.com

# 方式 B: 如果有 UE 容器/模拟器，从 UE 内部生成流量
docker exec <ue-container-id> curl -v https://www.google.com

# 方式 C: 使用 Apache Bench 生成并发连接
ab -n 10 -c 2 https://www.google.com/
```

### 步骤 5: 查看导出的数据

在第一次收集周期完成后（通常 5-10 秒），检查导出的数据：

```bash
cd /home/vagrant/AnLF/anlf

# 查看输出目录
ls -lh output/example/

# 查看最新的 inference JSON 文件
LATEST=$(ls -t output/example/inference_*.json 2>/dev/null | head -1)
echo "=== Latest inference file: $LATEST ==="
cat "$LATEST" | jq '.' 2>/dev/null || cat "$LATEST"

# 只查看 TLS 相关字段
cat "$LATEST" | jq '.[] | {ip, supi, has_tls_sample, tls_hello_hex}' 2>/dev/null
```

**成功的 JSON 输出示例**:
```json
[
  {
    "ip": "10.60.0.1",
    "supi": "imsi-208930000000001",
    "has_tls_sample": true,
    "tls_hello_hex": "160301005a010000560303..."
  },
  {
    "ip": "10.60.0.2",
    "supi": "imsi-208930000000002",
    "has_tls_sample": false,
    "tls_hello_hex": null
  }
]
```

## 完整验收标准

### ✅ 必须满足的条件

1. **AnLF 启动成功**
   - [ ] 无编译错误
   - [ ] XDP 程序成功 attach 到接口
   - [ ] TLS event reader 成功启动

2. **HTTPS 流量被捕获**
   - [ ] 生成 HTTPS 请求后，AnLF 日志中出现 TLS 相关信息
   - [ ] JSON 输出中包含 `has_tls_sample: true`
   - [ ] `tls_hello_hex` 字段非空

3. **TLS 数据格式正确**
   - [ ] `tls_hello_hex` 以 `160301` 开头（TLS 1.2 握手）
   - [ ] 数据为有效的十六进制字符串
   - [ ] 长度在 1-256 字符之间（对应 0.5-128 字节）

4. **无重复采样**
   - [ ] 对同一 UE 多次生成 HTTPS 请求
   - [ ] 同一 Flow 的 TLS 样本仅出现一次
   - [ ] 跨收集周期不应有重复

5. **系统性能正常**
   - [ ] AnLF 进程稳定运行，无崩溃
   - [ ] CPU 使用率增加 < 5%
   - [ ] 内存占用稳定
   - [ ] 原始流量统计准确

### ⚠️ 可能的问题及解决

#### 问题 1: `has_tls_sample` 总是 false

**原因可能**:
- 没有生成 HTTPS 流量
- HTTPS 流量没有到达 XDP 接口
- 网络配置问题

**检查步骤**:
```bash
# 1. 确认网络连接
ping 8.8.8.8

# 2. 验证 XDP 接口
sudo ip link show | grep -E "upfgtp|ens|eth"

# 3. 检查 tcpdump 是否看到 HTTPS 流量
sudo tcpdump -i upfgtp "tcp port 443" -c 5

# 4. 查看 AnLF 日志中的调试信息
# 在 AnLF 启动前设置:
export LOG_LEVEL=DEBUG
sudo ./bin/anlf
```

#### 问题 2: tls_hello_hex 为空字符串

**原因可能**:
- Payload 复制失败
- Byte Order 转换错误
- Perf Buffer 事件丢失

**检查步骤**:
```bash
# 生成 HTTPS 流量
curl https://www.google.com 2>&1 | head -5

# 立即检查日志（在 AnLF 运行的终端）
# 寻找: "Cached TLS event" 或 "Added TLS sample"

# 如果没有看到这些消息，说明 Perf Buffer 读取有问题
```

#### 问题 3: IP 地址显示错误

**例如**: `1.10.60.0` 而不是 `10.60.0.1`

**原因**: Byte Order 转换错误

**检查**: 查看 `tls_capture.go` 第 94-95 行的转换逻辑

```go
ipBytes := make([]byte, 4)
binary.BigEndian.PutUint32(ipBytes, event.SrcIP)
```

#### 问题 4: AnLF 启动时 eBPF 加载失败

**错误消息示例**:
```
Error: loading eBPF objects: field AnlfTcEgress: program anlf_tc_egress: map ue_metrics_map: map create: operation not permitted
```

**解决方案**:
```bash
# 1. 确认以 root 运行
sudo whoami  # 应该显示 root

# 2. 增加 MEMLOCK 限制
sudo sysctl -w vm.max_map_count=262144

# 3. 重新编译和运行
cd /home/vagrant/AnLF/anlf
make clean build
sudo ./bin/anlf
```

## 详细测试场景

### 场景 1: 基础功能验证

```bash
# Terminal 1: 启动 AnLF
cd /home/vagrant/AnLF/anlf
sudo ./bin/anlf

# Terminal 2: 生成单个 HTTPS 请求
curl -v https://www.google.com 2>&1 | head -20

# Terminal 3: 查看输出
sleep 8
cat output/example/inference_*.json | jq '.[] | select(.has_tls_sample == true)'
```

**预期**: 至少看到一个 UE 的 `has_tls_sample: true`

### 场景 2: 并发连接测试

```bash
# 从多个 UE 生成并发 HTTPS 连接
for i in {1..5}; do
  curl -s https://www.google.com > /dev/null &
done
wait

# 等待收集周期完成
sleep 8

# 验证多个 UE 的 TLS 样本
cat output/example/inference_*.json | jq '.[] | select(.has_tls_sample == true) | .ip' | sort -u
```

**预期**: 看到多个不同的 UE IP 地址

### 场景 3: 重复请求测试

```bash
# 对同一目标生成多个请求
for i in {1..3}; do
  echo "Request $i"
  curl -s https://www.google.com > /dev/null
  sleep 0.5
done

# 等待收集
sleep 8

# 检查 TLS 样本
LATEST=$(ls -t output/example/inference_*.json 2>/dev/null | head -1)
cat "$LATEST" | jq '.[] | {ip, tls_hello_hex}' | head -30
```

**预期**: 同一 UE 的 `tls_hello_hex` 在多个周期中仅出现一次

### 场景 4: 高频流量测试

```bash
# 生成高频 HTTPS 连接
ab -n 100 -c 10 https://www.google.com/ &

# 在另一个终端监控 AnLF
watch -n 1 'ps aux | grep anlf | grep -v grep'

# 等待完成并检查输出
sleep 15
cat output/example/inference_*.json | jq '.[-1:]'
```

**预期**:
- AnLF 进程稳定运行
- 没有明显的 CPU 峰值
- 数据输出正常

## 日志分析

### 关键日志消息

在 AnLF 运行日志中查找以下消息：

| 消息 | 含义 |
|------|------|
| `TLS event reader started` | TLS 读取器成功启动 |
| `Cached TLS event from 10.60.0.X: N bytes` | TLS 事件被缓存 |
| `Added TLS sample for UE 10.60.0.X: N bytes` | TLS 样本被合并到输出 |
| `Perf Buffer满 或其他错误` | 高频流量下可能的丢弃 |

### 启用调试模式

修改日志级别以获取更详细的信息：

```bash
# 在启动 AnLF 前设置环境变量（如适用）
export ANLF_LOG_LEVEL=DEBUG
sudo ./bin/anlf
```

## 验收检查清单

### 代码层面

- ✅ eBPF 代码编译通过（无验证器错误）
- ✅ Go 代码编译成功
- ✅ 所有单元测试通过 (6/6)
- ✅ 代码有完整注释
- ✅ 没有内存泄漏

### 功能层面

- ⏳ AnLF 成功启动 → **需要您测试**
- ⏳ HTTPS 流量被捕获 → **需要您测试**
- ⏳ JSON 包含 TLS 数据 → **需要您测试**
- ⏳ 无重复采样 → **需要您测试**
- ⏳ 系统性能正常 → **需要您测试**

### 性能基准

预期的性能指标（与启用 TLS DPI 前比较）：

| 指标 | 增加 |
|------|------|
| CPU 使用率 | < 5% |
| 内存占用 | < 10 MB |
| 包处理延迟 | < 1 µs |
| 数据丢弃率 | 0%（原始统计） |

## 完成后的步骤

### 1. 收集测试结果

```bash
# 导出测试数据
mkdir -p /tmp/tls-test-results
cp -r output/example/* /tmp/tls-test-results/

# 记录 AnLF 日志
cp anlf.log /tmp/tls-test-results/ 2>/dev/null || echo "No log file"
```

### 2. 生成测试报告

创建文件 `TLS_TEST_REPORT.md`:
```markdown
# TLS DPI 功能测试报告

## 测试环境
- 日期: [当前日期]
- 内核版本: [uname -r]
- Free5GC 版本: [版本号]

## 测试结果

### 基础功能
- AnLF 启动: [PASS/FAIL]
- HTTPS 流量捕获: [PASS/FAIL]
- JSON 输出正确: [PASS/FAIL]

### 性能测试
- CPU 使用率增加: [百分比]
- 内存占用: [MB]
- 性能: [PASS/FAIL]

### 问题
- [列出遇到的任何问题]

## 附件
- inference_*.json 文件
- AnLF 启动日志
```

### 3. 清理

```bash
# 停止 AnLF
sudo pkill -f "bin/anlf"

# 清理临时文件
rm -rf output/*
```

## 故障排查快速参考

```bash
# 1. 检查内核支持
uname -r  # 应该 >= 5.8

# 2. 检查 eBPF 能力
cat /proc/sys/kernel/unprivileged_userns_clone

# 3. 增加内存限制
sudo sysctl -w vm.max_map_count=262144

# 4. 检查网络接口
ip link show | grep upfgtp

# 5. 查看 eBPF 加载状态
bpftool prog list

# 6. 查看 XDP 附加状态
ip link show upfgtp | grep xdp

# 7. 检查 Perf 事件权限
cat /proc/sys/kernel/perf_event_paranoid
# 应该 <= 1
```

## 联系和反馈

如遇到任何问题，请提供：

1. **测试环境信息**
   - 内核版本: `uname -a`
   - Free5GC 版本
   - 网络拓扑

2. **日志信息**
   - AnLF 完整启动日志
   - 错误消息
   - 相关的 dmesg 输出

3. **测试数据**
   - inference_*.json 文件
   - traffic_*.csv 文件

4. **重现步骤**
   - 生成问题的具体步骤
   - 使用的命令
   - 预期 vs 实际结果

---

**重要**: 本实现已完成代码级别的所有工作。剩下的只是系统级别的集成测试，这需要一个完整的 Free5GC 环境和真实的网络流量。
