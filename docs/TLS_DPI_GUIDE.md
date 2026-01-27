# TLS DPI 功能完整指南

> **最後更新**: 2026-01-19 | **版本**: 1.0 完成版

## 📋 目錄

1. [概述](#概述)
2. [架構設計](#架構設計)
3. [核心技術](#核心技術)
4. [快速開始](#快速開始)
5. [診斷測試](#診斷測試)
6. [系統測試](#系統測試)
7. [問題排查](#問題排查)

---

## 概述

在 5G UE 流量監控系統 (AnLF) 中新增 **TLS Client Hello 側錄功能** (DPI)，用於捕捉可疑的 TLS Client Hello 封包（特別是 "Lazy Mimic" 攻擊），並將 Payload 提供給 LLM 進行資安分析。

### 關鍵特性

- 🎯 **自動捕獲**: HTTPS 流量 (Port 443) 的 TLS Client Hello
- 🔒 **防重複**: 每個連接僅採樣一次
- ⚡ **高效**: < 5% CPU 開銷
- 💾 **流式處理**: 10 字節 Payload 快照
- 🛡️ **可靠**: Fail-Open 保證流量不丟

---

## 架構設計

### 控制面與資料面分離策略

```
User Space (Go)
├─ TrafficMonitor (週期迴圈)
├─ TlsEventReader (背景 Goroutine)
└─ TlsEventCache (執行緒安全快取)

Kernel Space (eBPF/XDP)
├─ process_inner_ip() [XDP Hook]
├─ check_and_capture_tls() [偵測 & 捕獲]
├─ tls_events [Perf Buffer]
└─ tls_state_map [Flow 狀態追蹤]
```

**Kernel Space (eBPF/XDP)**
- 保留原有 `ue_metrics_map` 進行計數統計
- 新增旁路邏輯：偵測 HTTPS (Port 443) 初始封包
- 快照前 128 bytes 資料
- 透過 Perf Buffer 傳送至 Userspace

**User Space (Go)**
- 採用 **Sticky State 模式** (持久化快取)
- 背景 Goroutine 監聽 Perf 事件並寫入 Cache
- 週期性迴圈讀取 TLS Payload，但 **不刪除** (允許跨 Window 重複使用)
- 生成包含 TLS HEX 的 JSON/CSV 報告

---

## 核心技術

### 關鍵技術挑戰與解法

#### 1. Packet Boundary Check (Verifier)

**問題**: 直接讀取 TCP Payload 導致 eBPF Verifier 認為存取越界

**解法**: 讀取前嚴格檢查 `ptr + offset <= data_end`

```c
// 安全的邊界檢查
if (payload_start >= data_end) return 0;
if (payload_start + 1 > data_end) return 0;
__u8 first_byte = *(__u8 *)payload_start;
```

#### 2. IP Header 長度變化

**問題**: 使用 `sizeof(*iph)` 會忽略 IP options，導致 TCP header offset 計算錯誤

**解法**: 使用 `iph->ihl * 4` 計算實際 IP header 長度

```c
__u32 ip_hdr_len = iph->ihl * 4;  // 考慮 IP options
struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
```

#### 3. Byte Order (Endianness) 轉換

**問題**: eBPF 端使用 network byte order (big-endian)，Go 端用 `binary.Read(..., LittleEndian)` 會導致雙重反轉

**例**:
- eBPF 送: `0x0a3c6401` (10.60.100.1 in big-endian)
- Go 讀: `binary.Read(..., LittleEndian)` → `0x01643c0a`
- 錯誤: `binary.BigEndian.PutUint32()` → `1.100.60.10` ❌
- 正確: `binary.LittleEndian.PutUint32()` → `10.60.100.1` ✅

```go
// 正確的 IP 轉換
ipBytes := make([]byte, 4)
binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
ueIP := net.IP(ipBytes).String()
```

#### 4. 重複採樣防範

**問題**: TCP 重傳或後續封包導致重複發送 TLS 事件

**解法**: 利用 `tls_state_map` 記錄狀態，定義 Bitmask：
- `0x01`: Flow 建立
- `0x02`: TLS 已捕獲

只在 `(state & 0x02) == 0` 時觸發捕獲

```c
if (!flow_state || !(*flow_state & 0x02)) {
    if (check_and_capture_tls(ctx, iph, tcph, data_end)) {
        __u8 new_state = (flow_state ? *flow_state : 0) | 0x02 | 0x01;
        bpf_map_update_elem(&tls_state_map, &fkey, &new_state, BPF_ANY);
    }
}
```

#### 5. 並發安全 (Go)

**問題**: Perf Reader (Goroutine) 與 Metrics Collector (Main Loop) 同時存取資料

**解法**: 實作帶有 `sync.RWMutex` 的 `TlsEventCache`，使用 **Sticky State** 模式

```go
type TlsEventCache struct {
    mu   sync.RWMutex
    data map[string]string  // UE IP -> Hex String
}

// Get: 讀取但不刪除 (Sticky State)
func (c *TlsEventCache) Get(ueIP string) (string, bool) {
    c.mu.RLock()  // 讀鎖，效能較佳
    defer c.mu.RUnlock()
    val, ok := c.data[ueIP]
    return val, ok
}

// Add: 更新或新增 (自動覆蓋舊資料)
func (c *TlsEventCache) Add(ueIP string, hex string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.data[ueIP] = hex
}
```

**Sticky State 特性**:
- 第一次捕獲: `has_tls_sample=true`, `tls_hello_hex="160301..."`
- 之後的 Window: 繼續輸出相同的 Hex (即使沒有新封包)
- UE 重連: eBPF 捕獲新的 Hello → Cache 自動更新
- 優點: LLM 可持續分析，無須等待下次 TLS 握手

#### 6. Fail-Open 可靠性

**保證原始流量永不丟棄**

當以下情況發生時，eBPF 程式應直接忽略錯誤並回傳 `XDP_PASS`：
- Perf Buffer 滿載
- Flow State 更新失敗
- Payload 複製異常

```c
if (bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &event, sizeof(event)) != 0) {
    // Perf Buffer 滿或其他錯誤，直接忽略
    // 原始流量統計 (ue_metrics_map) 不受影響
}
```

### 核心資料結構

**eBPF (C)**:
```c
struct tls_event_t {
    __u32 src_ip;        // Network Byte Order
    __u32 dst_ip;        // Network Byte Order
    __u16 src_port;      // Network Byte Order
    __u16 dst_port;      // Network Byte Order
    __u32 payload_len;   // 實際 Payload 長度
    __u8  payload[10];   // 截取長度：min(payload_len, 10)
};

// Perf Event Map
BPF_MAP_TYPE_PERF_EVENT_ARRAY: tls_events

// Flow Tracking Map (LRU)
BPF_MAP_TYPE_LRU_HASH: tls_state_map
  - Key: flow_key (src_ip, dst_ip, proto, src_port, dst_port)
  - Value: __u8 (state bitmask: 0x01=Seen, 0x02=TLS_Captured)
```

**Go**:
```go
type TlsEventC struct {
    SrcIP      uint32
    DstIP      uint32
    SrcPort    uint16
    DstPort    uint16
    PayloadLen uint32
    Payload    [10]byte
}

type TlsEventCache struct {
    mu   sync.RWMutex
    data map[string]string  // UE IP -> Hex String
}
```

### 資料流程

```
XDP Hook (Port 443 偵測)
    ↓
check_and_capture_tls()
    ├─ 檢查 TLS Handshake (0x16)
    ├─ 複製長度：min(actual_payload_len, 128)
    └─ bpf_perf_event_output() → [Fail-Open: 失敗時直接忽略]
         ↓
    Perf Buffer (滿載時自動捨棄最舊事件)
         ↓
Go Perf Reader (Goroutine)
    ├─ binary.Read(TlsEventC)
    ├─ Byte Order 轉換 (Network → Host)
    ├─ hex.EncodeToString()
    └─ cache.Add(ueIP, hexPayload)
         ↓
CollectMetrics (每 5 秒)
    ├─ cache.Get(ueIP)  // 讀取但不刪除 (Sticky State)
    └─ 合併至 UeTrafficRecord.TlsHelloHex
         ↓
    JSON/CSV Output
```

**行為說明**:
- **T=0s**: UE 發起 HTTPS 連線 → eBPF 捕獲 Client Hello → Cache 寫入 `"160301..."`
- **T=5s**: UE Keep-Alive 傳輸，無新 Hello → Collector 讀到舊資料 → 輸出相同 Hex
- **T=10s**: UE 重連 → eBPF 捕獲新 Hello → Cache 自動更新 → 輸出新 Hex
- **T=15s**: UE 閒置，無流量 → 系統清除 Metrics Map 項目 → 無輸出 (符合邏輯)
```

### 輸出格式

**JSON**:
```json
{
  "supi": "imsi-208930000000001",
  "ip": "10.60.100.1",
  "ts": 1768791256,
  "has_tls_sample": true,
  "tls_hello_hex": "160301005a01000056030336..."
}
```

**CSV**:
```csv
timestamp,supi,ue_ip,...,has_tls_sample,tls_hello_hex
1768791256,imsi-208930000000001,10.60.100.1,...,true,160301005a...
```

---

## 快速開始

### Step 1: 編譯驗證 (2 分鐘)

```bash
cd /home/vagrant/AnLF/anlf
make clean build
# 預期: ✓ Build complete: bin/anlf
```

### Step 2: 單元測試 (1 分鐘)

```bash
go test -v ./internal/monitor -run "Tls"
# 預期: PASS (所有 6 個測試)

go test -v ./internal/analyzer/exporter -run "Csv"
# 預期: PASS (CSV exporter 測試)
```

### Step 3: 啟動 AnLF

```bash
cd /home/vagrant/AnLF/anlf
sudo ./bin/anlf
```

**預期日誌**:
```
[INFO][ANLF][Main] Loading eBPF programs...
[INFO][ANLF][Main] ✓ eBPF XDP attached successfully to upfgtp
[INFO][ANLF][Main] ✓ eBPF TC egress attached successfully to upfgtp
[INFO][ANLF][Monitor] Starting TrafficMonitor (poll interval: 3s)...
[INFO][ANLF][Monitor] TLS event reader started
```

### Step 4: 生成 HTTPS 流量

在 **UE 端** 執行:
```bash
while true; do
    curl --interface ueTun0 -k -s -o /dev/null -w "%{http_code}\n" https://10.201.10.177
    sleep 1
done
```

### Step 5: 驗證輸出

```bash
# 等待 1-2 個 poll cycle (~6 秒)
tail output/$(ls -1dt output/202* | head -1)/traffic_*.csv | cut -d',' -f3,26-27

# 預期:
# ue_ip,has_tls_sample,tls_hello_hex
# 10.60.100.1,true,160301...
```

---

## 診斷測試

### 分層診斷方法

使用 `tcpdump` 在各層進行驗證，逐步確認問題所在。

#### Level 1: Kernel 層 - XDP 前捕捉

**目的**: 確認流量確實到達 upfgtp 介面

```bash
# 在 AnLF 主機上，監聽 upfgtp 介面
sudo tcpdump -i upfgtp -nn 'tcp port 443' -c 10
```

**預期輸出**:
```
listening on upfgtp, link-type RAW (Raw IP)
10.60.100.1.34146 > 10.201.10.177.443: Flags [S], seq 3514285141, win 64240
10.201.10.177.443 > 10.60.100.1.34146: Flags [S.], seq 171739247, ack 3514285142
10.60.100.1.34146 > 10.201.10.177.443: Flags [.], ack 1, win 502
10.60.100.1.34146 > 10.201.10.177.443: Flags [P.], seq 1:518, ack 1 <-- **TLS Client Hello**
```

**檢查點**:
- ✅ 流量出現在 upfgtp
- ✅ 看到 3-way handshake
- ✅ 看到 [P.] flag 的大型 payload (通常 512+ bytes) = TLS Client Hello

#### Level 2: eBPF 層 - Flow State 檢查

**目的**: 確認 eBPF 程式已標記流量為 TLS captured

```bash
# 查看 tls_state_map 的內容
sudo bpftool map dump name tls_state_map
```

**預期輸出**:
```json
[{
    "key": {
        "src_ip": 10.60.100.1,
        "dst_ip": 10.201.10.177,
        "src_port": 34146,
        "dst_port": 443,
        "proto": 6
    },
    "value": 3  // 0x03 = 0x01 (Seen) | 0x02 (TLS_Captured)
}]
```

**檢查點**:
- ✅ value 為 3 表示 TLS 已捕獲
- ✅ value 為 1 表示流量已見但 TLS 未捕獲（可能不是 TLS）
- ❌ value 未出現 = 流量未到達 eBPF

#### Level 3: Perf Buffer 層 - 事件傳輸

**目的**: 確認 Perf Buffer 能收到 TLS 事件

檢查 AnLF 日誌中的 debug 訊息:

```bash
# 啟動時啟用 debug 日誌
RUST_LOG=debug sudo ./bin/anlf 2>&1 | grep -i "cached tls"

# 預期:
# [DEBUG][ANLF][Monitor] Cached TLS event from 10.60.100.1: 512 bytes
```

**檢查點**:
- ✅ 看到 "Cached TLS event" = Perf Buffer 成功傳輸
- ❌ 未看到 = Perf Buffer 可能滿載或讀取器未啟動

#### Level 4: Go 層 - 快取與匹配

**目的**: 確認 Go 端正確處理並快取 TLS 事件

檢查 CSV 輸出:

```bash
# 檢查最新的 CSV 檔案
LATEST=$(ls -1dt output/202* | head -1)
tail output/$LATEST/traffic_*.csv | cut -d',' -f3,26-27

# 預期:
# ue_ip,has_tls_sample,tls_hello_hex
# 10.60.100.1,true,160301...
```

**檢查點**:
- ✅ `has_tls_sample=true` = 快取成功
- ✅ `tls_hello_hex` 開頭為 `160301` = TLS Handshake v1.0
- ❌ `has_tls_sample=false` = 快取未匹配或 UE IP 轉換錯誤

### 完整診斷流程

```bash
#!/bin/bash
# TLS DPI 分層診斷腳本

echo "=== Level 1: tcpdump on upfgtp (5 秒) ==="
(timeout 5 sudo tcpdump -i upfgtp -nn 'tcp port 443' 2>&1 | head -20) &
TCPDUMP_PID=$!

echo "=== Level 2: eBPF Flow State Map ==="
sleep 2
sudo bpftool map dump name tls_state_map 2>&1 | jq . | head -30

echo ""
echo "=== Level 3: AnLF Logs (查找 TLS 訊息) ==="
# 這需要 AnLF 已執行，檢查它的輸出
ps aux | grep "bin/anlf" | grep -v grep && echo "✓ AnLF is running"

echo ""
echo "=== Level 4: CSV Output ==="
LATEST=$(ls -1dt /home/vagrant/AnLF/anlf/output/202* 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    echo "Latest directory: $LATEST"
    tail "$LATEST/traffic_*.csv" 2>/dev/null | cut -d',' -f3,26-27 | head -5
else
    echo "⚠ No output directory found"
fi

wait $TCPDUMP_PID 2>/dev/null
echo ""
echo "=== Diagnosis Complete ==="
```

---

## 系統測試

### 測試流程

#### Phase 1: 單元測試驗證

```bash
cd /home/vagrant/AnLF/anlf
go test -v ./internal/monitor -run "Tls"
```

**預期結果**: ✓ 6/6 PASS

#### Phase 2: AnLF 啟動

```bash
sudo ./bin/anlf
```

**檢查**:
- 無編譯或加載錯誤
- TrafficMonitor 正常啟動
- TLS event reader 正常啟動

#### Phase 3: HTTPS 流量生成

```bash
# 從 UE 端
while true; do
    curl -k https://10.201.10.177 2>&1 | head -5
    sleep 2
done
```

#### Phase 4: 驗證採樣

```bash
# 在 AnLF 主機上
sleep 8  # 等待至少一個 poll cycle
LATEST=$(ls -1dt output/202* | head -1)
cat "output/$LATEST/traffic_*.csv" | tail -5
```

**成功標誌**:
- `has_tls_sample=true`
- `tls_hello_hex` 以 `160301` 開頭
- 同一 UE 僅出現一次 TLS 樣本

### 性能基準

在標準配置下 (poll interval = 3s):

| 項目 | 預期值 |
|------|--------|
| 啟動時間 | < 5 秒 |
| TLS 捕獲成功率 | 100% |
| CPU 增加 | < 5% |
| 記憶體增加 | < 10 MB |
| 穩定性 | 24/7 連續運行 |

---

## 問題排查

### 常見問題與解決方案

#### Q1: tcpdump 看不到 Port 443 流量

**症狀**: `tcpdump -i upfgtp 'tcp port 443'` 無輸出

**診斷**:
```bash
# 1. 確認介面存在
ip link show upfgtp

# 2. 確認 XDP 已掛載
sudo bpftool prog list | grep xdp

# 3. 用 tcpdump 監聽所有流量
timeout 5 sudo tcpdump -i upfgtp 2>&1 | head -20
```

**解決方案**:
- 檢查 Free5GC 是否正常運行
- 確認 UE 已連接並獲得 IP
- 檢查防火牆規則

#### Q2: tls_state_map 為空

**症狀**: `sudo bpftool map dump name tls_state_map` 無輸出

**原因**: 
- 流量未到達 eBPF
- eBPF 程式未成功加載

**解決方案**:
```bash
# 1. 檢查 eBPF 程式狀態
sudo bpftool prog list | grep -i anlf

# 2. 檢查 maps
sudo bpftool map list | grep tls

# 3. 重新編譯
cd /home/vagrant/AnLF/anlf
make clean build
sudo ./bin/anlf
```

#### Q3: has_tls_sample 總是 false

**症狀**: CSV 中 `has_tls_sample=false`, `tls_hello_hex` 為空

**可能原因**:
1. 流量確實未到達 eBPF
2. Perf Buffer 讀取器未啟動
3. UE IP 轉換錯誤

**診斷步驟**:
```bash
# 1. 確認 eBPF 有捕獲
sudo bpftool map dump name tls_state_map | grep -v "^]"

# 2. 確認讀取器啟動（查看日誌）
sudo ./bin/anlf 2>&1 | grep "TLS event reader"

# 3. 檢查 UE IP（應該是 10.60.x.x）
tail output/*/traffic_*.csv | cut -d',' -f3 | sort -u
```

**解決方案**:
- 確認 UE 正在產生 HTTPS 流量
- 重啟 AnLF
- 檢查 tcpdump 是否看到 Port 443 流量

#### Q4: IP 地址顯示不正確

**症狀**: UE IP 顯示為 `1.100.60.10` 而不是 `10.60.100.1`

**原因**: Byte order 轉換錯誤（已在最新版本修正）

**檢查**:
```bash
# 驗證修正已應用
git log --oneline | grep "endianness\|byte order"

# 應該看到相關的修復提交
```

**解決方案**:
- 確保已拉取最新代碼
- 重新編譯和測試

#### Q5: CPU 或記憶體異常增長

**症狀**: 監視工具顯示 CPU/Memory 持續增長

**可能原因**:
- Goroutine 泄漏
- Map 無限增長

**診斷**:
```bash
# 1. 監視 AnLF 進程
top -p $(pgrep anlf)

# 2. 檢查 map 大小
sudo bpftool map show | grep -i tls

# 3. 查看 goroutine 數
# (需要在代碼中添加 pprof 端點)
```

**解決方案**:
- 確認 LRU map 已正確配置
- 停止 AnLF，清理資源後重啟

---

## 文件結構

```
anlf/
├── bpf/
│   ├── anlf.c                    # eBPF 核心程式
│   ├── include/maps.h            # TLS 相關 maps 定義
│   └── vmlinux.h
├── pkg/
│   ├── models/feature.go         # TlsHelloHex 欄位
│   └── ebpf/manager.go           # GetTlsEventsMap()
├── internal/
│   ├── monitor/
│   │   ├── tls_capture.go        # Perf Buffer 讀取與快取
│   │   ├── tls_capture_test.go   # 單元測試
│   │   └── monitor.go            # 整合點
│   └── analyzer/exporter/
│       └── csv_exporter.go       # CSV 輸出欄位
└── docs/
    └── TLS_DPI_GUIDE.md          # 本文件
```

---

## 檢查清單

### 開發人員

- [ ] eBPF: `tls_event_t` 結構已定義，Payload 字段為 128 bytes
- [ ] eBPF: `copy_payload()` 函式實作了邊界檢查與長度截斷
- [ ] eBPF: Flow State Bitmask (0x01, 0x02) 邏輯正確
- [ ] eBPF: Flow Tracking Map 配置為 LRU
- [ ] eBPF: `check_and_capture_tls()` 失敗時回傳 `XDP_PASS`
- [ ] Go: Perf Reader 正確解析 `TlsEventC` 二進制資料
- [ ] Go: Byte Order 轉換已正確處理（使用 LittleEndian）
- [ ] Go: `TlsEventCache` 使用 RWMutex 確保執行緒安全

### 測試人員

- [ ] 單元測試全部通過 (6/6)
- [ ] AnLF 成功編譯 (無警告)
- [ ] tcpdump 看到 Port 443 流量
- [ ] eBPF map 顯示 TLS_Captured 狀態
- [ ] CSV/JSON 包含 TLS 資料
- [ ] 高頻流量下穩定性驗證
- [ ] 無套件丟棄 (Fail-Open 正常)

---

## 更新日誌

| 版本 | 日期 | 變更 |
|------|------|------|
| 1.0 | 2026-01-19 | 首個完整版本，整合所有文件 |

---

**如有任何問題，請參考各章節或聯絡技術支援。**
