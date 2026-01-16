# TLS Client Hello 側錄功能 (DPI)

## 概述

在 5G UE 流量監控系統中新增惡意 TLS 流量側錄功能，用於捕捉可疑的 TLS Client Hello 封包（特別是 "Lazy Mimic" 攻擊），並將 Payload 提供給 LLM 進行資安分析。

## 架構設計

### 控制面與資料面分離策略

**Kernel Space (eBPF/XDP)**
- 保留原有 `ue_metrics_map` 進行計數統計
- 新增旁路邏輯：偵測 HTTPS (Port 443) 初始封包
- 快照前 128 bytes 資料
- 透過 Perf Buffer 傳送至 Userspace

**User Space (Go)**
- 採用緩衝與合併 (Buffer & Merge) 模式
- 背景 Goroutine 監聽 Perf 事件並暫存於 Cache
- 週期性迴圈將 TLS Payload 與 UE 統計數據合併
- 生成包含 TLS HEX 的 JSON 報告

## 關鍵技術挑戰

### 1. Packet Boundary Check (Verifier)
**問題**：直接讀取 TCP Payload 導致 eBPF Verifier 認為存取越界  
**解法**：讀取前嚴格檢查 `ptr + offset <= data_end`，使用 `bpf_probe_read_kernel` 或邊界檢查迴圈

### 2. Map 儲存空間限制
**問題**：eBPF Map 不適合儲存大量動態長度 Payload  
**解法**：使用 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 將事件串流化至 Userspace，避免 Map 儲存

### 3. 重複採樣防範
**問題**：TCP 重傳或後續封包導致重複發送 TLS 事件  
**解法**：利用 `flow_tracking_map` 記錄狀態，定義 Bitmask：
- `0x01`：Flow 建立
- `0x02`：TLS 已捕獲
- 只在 `(state & 0x02) == 0` 時觸發捕獲

### 4. 並發安全 (Go)
**問題**：Perf Reader (Goroutine) 與 Metrics Collector (Main Loop) 同時存取資料  
**解法**：實作帶有 `sync.RWMutex` 的 `TlsEventCache` 結構

### 5. Flow Tracking Map 生命週期管理
**問題**：`flow_tracking_map` 用於記錄 Flow 狀態防止重複採樣 (0x02 bit)，但若只進不出，Map 會隨時間填滿，導致無法追蹤新連線  
**解法**：
- **定期清空**：與 Metrics 收集迴圈同步（每 5 秒），清除過期狀態
- **LRU 配置**：改用 `BPF_MAP_TYPE_LRU_HASH` 自動驅逐最舊項目
- **權衡**：定期清空可能導致長連線跨週期發生極少量重複採樣，但頻率極低，在可接受範圍內

## 核心資料結構

### eBPF (C)
```c
struct tls_event_t {
    __u32 src_ip;        // Network Byte Order
    __u32 dst_ip;        // Network Byte Order
    __u16 src_port;      // Network Byte Order
    __u16 dst_port;      // Network Byte Order
    __u32 payload_len;   // 實際 Payload 長度
    __u8  payload[128];  // 截取長度：min(payload_len, 128)
};

// Perf Event Map
BPF_MAP_TYPE_PERF_EVENT_ARRAY: tls_events

// Flow Tracking Map (LRU 推薦)
BPF_MAP_TYPE_LRU_HASH: flow_tracking_map
  - Key: flow_key (src_ip, dst_ip, proto, src_port, dst_port)
  - Value: __u8 (state bitmask: 0x01=Seen, 0x02=TLS_Captured)
```

### Go
```go
type TlsEventC struct {
    SrcIP      uint32
    DstIP      uint32
    SrcPort    uint16
    DstPort    uint16
    PayloadLen uint32
    Payload    [128]byte
}

type TlsEventCache struct {
    sync.RWMutex
    data map[string]string  // UE IP -> Hex String
}
```

## 資料流程

```
XDP Hook (Port 443 偵測)
    ↓
check_and_capture_tls()
    ├─ 檢查 TLS Handshake (0x16)
    ├─ 複製長度：min(actual_payload_len, 128)
    ├─ 超界部分補 0 或保持未初始化
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
    ├─ cache.Pop(ueIP)
    ├─ flow_tracking_map 週期清空 (防止爆滿)
    └─ 合併至 UeTrafficRecord.TlsHelloHex
         ↓
    JSON Output
```

## 整合檢查點

### eBPF 端
- **位置**：`process_inner_ip()` 函式的 TCP 處理區塊
- **條件**：`dst_port == 443 && (!flow_state || !(flow_state & 0x02))`
- **動作**：呼叫 `check_and_capture_tls()` 並更新 Flow State

### Go 端
- **啟動時**：呼叫 `StartPerfReader(eventsMap, cache)` 啟動背景監聽
- **Byte Order 轉換**：IP 與 Port 從 C 端接收為 Network Byte Order (Big Endian)，需轉換為 Host Byte Order 後轉字串
  ```go
  // 示例：正確轉換 IP 為字串
  ipBytes := make([]byte, 4)
  binary.BigEndian.PutUint32(ipBytes, event.SrcIP)
  ueIP := net.IP(ipBytes).String()
  ```
- **收集時**：在 `CollectMetrics()` 中執行 `cache.Pop(ueIP)` 合併資料
- **清理時**：同時清空 `flow_tracking_map` 中的過期狀態（週期 = Metrics 迴圈）

## 輸出格式

```json
{
  "supi": "imsi-...",
  "ip": "10.60.0.2",
  "packet_count": 1523,
  "has_tls_sample": true,
  "tls_hello_hex": "160301..."
}
```

## 可靠性設計

### Fail-Open 機制
**保證原始流量永不丟棄**

當以下情況發生時，eBPF 程式應直接忽略錯誤並回傳 `XDP_PASS`：
- Perf Buffer 滿載（`bpf_perf_event_output()` 失敗）
- Flow State 更新失敗
- Payload 複製異常

**禁止行為**：絕不可因 TLS 捕獲失敗而丟棄封包 (`XDP_DROP`)，否則會破壞原始網路流量

```c
// 安全的錯誤處理
if (bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &event, sizeof(event)) != 0) {
    // Perf Buffer 滿或其他錯誤，直接忽略
    // 原始流量統計 (ue_metrics_map) 不受影響
}
```

## 效能考量

- **截取長度**：限制 128 bytes（涵蓋 TLS Header + SNI）
- **複製長度**：自動截斷至 `min(actual_payload_len, 128)`，防止越界
- **採樣策略**：每個 Flow 僅捕獲一次（0x02 bit），避免重複
- **記憶體**：使用 Perf Buffer 串流，不佔用 eBPF Map 空間；Flow State Map 可配置 LRU 自動回收
- **鎖競爭**：Cache 操作時間極短，RWMutex 影響可忽略
- **Perf Buffer 配置**：建議大小 >= 4 MB（根據 CPU 核心數調整），防止高頻率丟棄

## 安全性與合規性

⚠️ **重要提醒**：
- 本功能涉及封包內容檢測 (DPI)，部署前需確認符合當地隱私法規
- TLS Payload 僅用於威脅偵測，不應儲存明文通訊內容
- 建議實作資料保留期限與存取控制機制
- Flow State 與 TLS 事件應定期清理，避免 Map 持續佔用記憶體

## 實作檢查清單

- [ ] eBPF: `tls_event_t` 結構已定義，Payload 字段為 128 bytes
- [ ] eBPF: `copy_payload()` 函式實作了邊界檢查與長度截斷
- [ ] eBPF: Flow State Bitmask (0x01, 0x02) 邏輯正確
- [ ] eBPF: Flow Tracking Map 配置為 LRU 或已實作週期清空機制
- [ ] eBPF: `check_and_capture_tls()` 失敗時回傳 `XDP_PASS`，絕不 `XDP_DROP`
- [ ] Go: Perf Reader 正確解析 `TlsEventC` 二進制資料
- [ ] Go: Byte Order 轉換已正確處理（Network → Host）
- [ ] Go: `TlsEventCache` 使用 RWMutex 確保執行緒安全
- [ ] Go: `CollectMetrics()` 同時執行 Cache Pop 與 Flow State 清理
- [ ] 測試：驗證高頻 HTTPS 流量下無重複採樣與無套件丟棄
