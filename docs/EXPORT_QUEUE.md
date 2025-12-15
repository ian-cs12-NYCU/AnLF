# Export Message Queue 架構說明

## 概述

AnLF 的 Exporter 與 FlowAnalyzer 現已使用高效能的 Message Queue 架構進行解耦，提供更好的可擴展性和管理性。

## 架構組件

### 1. ExportMessage (`internal/analyzer/queue/message.go`)
- **通用訊息包裝器**：支援不同類型的 export 資料
- **類型安全轉換**：提供 `AsTrafficRecord()` 等方法進行型別轉換
- **可擴展設計**：透過 `MessageType` 輕鬆添加新的訊息類型

```go
// 現有類型
MessageTypeTrafficRecord    // UE 流量記錄

// 未來擴展
MessageTypeLLMInference     // LLM 推論結果
```

### 2. ExportQueue (`internal/analyzer/queue/export_queue.go`)
- **高效能 Buffered Channel**：預設 10000 訊息容量
- **多 Worker 並行處理**：預設 4 個 goroutine workers
- **非阻塞入隊**：queue 滿時丟棄訊息並記錄警告
- **優雅關閉**：確保所有訊息都被處理完畢才關閉
- **即時監控**：每 30 秒報告 queue 利用率

```go
// 配置範例
config := queue.Config{
    BufferSize:  10000,  // 大容量緩衝
    WorkerCount: 4,      // 並行 workers
}
```

### 3. ExportDispatcher (`internal/analyzer/dispatcher/dispatcher.go`)
- **訊息路由器**：根據 `MessageType` 分發到對應的 exporter
- **類型擴展支援**：未來可輕鬆添加新的 exporter 類型
- **統一 Shutdown 管理**：協調所有 exporters 的關閉流程

```go
// 現在：流量記錄 -> CsvExporter
MessageTypeTrafficRecord -> CsvExporter -> CSV 檔案

// 未來：LLM 推論 -> LlmExporter
MessageTypeLLMInference -> LlmExporter -> JSONL 檔案
```

### 4. FlowAnalyzer (`internal/analyzer/analyzer.go`)
- **簡化職責**：只負責將資料放入 queue
- **非同步處理**：不再直接調用 exporter，避免阻塞
- **錯誤處理**：記錄 enqueue 失敗但不影響主流程

## 資料流程

```
[Traffic Record] 
    ↓
FlowAnalyzer.processRecord()
    ↓
建立 ExportMessage
    ↓
ExportQueue.Enqueue() ← 非阻塞
    ↓
[Buffered Channel: 10000]
    ↓
4個 Workers 並行處理
    ↓
ExportDispatcher.Handle()
    ↓
根據 MessageType 路由
    ↓
┌─────────────┴──────────────┐
↓                            ↓
CsvExporter            LlmExporter (未來)
↓                            ↓
CSV 檔案                  JSON/JSONL
```

## 性能特性

### 高吞吐量
- **Buffered Channel**：10000 訊息容量處理突發流量
- **並行處理**：4 個 workers 同時消費訊息
- **非阻塞操作**：FlowAnalyzer 不會被 I/O 阻塞

### 可靠性
- **Graceful Drain**：關閉時處理完所有剩餘訊息
- **錯誤隔離**：單個訊息處理失敗不影響其他訊息
- **Overflow Protection**：queue 滿時丟棄並記錄，避免記憶體溢出

### 可觀測性
- **Queue 監控**：每 30 秒報告利用率
- **利用率警告**：超過 80% 時發出警告
- **Worker 日誌**：記錄每個 worker 的處理狀態

## 擴展範例：添加 LLM Inference Export

### 1. 定義新的訊息類型
```go
// internal/analyzer/queue/message.go
const (
    MessageTypeLLMInference MessageType = "llm_inference"
)

type LLMInferenceResult struct {
    UeIp       string
    Prediction string
    Confidence float64
    Timestamp  int64
}

func NewLLMInferenceMessage(result *LLMInferenceResult) *ExportMessage {
    return &ExportMessage{
        Type: MessageTypeLLMInference,
        Data: result,
    }
}
```

### 2. 實作新的 Exporter
```go
// internal/analyzer/exporter/llm_exporter.go
type LlmExporter struct {
    file *os.File
    // ...
}

func (e *LlmExporter) Export(data interface{}) error {
    // 寫入 JSONL 格式
    // ...
}
```

### 3. 更新 Dispatcher
```go
// internal/analyzer/dispatcher/dispatcher.go
type ExportDispatcher struct {
    trafficExporter exporter.Exporter
    llmExporter     exporter.Exporter  // 新增
}

func (d *ExportDispatcher) Handle(msg *queue.ExportMessage) error {
    switch msg.Type {
    case queue.MessageTypeTrafficRecord:
        return d.handleTrafficRecord(msg)
    case queue.MessageTypeLLMInference:  // 新增
        return d.handleLLMInference(msg)
    }
}
```

### 4. 使用
```go
// 在需要 export LLM 結果的地方
result := &LLMInferenceResult{...}
msg := queue.NewLLMInferenceMessage(result)
exportQueue.Enqueue(msg)
```

## 配置調整

可根據實際需求調整 queue 參數：

```go
// 高流量場景
config := queue.Config{
    BufferSize:  50000,  // 更大的緩衝
    WorkerCount: 8,      // 更多 workers
}

// 低延遲場景
config := queue.Config{
    BufferSize:  1000,   // 較小緩衝
    WorkerCount: 2,      // 較少 workers
}
```

## 測試

```bash
# 執行 queue 單元測試
go test ./internal/analyzer/queue/...

# 執行整合測試
go test ./pkg/service/...
```

## 監控指標

Queue 會自動記錄以下指標：
- **Queue Size**: 當前佇列中的訊息數量
- **Queue Capacity**: 佇列總容量
- **Utilization**: 利用率 (%)
- **Dropped Messages**: 因佇列滿而丟棄的訊息數
- **Worker Processing Time**: 每個 worker 的處理時間

## 注意事項

1. **記憶體管理**：BufferSize 越大，記憶體使用越多
2. **背壓處理**：當 queue 持續滿載時，應檢查 exporter 效能
3. **訊息順序**：多 worker 處理可能導致訊息順序不嚴格保證
4. **錯誤處理**：單個訊息失敗不會影響其他訊息

## 相關文件

- [架構圖](docs/architecture.md)
- [eBPF 實作](docs/eBPF.md)
- [優雅關閉](docs/GRACEFUL_SHUTDOWN.md)
