# AnLF 系統架構與資料流向

## 1. 系統總覽 (System Overview)

```mermaid
%%{init: {'theme':'neutral'}}%%
graph TB
    subgraph "5G Network Entities"
        UE[UE Devices<br/>使用者設備]
        UPF[UPF<br/>User Plane Function]
        NRF[NRF<br/>Network Repository]
        SMF[SMF/Mock SMF<br/>Session Management]
    end
    
    subgraph "AnLF - Analytics Logical Function"
        direction TB
        eBPF[eBPF XDP Program<br/>Kernel Space<br/>封包擷取與統計]
        Monitor[TrafficMonitor<br/>週期性輪詢]
        Analyzer[FlowAnalyzer<br/>流量分析器]
        
        subgraph "Export Pipeline"
            Queue[ExportQueue<br/>Message Queue<br/>Multi-Worker]
            Dispatcher[ExportDispatcher<br/>訊息分發器]
            
            subgraph "Exporters"
                CSV[CsvExporter<br/>流量記錄]
                LLM[LLM Exporter<br/>推論結果<br/>未來擴展]
            end
        end
        
        SBI_Server[SBI Server<br/>Service Interface]
    end
    
    subgraph "NWDAF - Network Data Analytics Function"
        SBI_NW[SBI APIs<br/>Data Management]
        Collector[Collector<br/>NF Resource]
        Processor[Processor<br/>資料處理]
        MTLF[MTLF Flask<br/>LoRA Model Provider]
        DB[(MongoDB<br/>時序資料庫)]
    end
    
    UE -->|網路流量| UPF
    UPF -->|GTP-U 封包| eBPF
    
    eBPF -->|Raw Metrics| Monitor
    SMF -.->|UE Info<br/>IP-SUPI Mapping| Monitor
    
    Monitor -->|Feature Vectors<br/>via Channel| Analyzer
    Analyzer -->|Enqueue Message| Queue
    Queue -->|Dispatch by Type| Dispatcher
    Dispatcher -->|Traffic Record| CSV
    Dispatcher -.->|Future: LLM Result| LLM
    
    AnLF -->|NF Registration| NRF
    
    SBI_NW --> Collector
    Collector --> Processor
    Processor -->|Get NF Load Prediction| MTLF
    Processor -->|Store Analytics| DB
    MTLF -.->|Prediction Result| Processor
    
    style eBPF fill:#ff9999
    style Monitor fill:#99ccff
    style Queue fill:#ffdd99
    style Dispatcher fill:#ddff99
    style CSV fill:#ffcc99
    style LLM fill:#ccccff,stroke-dasharray: 5 5
    style Stub fill:#dddddd
    style MTLF fill:#cc99ff
```

## 2. AnLF 內部資料流管道 (Internal Data Pipeline)

```mermaid
%%{init: {'theme':'neutral'}}%%
sequenceDiagram
    participant K as Kernel Space<br/>(eBPF Map)
    participant M as TrafficMonitor
    participant C as Go Channel<br/>(Feature)
    participant A as FlowAnalyzer
    participant Q as ExportQueue<br/>(Message Queue)
    participant W as Queue Workers<br/>(4 goroutines)
    participant D as ExportDispatcher
    participant E as Exporter<br/>(CSV/LLM)
    participant F as Output File
    
    Note over K: 封包到達時<br/>累計統計數據
    
    loop Every Poll Interval (e.g., 5s)
        M->>K: ReadAndReset()
        K-->>M: map[UE_IP]Metrics
        Note over K: 讀取後清空 Map
        
        M->>M: 遍歷所有已知 UE
        
        loop For Each UE
            M->>M: ConvertToTrafficRecord()<br/>計算特徵向量
            M->>C: Send (Non-blocking)
            
            alt Channel Full
                M->>M: Drop record & Log warning
            end
        end
    end
    
    loop Analyzer Processing Loop
        C->>A: Receive Feature Vector
        A->>A: Create ExportMessage<br/>(Type + Data)
        A->>Q: Enqueue(msg)
        
        alt Queue Full
            Q-->>A: Drop & Log warning
        end
    end
    
    par Worker Processing (Parallel)
        loop Worker-1
            Q->>W: Dequeue message
            W->>D: Handle(msg)
            D->>D: Route by msg.Type
            
            alt TrafficRecord
                D->>E: CsvExporter.Export()
                E->>F: Write CSV row
            else LLMInference (Future)
                D->>E: LlmExporter.Export()
                E->>F: Write JSON/JSONL
            end
        end
    and Worker-2..4
        Note over W: 其他 3 個 workers<br/>同時並行處理
    end
    
    Note over A,F: Graceful Shutdown:<br/>Stop → Drain Queue → Flush Files
```

## 3. eBPF 資料收集層 (eBPF Data Collection Layer)

```mermaid
%%{init: {'theme':'neutral'}}%%
graph LR
    subgraph "Network Interface"
        Packet[GTP-U Packet<br/>from UPF]
    end
    
    subgraph "Kernel Space - eBPF XDP"
        XDP[XDP Hook Point<br/>anlf_xdp_main]
        
        subgraph "Packet Processing"
            Parse[Parse Headers<br/>Eth → IP → UDP → GTP-U]
            Extract[Extract Inner IP<br/>Source = UE IP]
            Update[Update Metrics Map]
        end
        
        Map[(BPF_MAP_TYPE_HASH<br/>Key: UE_IP<br/>Value: ue_metrics_t)]
    end
    
    subgraph "Metrics Structure"
        Metrics["packet_count<br/>byte_count<br/>tcp_count / udp_count<br/>syn_count / rst_count<br/>new_flow_count<br/>dst_bitmap"]
    end
    
    Packet --> XDP
    XDP --> Parse
    Parse --> Extract
    Extract --> Update
    Update --> Map
    Map -.-> Metrics
    
    style XDP fill:#ff9999
    style Map fill:#ffcc99
    style Metrics fill:#ffffcc
```

## 4. 特徵工程轉換 (Feature Engineering)

```mermaid
%%{init: {'theme':'neutral'}}%%
graph TB
    Raw["<b>Raw eBPF Metrics</b><br/>packet_count: 50000<br/>byte_count: 75MB<br/>tcp_count: 30000<br/>udp_count: 20000<br/>syn_count: 15000<br/>new_flow_count: 2000<br/>dst_bitmap: 0xFF..."]
    
    Calc1["PPS =<br/>packet_count / window"]
    Calc2["AvgLen =<br/>byte_count / packet_count"]
    Calc3["TcpRatio =<br/>tcp_count / packet_count"]
    Calc4["SynRatio =<br/>syn_count / packet_count"]
    Calc5["FlowRate =<br/>new_flow_count / window"]
    Calc6["FanOut =<br/>CountBits(dst_bitmap)"]
    Calc7["LogPPS =<br/>log10(PPS+1)"]
    
    Features["<b>UeTrafficRecord</b><br/><b>(Feature Vector)</b><br/>Timestamp: 1734234567<br/>Supi: imsi-001010...<br/>UeIp: 60.60.0.1<br/><br/>LogPPS: 4.0<br/>AvgLen: 1500.0<br/>TcpRatio: 0.6<br/>UdpRatio: 0.4<br/>SynRatio: 0.3<br/>NewFlowRate: 400.0<br/>FanOut: 128"]
    
    Raw --> Calc1
    Raw --> Calc2
    Raw --> Calc3
    Raw --> Calc4
    Raw --> Calc5
    Raw --> Calc6
    Raw --> Calc7
    
    Calc1 --> Features
    Calc2 --> Features
    Calc3 --> Features
    Calc4 --> Features
    Calc5 --> Features
    Calc6 --> Features
    Calc7 --> Features
    
    style Raw fill:#ffcccc,stroke:#cc0000
    style Features fill:#ccffcc,stroke:#00cc00
    style Calc1 fill:#ffffcc,stroke:#cccc00
    style Calc2 fill:#ffffcc,stroke:#cccc00
    style Calc3 fill:#ffffcc,stroke:#cccc00
    style Calc4 fill:#ffffcc,stroke:#cccc00
    style Calc5 fill:#ffffcc,stroke:#cccc00
    style Calc6 fill:#ffffcc,stroke:#cccc00
    style Calc7 fill:#ffffcc,stroke:#cccc00
```

## 5. Message Queue 架構 (Export Message Queue Architecture)

```mermaid
%%{init: {'theme':'neutral'}}%%
graph TB
    subgraph "Producer"
        FA[FlowAnalyzer<br/>生產者]
    end
    
    subgraph "Message Queue System"
        direction TB
        Queue[ExportQueue<br/>Buffered Channel<br/>容量: 10000]
        
        subgraph "Workers"
            W1[Worker 1]
            W2[Worker 2]
            W3[Worker 3]
            W4[Worker 4]
        end
        
        Monitor[Queue Monitor<br/>監控利用率]
    end
    
    subgraph "Consumer (Dispatcher)"
        Disp[ExportDispatcher<br/>訊息分發器]
        
        subgraph "Export Types"
            TR[MessageType:<br/>TrafficRecord]
            LLM[MessageType:<br/>LLMInference<br/>未來]
        end
    end
    
    subgraph "Exporters (Output)"
        CSV[CsvExporter<br/>CSV 檔案]
        JSON[LLM Exporter<br/>JSON/JSONL<br/>未來]
    end
    
    FA -->|Enqueue| Queue
    Queue -->|Distribute| W1
    Queue -->|Distribute| W2
    Queue -->|Distribute| W3
    Queue -->|Distribute| W4
    
    W1 --> Disp
    W2 --> Disp
    W3 --> Disp
    W4 --> Disp
    
    Monitor -.->|30s Report| Queue
    
    Disp -->|Route| TR
    Disp -.->|Future| LLM
    
    TR --> CSV
    LLM -.-> JSON
    
    style Queue fill:#ffdd99
    style W1 fill:#ddffdd
    style W2 fill:#ddffdd
    style W3 fill:#ddffdd
    style W4 fill:#ddffdd
    style Disp fill:#ddff99
    style TR fill:#99ccff
    style LLM fill:#ccccff,stroke-dasharray: 5 5
    style CSV fill:#ffcc99
    style JSON fill:#ccccff,stroke-dasharray: 5 5
```

### Message Queue 特性
- **高效能**: 使用 Go buffered channel，支援 10000 訊息緩衝
- **並行處理**: 4 個 worker goroutines 並行處理訊息
- **易擴展**: 透過 MessageType 輕鬆添加新的 export 類型
- **好管理**: 內建監控，每 30 秒報告 queue 利用率

### 訊息類型擴展範例
```go
// 現在：流量記錄
MessageTypeTrafficRecord -> CsvExporter -> traffic_*.csv

// 未來：LLM 推論結果
MessageTypeLLMInference -> LlmExporter -> inference_*.jsonl
```

## 6. 雙模式運作流程 (Dual-Mode Operation)

```mermaid
%%{init: {'theme':'neutral'}}%%
graph TB
    Start[AnLF Startup]
    
    Start --> Config{Read Config:<br/>EnableRecording?}
    
    Config -->|true| RecordMode[Recording Mode<br/>資料記錄]
    Config -->|false| DisableMode[Disabled Mode<br/>不記錄資料]
    
    subgraph "Recording Mode"
        RecordMode --> CSV[CsvExporter]
        CSV --> File[output/YYYYMMDD_HHMMSS/<br/>traffic_YYYYMMDD_HHMMSS.csv]
        File --> Training[離線分析與<br/>ML 模型訓練]
    end
    
    subgraph "Disabled Mode"
        DisableMode --> Stub[StubExporter]
        Stub --> NoOp[No-op<br/>資料不輸出]
    end
    
    style RecordMode fill:#99ccff
    style DisableMode fill:#dddddd
    style File fill:#ffffcc
    style NoOp fill:#eeeeee
```

## 7. NWDAF 資料流 (NWDAF Data Flow)

```mermaid
%%{init: {'theme':'neutral'}}%%
sequenceDiagram
    participant NF as Network Function<br/>(SMF/AMF/UPF)
    participant API as NWDAF<br/>SBI API
    participant Coll as Collector
    participant Proc as Processor
    participant MTLF as MTLF Flask<br/>(LoRA Provider)
    participant DB as MongoDB
    
    NF->>API: GET /nnwdaf-analyticsinfo<br/>Request NF Load Analytics
    API->>Coll: Route to Collector
    
    Coll->>Coll: Collect NF Resource Usage
    Coll->>Proc: Process Request
    
    Proc->>MTLF: GetPredict(nfType)
    MTLF->>MTLF: Load Model with LoRA
    MTLF->>MTLF: Generate Prediction
    MTLF-->>Proc: NfLoadPrediction<br/>(CPU, Memory, LoadLevel)
    
    Proc->>DB: Store Analytics Data<br/>(Time Series)
    
    Proc-->>API: Analytics Response
    API-->>NF: HTTP Response<br/>{prediction, confidence}
    
    Note over MTLF: MTLF 提供經過 LoRA 微調的<br/>NF 負載預測模型
```

## 8. 系統生命週期管理 (Lifecycle Management)

```mermaid
%%{init: {'theme':'neutral'}}%%
stateDiagram-v2
    [*] --> Initializing
    
    Initializing --> LoadingConfig: Read anlfcfg.yaml
    LoadingConfig --> LoadingeBPF: Load eBPF objects
    LoadingeBPF --> AttachingXDP: Attach to network interface
    AttachingXDP --> InitComponents: Create Monitor/Analyzer/Exporter
    InitComponents --> RegisterNRF: Register with NRF
    
    RegisterNRF --> Running
    
    state Running {
        [*] --> Monitoring
        Monitoring --> Analyzing: Feature vectors via channel
        Analyzing --> Exporting: CSV or Stub
        Exporting --> Monitoring: Continue loop
    }
    
    Running --> ShuttingDown: SIGTERM/SIGINT
    
    ShuttingDown --> StopMonitor: Stop TrafficMonitor
    StopMonitor --> StopAnalyzer: Close channel & wait
    StopAnalyzer --> FlushExporter: exporter.Shutdown()
    FlushExporter --> DetachXDP: Detach eBPF program
    DetachXDP --> DeregisterNRF: Deregister from NRF
    
    DeregisterNRF --> [*]
```

## 9. 關鍵資料結構 (Key Data Structures)

### eBPF Map Value (Kernel)
```c
struct ue_metrics_t {
    u64 packet_count;      // 總封包數
    u64 byte_count;        // 總位元組數
    u64 tcp_count;         // TCP 封包數
    u64 udp_count;         // UDP 封包數
    u64 icmp_count;        // ICMP 封包數
    u64 syn_count;         // TCP SYN 封包數
    u64 rst_count;         // TCP RST 封包數
    u64 new_flow_count;    // 新連線數
    u64 dst_bitmap;        // 目標 IP 分散度 (Bitmap)
};
```

### Feature Vector (User Space)
```go
type UeTrafficRecord struct {
    Timestamp   int64   // Unix timestamp
    Supi        string  // UE identifier
    UeIp        string  // UE IP address
    
    // Normalized features
    LogPPS      float64 // log10(PPS + 1)
    AvgLen      float64 // Average packet length
    TcpRatio    float64 // TCP packet ratio
    UdpRatio    float64 // UDP packet ratio
    IcmpRatio   float64 // ICMP packet ratio
    SynRatio    float64 // TCP SYN ratio
    RstRatio    float64 // TCP RST ratio
    NewFlowRate float64 // New flows per second
    FanOut      float64 // Destination diversity (0-256)
}
```

### Export Message Structure
```go
type ExportMessage struct {
    Type MessageType  // "traffic_record", "llm_inference", etc.
    Data interface{}  // 實際資料內容
}

// 範例：流量記錄訊息
{
    Type: "traffic_record",
    Data: &UeTrafficRecord{...}
}

// 未來：LLM 推論結果訊息
{
    Type: "llm_inference",
    Data: &LLMInferenceResult{...}
}
```

## 10. 效能考量與設計決策

### eBPF 層
- **XDP Hook**: 在網路堆疊最早期攔截封包，延遲最低
- **Per-UE Map**: 使用 HASH Map 支援動態 UE 數量
- **Atomic Updates**: eBPF 內建原子操作，無需額外鎖

### User Space 層
- **Non-blocking Channel**: 防止 eBPF 讀取被阻塞
- **ReadAndReset()**: 原子讀取後清空，避免重複計數
- **Buffered Channel**: 1024 容量緩衝，應對流量突發

### Export Message Queue
- **Large Buffer**: 10000 訊息容量，處理高流量突發
- **Multi-Worker**: 4 個並行 goroutines，提升吞吐量
- **Type-based Routing**: 根據 MessageType 動態分發到不同 exporter
- **Graceful Drain**: 關閉時確保所有佇列訊息都被處理
- **Monitoring**: 每 30 秒報告佇列利用率，超過 80% 發出警告

### 資料完整性
- **Zero-filling**: 沒有流量的 UE 也會產生零值記錄
- **Graceful Shutdown**: 確保 CSV 完整 flush，無資料遺失
- **Queue Persistence**: 關閉時先停止生產者，再 drain 完所有訊息

---

## 補充說明

### AnLF 目前實作狀態
- **已實作**: CsvExporter（記錄模式）、StubExporter（停用記錄）
- **未實作**: LlmExporter（即時推論模式）尚在規劃中
- **資料收集**: 專注於 eBPF 層的封包統計與特徵提取
- **輸出格式**: CSV 格式用於離線分析與 ML 模型訓練

### NWDAF & MTLF
- **MTLF 角色**: 提供經過 LoRA 微調的 NF 負載預測模型
- **主要用途**: 預測 5G Network Functions (SMF/AMF/UPF) 的資源使用狀況
- **預測指標**: CPU Usage, Memory Usage, Load Level Average/Peak
- **模型架構**: Flask Server + LoRA Fine-tuned Models

### 資料流總結 (更新版本)
```
[封包流量] → [eBPF XDP] → [TrafficMonitor] → [Feature Channel] → [FlowAnalyzer]
                                                                        ↓
                                                                   [ExportQueue]
                                                                   (Message Queue)
                                                                        ↓
                                                      4 Workers → [ExportDispatcher]
                                                                        ↓
                                                              ┌─────────┴─────────┐
                                                              ↓                   ↓
                                                        [CsvExporter]      [LlmExporter]
                                                              ↓                (未來)
                                                        [CSV 檔案]
                                                      (用於訓練/分析)
```