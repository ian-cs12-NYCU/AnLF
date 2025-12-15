# AnLF LLM Server 整合指南

## 概述 (Overview)

本文件說明 AnLF 系統如何與 LLM 伺服器進行異常流量偵測。

**適用模型**: Qwen 2.5 1.5B Instruct  
**伺服器位址**: http://140.113.208.76:8000  
**更新日期**: 2025-12-15

---

## 1. API 端點規格 (API Endpoints)

### 1.1 核心端點：Chat Completions API

**重要**: 使用符合 OpenAI 標準的 Chat 介面，忽略所有 Legacy API (/completion)。

```
URL:     http://140.113.208.76:8000/v1/chat/completions
Method:  POST
Header:  Content-Type: application/json
```

### 1.2 Request Payload 結構（含 JSON Schema）

```json
{
  "model": "default",
  "messages": [
    {
      "role": "system",
      "content": "<system_prompt>"
    },
    {
      "role": "user",
      "content": "<traffic_data_json>"
    }
  ],
  "temperature": 0.1,
  "max_tokens": 1000,
  "response_format": {
    "type": "json_object",
    "schema": {
      "type": "object",
      "properties": {
        "results": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "supi": {"type": "string"},
              "anomaly_score": {"type": "number"}
            },
            "required": ["supi", "anomaly_score"]
          }
        }
      },
      "required": ["results"]
    }
  }
}
```

### 1.3 關鍵參數設定

| 參數名稱 | 建議值 | 原因與說明 |
|---------|--------|-----------|
| `model` | `"default"` | llama-server 啟動時已鎖定模型檔案，此欄位為必填但值不影響推論 |
| `messages` | List of Dicts | 包含 `system` (系統指令) 與 `user` (eBPF 流量數據) |
| `temperature` | `0.1` | **極重要** - 資安偵測需要確定性 (Determinism)，越低越穩定，避免模型發揮創意 |
| `max_tokens` | `1000` | **極重要** - 必須足夠大以避免 JSON 被截斷。批次 10 UEs 建議至少 1000 tokens |
| `response_format.type` | `"json_object"` | 強制 JSON 輸出（llama-server 支援） |
| `response_format.schema` | JSON Schema | **關鍵技術** - 使用 GBNF 引擎鎖定輸出結構，杜絕格式錯誤和截斷問題 |

---

## 2. Prompt 策略 (Prompt Engineering)

### 2.1 模型特性

Qwen 2.5 1.5B 是**小模型** (1.5B 參數)，具有以下特性：

- ✅ 優點：推論速度快、資源需求低
- ⚠️ 缺點：容易「聽不懂複雜指令」或「輸出格式不穩定」 + **One-Shot Example**

### 2.2 System Prompt 範本（One-Shot + 極簡格式）

```
You are a 5G network firewall logic engine. Analyze UE traffic and output anomaly scores.

RULES:
- new_flow_rate > 0.8 => anomaly_score 0.9 (Critical)
- pps > 50000 => anomaly_score 0.8 (High)  
- byte_count > 10000000 in short duration => anomaly_score 0.7 (Medium)
- otherwise => anomaly_score 0.1 (Normal)

OUTPUT FORMAT (Keys first, then values only):
{
  "results": [
    {"supi": "imsi-208930000000001", "anomaly_score": 0.1},
    {"supi": "imsi-208930000000002", "anomaly_score": 0.8}
  ]
}

EXAMPLE INPUT:
[{"supi": "imsi-001", "pps": 60000, "byte_count": 5000000}]

EXAMPLE OUTPUT:
{"results": [{"supi": "imsi-001", "anomaly_score": 0.8}]}

Analyze the user input now. Output JSON only, no explanation.
```

**關鍵要素**：
- **One-Shot Example**: 給小模型一個完整的輸入輸出範例
- **明確規則**: 用數字門檻而非模糊描述（`pps > 50000` 而非 "high traffic"）
- **極簡格式**: 只輸出 `supi` 和 `anomaly_score` 兩個欄位
- **強制禁令**: "Output JSON only, no explanation"

### 2.3 輸出格式簡化原理

**為何只保留 2 個欄位？**

傳統格式（7 個欄位）:
```json
{"ue_ip": "...", "supi": "...", "prediction": "...", "anomaly_score": 0.8, "confidence": 0.9, "timestamp": 123, "model_version": "..."}
```

極簡格式（2 個欄位）:
```json
{"supi": "imsi-001", "anomaly_score": 0.8}
```

**優勢**：
- ✅ **減少 Token 消耗**: 7 欄位 → 2 欄位，降低 70% 輸出長度
- ✅ **降低格式錯誤**: 欄位越少，小模型越不容易「算錯」或「漏掉」
- ✅ **避免截斷**: 1000 max_tokens 可穩定處理 10-15 UEs
- ✅ **提高解析成功率**: JSON 結構簡單，不易損壞
```

---

## 3. 批次處理策略 (Batch Processing)

### 3.1 批次大小限制

⚠️ **關鍵限制**: Qwen 2.5 1.5B 處理大批次時容易出錯

| 批次大小 | 狀態 | 說明 |
|---------|------|------|
| 1-5 UEs | ✅ 最佳 | 穩定、快速、格式正確率高 |
| 5-10 UEs | ⚠️ 可接受 | 偶有格式錯誤，需處理 |
| 10-20 UEs | ⚠️ 風險 | 容易「算錯行數」或「JSON 格式損壞」|
| 20+ UEs | ❌ 不建議 | 極高錯誤率，效能下降 |

### 3.2 建議實作方式

**選項 A: 單一批次請求** (目前實作)
```go
// 一次發送所有 UE，依賴 LLM Server 處理
batchResult, err := llmClient.PredictBatch(ctx, records)
```

**選項 B: 分批發送 + Goroutines** (建議改進)
```go
// 分成多個小批次，並行處理
const batchSize = 5
var wg sync.WaitGroup
resultsChan := make(chan *InferenceResult, len(records))

for i := 0; i < len(records); i += batchSize {
    end := min(i+batchSize, len(records))
    batch := records[i:end]
    
    wg.Add(1)
    go func(b []*UeTrafficRecord) {
        defer wg.Done()
        result, err := llmClient.PredictBatch(ctx, b)
        // 處理結果...
    }(batch)
}

wg.Wait()
```

---

## 4. 錯誤處理與除錯 (Error Handling)

### 4.1 常見錯誤與解法

#### 錯誤 1: `unexpected end of JSON input` (JSON 被截斷)

**症狀**: Log 顯示 `Content length: 999 bytes` 但 JSON 不完整  
**原因**: `max_tokens` 設定太小（如 50），導致 llama-server 強制截斷輸出  
**解法**: 增加 `max_tokens` 到 **1000** (批次 10 UEs) 或 **2000** (批次 20 UEs)

#### 錯誤 2: 格式不穩定（多餘欄位或錯誤結構）

**症狀**: 模型輸出 7 個欄位但某些值錯誤，或順序混亂  
**解法**: 使用 **JSON Schema** 強制鎖定結構：
```json
"response_format": {
  "type": "json_object",
  "schema": {
    "type": "object",
    "properties": {
      "results": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "supi": {"type": "string"},
            "anomaly_score": {"type": "number"}
          },
          "required": ["supi", "anomaly_score"]
        }
      }
    },
    "required": ["results"]
  }
}
```
**原理**: llama-server 的 GBNF 引擎會在生成時**即時過濾不符合 schema 的 tokens**，杜絕格式錯誤

#### 錯誤 3: 小模型「不知道該填什麼值」

**症狀**: JSON 結構正確但內容全是 0.0 或重複值  
**解法**: 在 System Prompt 加入 **One-Shot Example**：
```
EXAMPLE INPUT:
[{"supi": "imsi-001", "pps": 60000}]

EXAMPLE OUTPUT:
{"results": [{"supi": "imsi-001", "anomaly_score": 0.8}]}
```
**原理**: 小模型需要具體範例才能理解「什麼樣的輸入對應什麼樣的輸出」

### 4.2 Fail-Open 機制

⚠️ **關鍵安全機制**: 當 LLM 推論失敗時，避免阻塞整個網路

```go
result, err := llmClient.PredictBatch(ctx, records)
if err != nil {
    // 預設視為 Normal，記錄錯誤但繼續運作
    logger.Warnf("LLM inference failed: %v, assuming Normal", err)
    return defaultNormalResult, nil
}
```

---

## 5. 效能優化建議 (Performance Optimization)

### 5.1 非同步處理 (Asynchronous Processing)

**當前架構**:  
```
Monitor → Analyzer → InferenceQueue (Single Worker) → Detector → LLM Server
```

**建議改進**:
1. **使用 Goroutine Pool**: InferenceQueue 使用多個 Worker 並行處理
2. **批次分割**: 將大批次 (20 UEs) 分成小批次 (5 UEs) 並行發送
3. **Context Timeout**: 每個請求設定合理超時 (5-10 秒)

### 5.2 延遲測量

**關鍵指標**:
- LLM Server 回應時間: < 500ms (5 UEs)
- 批次處理總時間: < 1s (20 UEs 分 4 批)
- Queue 等待時間: < 100ms

### 5.3 Risk Score 解讀

⚠️ **重要觀念**: 模型輸出的 `anomaly_score` (如 0.95) 並非統計機率，而是：
- 模型根據 Prompt 中定義的規則 (如 "High PPS = Attack") 推斷的「信心程度」
- 取決於 temperature 設定和訓練數據
- 應視為「相對風險指標」而非絕對機率

---

## 6. 整合檢查清單 (Integration Checklist)

- [ ] LLM Server 健康檢查 (`/health` endpoint)
- [ ] System Prompt 載入與驗證
- [ ] Request Timeout 設定 (建議 5-10 秒)
- [ ] JSON 輸出清理機制 (移除 Markdown 標記)
- [ ] Fail-Open 錯誤處理 (預設 Normal)
- [ ] 批次大小限制 (5-10 UEs per batch)
- [ ] Goroutine 並行處理 (選配，效能優化)
- [ ] 結果 SUPI 排序 (維持輸出一致性)
- [ ] 日誌記錄 (請求/回應/錯誤)

---

## 7. 測試與驗證 (Testing)

### 7.1 API 端點兼容性

**AnLF LLMClient 支援兩種 API 模式：**

1. **生產環境 (llama-server)**: 使用 OpenAI 兼容 API
   - 端點: `POST /v1/chat/completions`
   - 格式: OpenAI Chat Completions API
   - 伺服器: http://140.113.208.76:8000

2. **測試環境 (test_LLM_server)**: 使用自定義 API
   - 端點: `POST /predict_batch`
   - 格式: 自定義批次推論格式
   - 伺服器: http://127.0.0.1:5001

**自動切換機制**:
- LLMClient 會先嘗試 OpenAI API
- 如果失敗，自動降級到自定義 API
- 確保與兩種伺服器的兼容性

### 7.2 本地測試伺服器

使用 `test_LLM_server/llm_server.py` 進行本地測試：

```bash
cd test_LLM_server
python3 llm_server.py 5001
```

**支援端點**:
- `POST /v1/chat/completions`: OpenAI 兼容 API（返回簡化格式：只有 supi 和 anomaly_score）
- `GET /health`: 健康檢查

**測試範例**:
```bash
curl -X POST http://127.0.0.1:5001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "test",
    "messages": [
      {"role": "user", "content": "[{\"supi\": \"imsi-001\", \"pps\": 1000}]"}
    ]
  }'
```

### 7.3 生產環境配置

```yaml
# anlf/config/anlfcfg.yaml
configuration:
  anomalyDetection:
    enable: true
    serverUrl: http://140.113.208.76:8000  # 生產 llama-server
    timeout: 5
    batchSize: 10  # 每次發送 10 個 UE
    systemPromptPath: ./prompts/anomaly_detection_basic.txt
```

**測試環境配置**:
```yaml
configuration:
  anomalyDetection:
    enable: true
    serverUrl: http://127.0.0.1:5001  # 本地測試伺服器
    timeout: 5
    batchSize: 10
    systemPromptPath: ./prompts/anomaly_detection_basic.txt
```

---

## 附錄：常見問題 (FAQ)

**Q: 為什麼使用 Qwen 2.5 1.5B 而非更大模型？**  
A: 權衡推論延遲與準確度。1.5B 模型可在 <500ms 內回應，適合即時偵測。

**Q: 可以使用其他 LLM 嗎？**  
A: 可以，只需確保符合 OpenAI Chat Completions API 格式並支援 `response_format.schema`。

**Q: 為什麼要用 JSON Schema？**  
A: llama-server 的 GBNF 引擎會在生成時**即時過濾不符合 schema 的 tokens**，這是唯一能 100% 保證輸出格式的方法。沒有 schema，小模型會隨機輸出任何東西。

**Q: max_tokens 應該設多少？**  
A: **經驗公式**: `max_tokens = 100 * batch_size`。例如批次 10 UEs → 1000 tokens，批次 20 UEs → 2000 tokens。寧可多不可少，避免截斷。

**Q: One-Shot Example 有多重要？**  
A: **極度重要**。對於 1.5B 小模型，沒有範例就像「叫一個沒見過 JSON 的人寫 JSON」，成功率 < 50%。加入 One-Shot 後成功率 > 90%。

**Q: 如何提高偵測準確度？**  
A: (1) 優化 System Prompt 中的規則門檻 (2) 提供更多 eBPF 特徵 (3) Fine-tune 模型 (4) 使用更大模型（如 7B）

**Q: Goroutine 並行是否安全？**  
A: 是，只要每個 goroutine 使用獨立的 context 和 HTTP client，並正確使用 WaitGroup。
