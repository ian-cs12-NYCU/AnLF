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

### 1.2 Request Payload 結構

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
  "max_tokens": 50,
  "response_format": {"type": "json_object"}
}
```

### 1.3 關鍵參數設定

| 參數名稱 | 建議值 | 原因與說明 |
|---------|--------|-----------|
| `model` | `"default"` | llama-server 啟動時已鎖定模型檔案，此欄位為必填但值不影響推論 |
| `messages` | List of Dicts | 包含 `system` (系統指令) 與 `user` (eBPF 流量數據) |
| `temperature` | `0.1` | **極重要** - 資安偵測需要確定性 (Determinism)，越低越穩定，避免模型發揮創意 |
| `max_tokens` | `50` | **極重要** - 僅需 JSON 格式回應如 `{"label": "Attack"}`，限制長度可降低延遲 |
| `response_format` | `{"type": "json_object"}` | 嘗試強制 JSON 輸出 (需伺服器版本支援)，若出現 400 錯誤可移除改用 Prompt 控制 |

---

## 2. Prompt 策略 (Prompt Engineering)

### 2.1 模型特性

Qwen 2.5 1.5B 是**小模型** (1.5B 參數)，具有以下特性：

- ✅ 優點：推論速度快、資源需求低
- ⚠️ 缺點：容易「聽不懂複雜指令」或「輸出格式不穩定」
- 🎯 策略：Prompt 必須**極度簡潔、強勢、明確**

### 2.2 System Prompt 範本

```
You are a strict network firewall. Analyze the input traffic JSON. 
Output ONLY a JSON object with a single key 'label' and value 'Normal' or 'Attack'. 
Do not explain. No preamble.
```

**關鍵要素**：
- 明確角色定位 ("strict network firewall")
- 精確輸出格式要求 ("ONLY a JSON object")
- 嚴格禁止額外說明 ("Do not explain. No preamble.")

### 2.3 User Prompt 範本

直接將 eBPF 擷取的流量數據轉換為 JSON 字串：

```json
{
  "ue_ip": "10.60.0.1",
  "supi": "imsi-208930000000001",
  "pkt_count": 15230,
  "byte_count": 8234567,
  "duration_sec": 5,
  "pps": 3046,
  "bps": 13175269.6
}
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

#### 錯誤 1: `400 Bad Request`

**原因**: `response_format: {"type": "json_object"}` 不被支援  
**解法**: 移除該參數，完全依賴 System Prompt 控制輸出格式

#### 錯誤 2: 模型回傳冗長說明

**症狀**: 回應包含 `"Here is the analysis: {"label": "Attack"}"`  
**解法**: 在 System Prompt 最後加強禁令：
```
"Do not explain. No preamble. No commentary. Output JSON only."
```

#### 錯誤 3: JSON 解析失敗

**症狀**: 輸出包含 Markdown 標記如 ` ```json ... ``` `  
**解法**: 在 Go 程式碼中清理輸出：
```go
import "strings"

content = strings.TrimPrefix(content, "```json")
content = strings.TrimSuffix(content, "```")
content = strings.TrimSpace(content)
```

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
- `POST /predict`: 單一 UE 推論 (Legacy)
- `POST /predict_batch`: 批次 UE 推論
- `GET /health`: 健康檢查

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
A: 可以，只需確保符合 OpenAI Chat Completions API 格式即可。

**Q: 如何提高偵測準確度？**  
A: (1) 優化 System Prompt (2) 提供更多 eBPF 特徵 (3) Fine-tune 模型 (4) 增加 temperature 多樣性測試

**Q: Goroutine 並行是否安全？**  
A: 是，只要每個 goroutine 使用獨立的 context 和 HTTP client，並正確使用 WaitGroup。
