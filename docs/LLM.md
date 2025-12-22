這是應該經由 AnLF 計算出，交給LLM inference 時的 per-UE 資料

| 特徵變數名 (JSON) | 來源運算 (Go)                  | 預期物理意義 (給 LLM 的提示)                     | 是否核心 (Core) |
|-------------------|--------------------------------|--------------------------------------------------|----------------|
| log_pps           | Log10(packet_count)            | 流量大不大？(基本門檻)                           | ✅ Core        |
| ul_avg_len        | byte_count / packet_count      | 上行是小封包攻擊還是大檔案上傳？                 | ✅ Core        |
| icmp_ratio        | icmp_count / packet_count      | 是不是 Ping Flood？(排除法用)                    | ⚠️ Candidate   |
| tcp_ratio         | tcp_count / packet_count       | 攻擊是用什麼協定打的？                           | ✅ Core        |
| udp_ratio         | udp_count / packet_count       | (同上，通常與 TCP 互補，選一個即可，但初期可都留) | ⚠️ Candidate   |
| syn_ratio         | syn_count / packet_count       | 試圖建立連線的頻率？(SYN Flood 特徵)             | ⚠️ Candidate   |
| rst_ratio         | rst_count / packet_count       | 攻擊是否打到了無效端口？(掃描特徵)               | ⚠️ Candidate   |
| flow_rate         | new_flow_count / packet_count  | 連線周轉率 (Random Port 特徵)                    | ✅ Top 1       |
| fan_out           | PopCount(dst_bitmap) / 64.0    | 目標擴散度 (Carpet Bombing 特徵)                 | ✅ Top 2       |
| pkt_density       | packet_count / (active_time)   | 封包的密集程度 (Burstiness)                      | ⚠️ Candidate   |

這份指南將針對你列出的 10 個特徵變數，提供詳細的 **Go 語言實作細節** 與 **數學計算邏輯**。這些數值是連接 eBPF 底層統計與 LLM 高層推論的橋樑，處理好邊界情況（Edge Cases）至關重要。

以下是針對每個特徵的詳細計算指南：

-----

### 通用處理原則

1.  **資料來源**：假設輸入變數 `m` 為從 eBPF Map 讀出的 `ue_metrics_t` 結構體。
2.  **浮點數處理**：所有比例計算最終都應轉為 `float64`，保留至少 4 位小數精度，以便 LLM 感知微小差異。
3.  **除以零保護**：所有除法分母（通常是 `packet_count`）若為 0，該特徵值應設為 0.0，避免 `NaN` 或 `Inf`。
4.  **空記錄處理**：當 UE 的所有特徵值都為 0 時（無流量活動），系統會跳過 LLM 請求，直接將 risk value 設為 0.0，以節省 LLM 資源。**但該 UE 仍會被 exporter 輸出**，確保完整的 UE 列表追蹤。

-----

### 1\. 流量規模 (Log\_PPS)

  * **核心概念**：將巨大的流量數值壓縮到線性區間，讓模型更容易收斂。
  * **Go 實作公式**：
    ```go
    // 引入 "math" 包
    var logPPS float64
    if m.PacketCount > 0 {
        // 使用 Log10，並加 1 避免 log(0) 無定義 (雖然上面已擋，但為了數學嚴謹性通常用 count+1)
        // 這裡直接取 Log10(count) 即可，因為已知 count > 0
        // 若 count=1, result=0; count=100, result=2; count=100k, result=5
        logPPS = math.Log10(float64(m.PacketCount))
    } else {
        logPPS = 0.0
    }
    ```
  * **數值範圍**：`0.0` \~ `7.0` (對應 10M PPS)。

### 2. 上行平均封包大小 (UL_Avg_Len)

  * **核心概念**：區分政擊類型（小包洪水 vs 大包塞頻寬）。
  * **Go 實作公式**：
    ```go
    var avgLen float64
    if m.PacketCount > 0 {
        avgLen = float64(m.ByteCount) / float64(m.PacketCount)
    } else {
        avgLen = 0.0
    }
    // 選項：可以做 Rounding 取整數，減少 LLM 的雜訊干擾
    // avgLen = math.Round(avgLen) 
    ```
  * **數值範圍**：`0.0` \~ `1500.0` (假設 MTU 1500)。

### 3\. ICMP 比例 (ICMP\_Ratio)

  * **核心概念**：用於快速識別或排除 Ping Flood。
  * **Go 實作公式**：
    ```go
    var icmpRatio float64
    if m.PacketCount > 0 {
        icmpRatio = float64(m.IcmpCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0`。

### 4\. TCP 比例 (TCP\_Ratio)

  * **核心概念**：判斷攻擊協定。正常網頁瀏覽此值較高，UDP Flood 時此值極低。
  * **Go 實作公式**：
    ```go
    var tcpRatio float64
    if m.PacketCount > 0 {
        tcpRatio = float64(m.TcpCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0`。

### 5\. UDP 比例 (UDP\_Ratio)

  * **核心概念**：Carpet Bombing 常見載體。與 TCP Ratio 互補。
  * **Go 實作公式**：
    ```go
    var udpRatio float64
    if m.PacketCount > 0 {
        udpRatio = float64(m.UdpCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0`。

### 6\. SYN 比例 (SYN\_Ratio)

  * **核心概念**：偵測 TCP SYN Flood。正常流量中 SYN 只佔極小部分（握手階段）。若此值飆高 (\>0.8)，幾乎肯定是攻擊。
  * **Go 實作公式**：
    ```go
    var synRatio float64
    if m.PacketCount > 0 {
        synRatio = float64(m.SynCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0`。

### 7\. RST 比例 (RST\_Ratio)

  * **核心概念**：偵測 TCP Reset 攻擊或掃描（端口關閉回應）。
  * **Go 實作公式**：
    ```go
    var rstRatio float64
    if m.PacketCount > 0 {
        rstRatio = float64(m.RstCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0`。

### 8\. 連線周轉率 (Flow\_Rate) - 【Top 1 關鍵特徵】

  * **核心概念**：衡量「新連線建立的頻率」。攻擊者通常隨機生成 Source Port 來偽裝，導致此數值極高。正常長連線（如下載、串流）此值極低。
  * **Go 實作公式**：
    ```go
    var flowRate float64
    if m.PacketCount > 0 {
        flowRate = float64(m.NewFlowCount) / float64(m.PacketCount)
        // 保護：理論上不應超過 1.0，但若有計數誤差可做截斷
        if flowRate > 1.0 { flowRate = 1.0 }
    }
    ```
  * **數值範圍**：`0.0` \~ `1.0` (越接近 1 代表越可能是隨機掃描或 Flood)。

### 9\. 目標擴散度 (Fan\_Out) - 【Top 2 關鍵特徵】

  * **核心概念**：Carpet Bombing 的指紋。利用 Bitmap 計算目標 IP 的分布廣度。
  * **Go 實作公式**：
    ```go
    // 引入 "math/bits" 包
    var fanOut float64
    // m.DstBitmap 是一個 uint64
    ones := bits.OnesCount64(m.DstBitmap) // 計算二進制中 '1' 的個數

    // 分母為 Bitmap 的總位元數 (64)
    fanOut = float64(ones) / 64.0
    ```
  * **數值範圍**：`0.015` (1/64, 單點攻擊) \~ `1.0` (64/64, 地毯式轟炸)。

### 10\. 封包密集度 (Pkt\_Density)

  * **核心概念**：這其實是 PPS 的變體，但如果你的 `active_time` 定義不同，意義就不同。
      * **定義 A (MVP 推薦)**：`active_time` = 採樣視窗時間 (例如 1.0 秒)。這時 `Pkt_Density` 等於原始 `PPS`。
      * **定義 B (進階)**：`active_time` = 該視窗內「第一個封包到最後一個封包的時間差」。這能反映流量是「均勻分佈」還是「瞬間爆發 (Burst)」。
  * **Go 實作公式 (定義 A)**：
    ```go
    // 假設 windowDuration 是你的 Ticker 時間，例如 1.0
    var pktDensity float64
    pktDensity = float64(m.PacketCount) / windowDuration
    ```
  * **建議**：為了與 `log_pps` 區隔，建議此欄位若無特殊 `active_time` 測量手段，可先暫時移除或保留為原始 PPS 數值（不取 Log）。

-----

### 完整的轉換函數範例 (Go)

```go
import (
    "math"
    "math/bits"
)

type UeFeatureVector struct {
    LogPPS    float64 `json:"log_pps"`
    UlAvgLen  float64 `json:"ul_avg_len"`
    IcmpRatio float64 `json:"icmp_ratio"`
    TcpRatio  float64 `json:"tcp_ratio"`
    UdpRatio  float64 `json:"udp_ratio"`
    SynRatio  float64 `json:"syn_ratio"`
    RstRatio  float64 `json:"rst_ratio"`
    FlowRate  float64 `json:"flow_rate"`
    FanOut    float64 `json:"fan_out"`
}

func ConvertToFeatures(m *ue_metrics_t) UeFeatureVector {
    // 基礎分母，避免重複轉換
    pktCnt := float64(m.PacketCount)
    if pktCnt == 0 {
        return UeFeatureVector{} // 全部回傳 0
    }

    // Uplink features
    features := UeFeatureVector{
        LogPPS:    math.Log10(pktCnt),
        UlAvgLen:  float64(m.ByteCount) / pktCnt,
        IcmpRatio: float64(m.IcmpCount) / pktCnt,
        TcpRatio:  float64(m.TcpCount) / pktCnt,
        UdpRatio:  float64(m.UdpCount) / pktCnt,
        SynRatio:  float64(m.SynCount) / pktCnt,
        RstRatio:  float64(m.RstCount) / pktCnt,
        
        // 關鍵特徵
        FlowRate:  float64(m.NewFlowCount) / pktCnt,
        FanOut:    float64(bits.OnesCount64(m.DstBitmap)) / 64.0,
    }

    // Downlink features (if downlink traffic exists)
    dlPktCnt := float64(m.DlPacketCount)
    if dlPktCnt > 0 {
        features.DlPPS = dlPktCnt
        features.DlAvgLen = float64(m.DlByteCount) / dlPktCnt
        features.PPSRatio = dlPktCnt / pktCnt
        features.ByteRatio = float64(m.DlByteCount) / float64(m.ByteCount)
        
        if m.DlTcpCount > 0 {
            features.AckRatio = float64(m.DlAckCount) / float64(m.DlTcpCount)
        }
    }

    return features
}
```

-----

## 下行特徵說明（Downlink Features）

基於 CIC-DDoS2019 研究，下行流量特徵可有效區分真實攻擊和正常流量。

### 11. 下行封包數（DL_PPS）

  * **核心概念**：觀察目標伺服器是否有回應。正常雙向通訊應有對等的上下行流量，單向攻擊則沒有或很少下行封包。
  * **Go 實作公式**：
    ```go
    dlPPS := float64(m.DlPacketCount)
    ```
  * **數值範圍**：`0.0` ~ 取決於實際流量（不取 Log，與 LogPPS 相比較）。

### 12. 下行平均封包大小（DL_AvgLen）

  * **核心概念**：區分正常下載（大封包，MTU 1500 bytes）和攻擊回應（小封包，ICMP/RST）。
  * **Go 實作公式**：
    ```go
    var dlAvgLen float64
    if m.DlPacketCount > 0 {
        dlAvgLen = float64(m.DlByteCount) / float64(m.DlPacketCount)
    }
    ```
  * **數值範圍**：`0.0` ~ `1500.0` bytes。

### 13. PPS 比例（PPS_Ratio）

  * **核心概念**：下行/上行封包數比例。正常流量 ~0.5-2.0，攻擊流量 <0.1。
  * **Go 實作公式**：
    ```go
    var ppsRatio float64
    if m.PacketCount > 0 && m.DlPacketCount > 0 {
        ppsRatio = float64(m.DlPacketCount) / float64(m.PacketCount)
    }
    ```
  * **數值範圍**：`0.0` ~ `無上限（通常 <10.0）`。

### 14. 位元組比例（Byte_Ratio）

  * **核心概念**：下行/上行位元組比例。正常下載 >10，攻擊 <0.5。
  * **Go 實作公式**：
    ```go
    var byteRatio float64
    if m.ByteCount > 0 && m.DlByteCount > 0 {
        byteRatio = float64(m.DlByteCount) / float64(m.ByteCount)
    }
    ```
  * **數值範圍**：`0.0` ~ `無上限（視頻下載可達 >50）`。

### 15. ACK 封包比例（ACK_Ratio）

  * **核心概念**：下行 TCP ACK 封包比例。正常 TCP 連線 >0.7，攻擊（無效連線）<0.3。
  * **Go 實作公式**：
    ```go
    var ackRatio float64
    if m.DlTcpCount > 0 {
        ackRatio = float64(m.DlAckCount) / float64(m.DlTcpCount)
    }
    ```
  * **數值範圍**：`0.0` ~ `1.0`。

-----

### 完整的轉換函數範例（含下行特徵）

```go
import (
    "math"
    "math/bits"
)

type UeFeatureVector struct {
    // Uplink features
    LogPPS    float64 `json:"log_pps"`
    UlAvgLen  float64 `json:"ul_avg_len"`
    IcmpRatio float64 `json:"icmp_ratio"`
    TcpRatio  float64 `json:"tcp_ratio"`
    UdpRatio  float64 `json:"udp_ratio"`
    SynRatio  float64 `json:"syn_ratio"`
    RstRatio  float64 `json:"rst_ratio"`
    FlowRate  float64 `json:"flow_rate"`
    FanOut    float64 `json:"fan_out"`

    // Downlink features
    DlPPS     float64 `json:"dl_pps"`
    DlAvgLen  float64 `json:"dl_avg_len"`
    PPSRatio  float64 `json:"pps_ratio"`
    ByteRatio float64 `json:"byte_ratio"`
    AckRatio  float64 `json:"ack_ratio"`
}

func ConvertToFeatures(m *ue_metrics_t) UeFeatureVector {
    // 基礎分母，避免重複轉換
    pktCnt := float64(m.PacketCount)
    if pktCnt == 0 {
        return UeFeatureVector{} // 全部回傳 0
    }

    // Uplink features
    features := UeFeatureVector{
        LogPPS:    math.Log10(pktCnt),
        UlAvgLen:  float64(m.ByteCount) / pktCnt,
        IcmpRatio: float64(m.IcmpCount) / pktCnt,
        TcpRatio:  float64(m.TcpCount) / pktCnt,
        UdpRatio:  float64(m.UdpCount) / pktCnt,
        SynRatio:  float64(m.SynCount) / pktCnt,
        RstRatio:  float64(m.RstCount) / pktCnt,
        
        // 關鍵特徵
        FlowRate:  float64(m.NewFlowCount) / pktCnt,
        FanOut:    float64(bits.OnesCount64(m.DstBitmap)) / 64.0,
    }

    // Downlink features (if downlink traffic exists)
    dlPktCnt := float64(m.DlPacketCount)
    if dlPktCnt > 0 {
        features.DlPPS = dlPktCnt
        features.DlAvgLen = float64(m.DlByteCount) / dlPktCnt
        features.PPSRatio = dlPktCnt / pktCnt
        features.ByteRatio = float64(m.DlByteCount) / float64(m.ByteCount)
        
        if m.DlTcpCount > 0 {
            features.AckRatio = float64(m.DlAckCount) / float64(m.DlTcpCount)
        }
    }

    return features
}
```