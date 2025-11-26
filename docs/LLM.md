這是應該經由 AnLF 計算出，交給LLM inference 時的 per-UE 資料

| 特徵變數名 (JSON) | 來源運算 (Go)                  | 預期物理意義 (給 LLM 的提示)                     | 是否核心 (Core) |
|-------------------|--------------------------------|--------------------------------------------------|----------------|
| log_pps           | Log10(packet_count)            | 流量大不大？(基本門檻)                           | ✅ Core        |
| avg_len           | byte_count / packet_count      | 是小封包攻擊還是大檔案下載？                     | ✅ Core        |
| icmp_ratio        | icmp_count / packet_count      | 是不是 Ping Flood？(排除法用)                    | ⚠️ Candidate   |
| tcp_ratio         | tcp_count / packet_count       | 攻擊是用什麼協定打的？                           | ✅ Core        |
| udp_ratio         | udp_count / packet_count       | (同上，通常與 TCP 互補，選一個即可，但初期可都留) | ⚠️ Candidate   |
| syn_ratio         | syn_count / packet_count       | 試圖建立連線的頻率？(SYN Flood 特徵)             | ⚠️ Candidate   |
| rst_ratio         | rst_count / packet_count       | 攻擊是否打到了無效端口？(掃描特徵)               | ⚠️ Candidate   |
| flow_rate         | new_flow_count / packet_count  | 連線周轉率 (Random Port 特徵)                    | ✅ Top 1       |
| fan_out           | PopCount(dst_bitmap) / 64.0    | 目標擴散度 (Carpet Bombing 特徵)                 | ✅ Top 2       |
| pkt_density       | packet_count / (active_time)   | 封包的密集程度 (Burstiness)                      | ⚠️ Candidate   |
