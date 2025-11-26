# eBPF 測試指南

## 編譯與準備

### 1. 編譯 eBPF 測試工具

eBPF 程式使用 Makefile 自動化編譯流程，會自動生成 `vmlinux.h` 和 Go bindings。

```bash
cd /home/vagrant/AnLF/anlf

# 編譯 eBPF 測試工具
make ebpf-test
```

編譯流程：
1. 從 kernel BTF 生成 `bpf/vmlinux.h`（約 2.7MB）
2. 使用 bpf2go 編譯 `bpf/anlf.c` 生成 Go bindings
3. 編譯測試工具到 `bin/ebpf-test`

**注意**：`vmlinux.h` 和生成的 `.go`/`.o` 檔案已加入 `.gitignore`，不會被追蹤到 git。

## 測試步驟

### 1. 檢查目標 interface 是否存在

```bash
ip link show upfgtp
```

如果不存在，可以用其他 interface 測試，例如：
- `eth0`, `eth1` - 實體網卡
- `lo` - loopback（可用於簡單測試）
- `enp0s3` - 常見的網卡名稱

### 2. 啟動測試工具

```bash
cd /home/vagrant/AnLF/anlf

# 使用預設 interface (upfgtp)
sudo ./bin/ebpf-test

# 或指定其他 interface
sudo ./bin/ebpf-test -iface eth0

# 自訂讀取間隔
sudo ./bin/ebpf-test -iface upfgtp -interval 2s
```

參數說明：
- `-iface`: 要監聽的 interface 名稱（預設: upfgtp）
- `-interval`: 讀取間隔（預設: 1s）

### 3. 使用 loopback 做簡單測試

如果 upfgtp 不存在，可以先用 lo 測試：

```bash
# Terminal 1: 啟動監聽
sudo ./bin/ebpf-test -iface lo

# Terminal 2: 產生流量
ping -c 10 127.0.0.1
```

**注意**: lo interface 不會有 GTP-U 封包，所以看不到內層 IP，但可以驗證 XDP attach 是否成功。

### 4. 模擬 GTP-U 流量測試

如果要測試完整的 GTP-U 解析功能，需要：

1. **確認 upfgtp interface 存在且有流量**:
   ```bash
   # 檢查 interface
   ip link show upfgtp
   
   # 監聽流量（另一個 terminal）
   sudo tcpdump -i upfgtp -n
   ```

2. **啟動測試工具**:
   ```bash
   sudo ./bin/ebpf-test -iface upfgtp
   ```

3. **從 UE 發送流量**:
   - 如果有實際的 UE 連接，從 UE 發送 ping 或瀏覽網頁
   - 觀察測試工具輸出的統計資訊

## 預期輸出

### 成功 attach XDP
```
2025/11/26 05:30:00 Starting eBPF test tool
2025/11/26 05:30:00 Interface: upfgtp
2025/11/26 05:30:00 Read interval: 1s
2025/11/26 05:30:00 Loading eBPF program...
2025/11/26 05:30:00 Attaching XDP to interface upfgtp...
2025/11/26 05:30:00 ✓ XDP attached successfully
2025/11/26 05:30:00 Monitoring traffic... (Ctrl+C to stop)
```

### 沒有流量
```
[05:30:01] No traffic detected
[05:30:02] No traffic detected
```

### 有 GTP-U 流量
```
=== Metrics at 05:30:03 ===

UE IP: 10.60.0.1
  Packets: 150, Bytes: 15000
  TCP: 100, UDP: 50, ICMP: 0
  TCP Flags - SYN: 5, RST: 0
  New Flows: 10
  Fan-Out (unique dsts): 3/64
```

## 故障排除

### 1. Permission denied
```bash
# 需要 root 權限
sudo ./bin/ebpf-test -iface upfgtp
```

### 2. Interface not found
```bash
# 檢查可用的 interface
ip link show

# 使用存在的 interface
sudo ./bin/ebpf-test -iface eth0
```

### 3. XDP attach 失敗
可能原因：
- Interface 不支援 XDP（某些虛擬網卡）
- 已有其他 XDP 程式 attached
- Kernel 版本太舊

檢查：
```bash
# 查看 interface 支援的功能
ethtool -k upfgtp | grep xdp

# 查看是否有其他 XDP 程式
sudo bpftool net show
```

### 4. 看不到內層 IP 資料
可能原因：
- 流量不是 GTP-U (port 2152)
- GTP-U 封包格式不符預期
- Interface 收不到流量

驗證：
```bash
# 確認有 GTP-U 流量
sudo tcpdump -i upfgtp -n udp port 2152 -c 5
```

## 進階測試

### 重新編譯

如果修改了 eBPF C 程式碼：

```bash
# 清理舊的生成檔案
make clean

# 重新編譯
make ebpf-test
```

### 檢查 eBPF map 內容

```bash
# 查看載入的 eBPF 程式
sudo bpftool prog show

# 查看 map
sudo bpftool map show

# 讀取 map 內容（找到 ue_metrics_map 的 ID）
sudo bpftool map dump id <MAP_ID>
```

### 產生測試流量

如果有 free5GC 環境：
```bash
# 從 UE 端執行
ping -c 100 google.com
curl http://example.com
```

## Makefile 指令參考

```bash
make ebpf-test      # 編譯 eBPF 測試工具
make ebpf-generate  # 只生成 eBPF Go bindings
make build          # 編譯主程式（會自動生成 eBPF）
make clean          # 清理所有生成檔案（包含 vmlinux.h）
```

## 測試工具架構說明

測試工具 (`cmd/ebpf-test`) 完全使用 `pkg/ebpf` 包的程式碼：

```
cmd/ebpf-test/main.go
    ↓ import
pkg/ebpf/manager.go
    ├── Load()         → 載入 eBPF 程式到 kernel
    ├── AttachXDP()    → attach 到網卡
    ├── ReadMetrics()  → 從 eBPF map 讀取資料
    └── Close()        → 卸載程式
    ↓ 使用
pkg/ebpf/anlf_bpf.go (自動生成)
    ├── anlfUeMetricsT    → Go struct 對應 C struct
    ├── loadAnlfObjects() → 載入 embedded 的 .o 檔
    └── _AnlfBytes        → embedded eBPF 字節碼
    ↓ 來自
bpf/anlf.c (編譯為 anlf_bpf.o)
    └── anlf_xdp_main() → XDP 程式入口
```

**關鍵特性**：
- eBPF 字節碼 embedded 在 Go binary 中，無需額外檔案
- `pkg/ebpf` 可被任何程式復用（測試工具、主程式）
- Kernel ↔ User Space 透過 eBPF map 共享資料（零拷貝）

## 下一步

測試成功後，可以整合到 AnLF 主程式：
1. 在 `pkg/app/app.go` 中初始化 eBPF manager
2. 定期讀取 metrics
3. 結合 ML 模型進行異常檢測
