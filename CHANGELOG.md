# eBPF 開發環境改進

## 2025-11-26

### 改進項目

1. **移除測試腳本**
   - 刪除 `test-ebpf.sh`
   - 改用標準的 `cmd/ebpf-test` 工具

2. **Makefile 自動化**
   - 新增 `bpf/vmlinux.h` 自動生成 target
   - 新增 `ebpf-generate` target（生成 Go bindings）
   - 新增 `ebpf-test` target（編譯測試工具）
   - `build` 會自動依賴 `ebpf-generate`
   - `clean` 會清理所有生成檔案

3. **.gitignore 優化**
   - 加入 `bpf/vmlinux.h`（2.7MB，不應追蹤）
   - 加入 `pkg/ebpf/anlf_bpf.go`（自動生成）
   - 加入 `pkg/ebpf/anlf_bpf.o`（編譯產物）

### 使用方式

```bash
# 清理
make clean

# 編譯測試工具（會自動生成 vmlinux.h 和 bindings）
make ebpf-test

# 執行測試
sudo ./bin/ebpf-test -iface upfgtp

# 編譯主程式（也會自動處理 eBPF）
make build
```

### 優點

- **減少 repo 大小**：vmlinux.h 不再追蹤（每次 clone 省 2.7MB）
- **跨平台相容**：每個環境生成自己的 vmlinux.h（kernel 特定）
- **自動化流程**：一個指令完成所有編譯步驟
- **清理完整**：`make clean` 清除所有生成檔案
