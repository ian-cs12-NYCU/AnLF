# Graceful Shutdown 設計文檔

## 概述

AnLF 實現了完善的 graceful shutdown 機制，確保在接收到終止信號時能夠優雅地關閉所有組件，避免數據丟失和資源洩漏。

## 核心組件

### 1. Lifecycle Manager (`pkg/app/lifecycle.go`)

生命週期管理器提供統一的組件管理接口：

```go
type Lifecycle interface {
    Start(ctx context.Context) error
    Stop(timeout time.Duration) error
    Name() string
}
```

**特性:**
- 組件註冊與管理
- 按註冊逆序關閉（LIFO）
- 每個組件獨立超時控制
- 錯誤隔離（單個組件失敗不影響其他組件）

**使用方式:**
```go
// 在 Phase 2-4 添加新組件時
ebpfComponent := &MyEbpfComponent{}
app.GetLifecycleManager().Register(ebpfComponent)

// 實現 Lifecycle 接口
func (c *MyEbpfComponent) Start(ctx context.Context) error {
    // 啟動邏輯
}

func (c *MyEbpfComponent) Stop(timeout time.Duration) error {
    // 清理邏輯
}

func (c *MyEbpfComponent) Name() string {
    return "eBPF Manager"
}
```

### 2. 超時控制機制

#### 多層超時保護：

1. **全局 Shutdown 超時** (預設 10 秒)
   - 控制整個應用關閉流程
   - 可通過 `SetShutdownTimeout()` 自定義

2. **HTTP Server 關閉超時** (5 秒)
   - 等待正在處理的 HTTP 請求完成
   - 超時後強制關閉

3. **組件關閉超時** (5 秒/每個組件)
   - 確保每個組件有足夠時間清理
   - 超時後繼續下一個組件

4. **WaitGroup 超時** (15 秒)
   - 檢測是否有 goroutine 洩漏
   - 發出警告但不阻塞退出

### 3. 關閉順序

```
信號接收 (SIGINT/SIGTERM)
    ↓
Context Cancel
    ↓
HTTP Server Shutdown (5s timeout)
    ├─ 停止接受新連線
    ├─ 等待現有請求完成
    └─ NRF Deregistration
    ↓
Lifecycle Manager StopAll (5s per component)
    ├─ Component N
    ├─ Component N-1
    ├─ ...
    └─ Component 1
    ↓
WaitGroup Wait (15s timeout)
    ↓
程式退出
```

## 關鍵改進點

### 1. 信號日誌
```go
select {
case <-a.ctx.Done():
    logger.MainLog.Infof("Shutdown signal received, reason: %v", a.ctx.Err())
}
```
- 明確記錄關閉原因
- 幫助診斷異常關閉

### 2. 並行關閉 + 超時保護
```go
shutdownComplete := make(chan struct{})
go func() {
    defer close(shutdownComplete)
    // 關閉邏輯
}()

select {
case <-shutdownComplete:
    logger.MainLog.Infof("Graceful shutdown completed successfully")
case <-shutdownCtx.Done():
    logger.MainLog.Warnf("Shutdown timeout, forcing termination")
}
```
- 避免無限等待
- 提供清晰的超時反饋

### 3. HTTP Server 強制關閉回退
```go
if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
    logger.SBILog.Errorf("Error during server shutdown: %v", err)
    // 降級處理：強制關閉
    if err := s.httpServer.Close(); err != nil {
        logger.SBILog.Errorf("Error forcing server close: %v", err)
    }
}
```
- 優雅關閉失敗時的降級策略
- 確保資源最終被釋放

### 4. WaitGroup 洩漏檢測
```go
done := make(chan struct{})
go func() {
    a.wg.Wait()
    close(done)
}()

select {
case <-done:
    logger.MainLog.Infof("ANLF terminated successfully")
case <-time.After(15 * time.Second):
    logger.MainLog.Warnf("WaitGroup timeout - some goroutines may still be running")
}
```
- 檢測潛在的 goroutine 洩漏
- 不會無限阻塞程式退出

## 測試場景

### 1. 正常關閉
```bash
./bin/anlf -c config/anlfcfg.yaml
# Press Ctrl+C
```
**預期日誌:**
```
[ANLF][Main] Shutdown signal received, reason: context canceled
[ANLF][Main] Terminating ANLF...
[ANLF][SBI] Stopping SBI server (listen on 127.0.0.165:8000)
[ANLF][SBI] Deregister from NRF successfully
[ANLF][SBI] SBI server stopped gracefully
[ANLF][Main] Graceful shutdown completed successfully
[ANLF][Main] ANLF terminated successfully
```

### 2. 超時關閉（模擬阻塞）
如果組件在 10 秒內未關閉：
```
[ANLF][Main] Shutdown timeout after 10s, forcing termination
```

### 3. HTTP 請求處理中關閉
- 現有請求會在 5 秒內完成
- 新請求被拒絕
- 超時後強制關閉

## 擴展指南

### 為 Phase 2-4 添加新組件

#### 1. eBPF Manager 示例
```go
// internal/ebpf/manager.go
type Manager struct {
    objs *bpfObjects
    link netlink.Link
}

func (m *Manager) Name() string {
    return "eBPF Manager"
}

func (m *Manager) Start(ctx context.Context) error {
    logger.EbpfLog.Info("Loading eBPF programs...")
    // 載入 eBPF 程式
    // 附加到網卡
    return nil
}

func (m *Manager) Stop(timeout time.Duration) error {
    logger.EbpfLog.Info("Detaching eBPF programs...")
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    // 卸載 eBPF 程式
    if m.link != nil {
        m.link.Close()
    }
    if m.objs != nil {
        m.objs.Close()
    }
    
    logger.EbpfLog.Info("eBPF Manager stopped")
    return nil
}
```

#### 2. Data Recorder 示例 (Phase 4)
```go
// internal/recorder/recorder.go
type Recorder struct {
    file   *os.File
    writer *csv.Writer
    mu     sync.Mutex
}

func (r *Recorder) Name() string {
    return "Data Recorder"
}

func (r *Recorder) Start(ctx context.Context) error {
    logger.RecorderLog.Info("Starting data recorder...")
    // 開啟 CSV 檔案
    return nil
}

func (r *Recorder) Stop(timeout time.Duration) error {
    logger.RecorderLog.Info("Flushing and closing recorder...")
    r.mu.Lock()
    defer r.mu.Unlock()
    
    // Flush buffer
    if r.writer != nil {
        r.writer.Flush()
    }
    // 關閉檔案
    if r.file != nil {
        r.file.Close()
    }
    
    logger.RecorderLog.Info("Recorder stopped")
    return nil
}
```

#### 3. 在 service/init.go 中註冊
```go
func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*AnlfApp, error) {
    // ... 現有代碼 ...
    
    // Phase 2: 註冊 eBPF Manager
    if cfg.GetEbpfEnabled() {
        ebpfMgr, err := ebpf.NewManager(cfg)
        if err != nil {
            return nf, err
        }
        nf.lifecycleManager.Register(ebpfMgr)
    }
    
    // Phase 4: 註冊 Recorder
    if cfg.GetRecordingStatus() {
        recorder, err := recorder.NewRecorder(cfg.GetRecordingOutput())
        if err != nil {
            return nf, err
        }
        nf.lifecycleManager.Register(recorder)
    }
    
    return nf, nil
}
```

## 配置選項

```yaml
# config/anlfcfg.yaml
configuration:
  # ... 其他配置 ...
  
  # Graceful shutdown timeout (optional)
  shutdownTimeout: 15s  # 預設 10s
```

## 最佳實踐

1. **組件啟動失敗處理**
   - Start() 返回錯誤時自動回滾
   - 已啟動的組件會被正確關閉

2. **避免在 Stop() 中 panic**
   - 使用 recover() 保護
   - 記錄錯誤但繼續關閉流程

3. **超時設定建議**
   - 快速操作：1-3 秒
   - 網路操作：5-10 秒
   - 持久化操作：10-30 秒

4. **日誌規範**
   - 開始關閉：Info 級別
   - 正常完成：Info 級別
   - 超時警告：Warn 級別
   - 關閉錯誤：Error 級別

## 故障排查

### 問題：程式無法退出
**檢查:**
1. 是否有 goroutine 沒有監聽 context.Done()
2. 是否有阻塞的 channel 操作
3. 檢查 WaitGroup 計數是否正確

**解決:**
```go
// ✅ 正確：監聽 context
select {
case <-ctx.Done():
    return
case data := <-ch:
    // 處理
}

// ❌ 錯誤：無法中斷
for data := range ch {
    // 處理
}
```

### 問題：NRF Deregistration 失敗
**檢查:**
1. 網路連線狀態
2. NRF 服務是否可用
3. 超時設定是否足夠

**解決:**
- 增加重試邏輯
- 記錄失敗但不阻塞關閉

## 效能考量

- **關閉時間**: 通常 < 2 秒（無阻塞情況）
- **記憶體**: Lifecycle Manager overhead < 1KB
- **CPU**: 關閉過程 CPU 使用率微乎其微

## 總結

AnLF 的 graceful shutdown 機制提供了：
- ✅ 清晰的組件生命週期管理
- ✅ 多層超時保護機制
- ✅ 易於擴展的接口設計
- ✅ 完善的錯誤處理
- ✅ 詳細的日誌追蹤

這套機制為 Phase 2-4 的 eBPF、數據錄製等功能提供了可靠的基礎設施。
