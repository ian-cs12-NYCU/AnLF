## eBPF Map Value 結構說明
上行 Uplink
```
// 定義在 eBPF C 程式中的 Map Value 結構
struct ue_metrics_t {
    // --- 1. 流量規模 (Volume Metrics) ---
    // 用途：計算 PPS (Packets Per Second) 和 BPS (Bytes Per Second)
    // 物理意義：最基礎的 DDoS 指標，量大通常有問題。
    u64 packet_count;  
    u64 byte_count;    

    // --- 2. 協議分佈 (Protocol Distribution) ---
    // 用途：計算 TCP/UDP/ICMP 的比例
    // 物理意義：
    // - Carpet Bombing 常見是用 UDP (效率高)。
    // - 一般網頁瀏覽是 TCP 為主。
    // - ICMP 突然變多可能是 Ping Flood。
    u64 tcp_count;     
    u64 udp_count;     
    u64 icmp_count;    // [擴充] 多蒐集這個，成本極低，但能排除 Ping Flood 誤判

    // --- 3. TCP 旗標細節 (TCP Flags) ---
    // 用途：計算 SYN Rate, RST Rate
    // 物理意義：
    // - SYN 高但 ACK 低：典型 SYN Flood。
    // - RST 高：代表目標端口沒開 (Port Closed)，這是掃描行為 (Scanning) 的強特徵。
    u64 syn_count;     // [擴充] 紀錄 TCP SYN 封包
    u64 rst_count;     // [擴充] 紀錄 TCP RST 封包

    // --- 4. 行為意圖 (Behavioral Intent) ---
    // 用途：計算 New Flow Rate
    // 物理意義：
    // - 只有上行 (Uplink) 需要算。
    // - 狂發新連線 = 惡意行為/感染徵兆。
    // - 邏輯：TCP看SYN, UDP看第一包(或全部算，視MVP實作而定)。
    u64 new_flow_count; 

    // --- 5. 目標多樣性 (Target Diversity / Fan-Out) ---
    // 用途：計算 Fan-Out Rate (Dst Dispersion)
    // 物理意義：偵測 Carpet Bombing 的核心數值。
    // 邏輯：利用 IP 最後 8 bits 做 Bitmap 映射。
    // 0 = 沒打, 1 = 有打。最後算有幾個 bit 是 1。
    u64 dst_bitmap;    
};

```

## 環境確認
```
# 1. 檢查 Clang/LLVM (建議 12 以上，支援 BTF)
clang --version

# 2. 檢查 Go 版本
go version

# 3. 檢查 bpftool (這是最重要的與 Kernel 溝通的工具)
bpftool --version

# 4. 檢查 kernel headers (必須與 uname -r 一致)
ls -d /usr/src/linux-headers-$(uname -r)
```

目前佈署主機狀態
```
vagrant@free5GC:~/AnLF$ clang --version
Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
vagrant@free5GC:~/AnLF$ go version
go version go1.24.5 linux/amd64
vagrant@free5GC:~/AnLF$ bpftool --version
/usr/lib/linux-tools/5.15.0-91-generic/bpftool v5.15.131
features:
vagrant@free5GC:~/AnLF$ ls -d /usr/src/linux-headers-$(uname -r)
/usr/src/linux-headers-5.15.0-91-generic
```

檢查 Kernel 支援的 eBPF 操作 (bpftool feature probe)

確認重點：是否有 Hash? 是否有 PerCPU Hash? (這決定我們要用哪種 Map)
```
$ sudo bpftool feature probe | grep "map_type"
eBPF map_type hash is available
eBPF map_type array is available
eBPF map_type prog_array is available
eBPF map_type perf_event_array is available
eBPF map_type percpu_hash is available
eBPF map_type percpu_array is available
eBPF map_type stack_trace is available
eBPF map_type cgroup_array is available
eBPF map_type lru_hash is available
eBPF map_type lru_percpu_hash is available
eBPF map_type lpm_trie is available
eBPF map_type array_of_maps is available
eBPF map_type hash_of_maps is available
eBPF map_type devmap is available
eBPF map_type sockmap is available
eBPF map_type cpumap is available
eBPF map_type xskmap is available
eBPF map_type sockhash is available
eBPF map_type cgroup_storage is available
eBPF map_type reuseport_sockarray is available
eBPF map_type percpu_cgroup_storage is available
eBPF map_type queue is available
eBPF map_type stack is available
eBPF map_type sk_storage is available
eBPF map_type devmap_hash is available
eBPF map_type struct_ops is NOT available
eBPF map_type ringbuf is available
eBPF map_type inode_storage is available
eBPF map_type task_storage is available
```

確認重點：尋找與封包讀取相關的 helper，如 bpf_xdp_load_bytes (如果不支援，就要用指標直接讀)。
```
$ sudo bpftool feature probe | grep "helper"
Scanning eBPF helper functions...
eBPF helpers supported for program type socket_filter:
eBPF helpers supported for program type kprobe:
eBPF helpers supported for program type sched_cls:
eBPF helpers supported for program type sched_act:
eBPF helpers supported for program type tracepoint:
eBPF helpers supported for program type xdp:
eBPF helpers supported for program type perf_event:
eBPF helpers supported for program type cgroup_skb:
eBPF helpers supported for program type cgroup_sock:
eBPF helpers supported for program type lwt_in:
eBPF helpers supported for program type lwt_out:
eBPF helpers supported for program type lwt_xmit:
eBPF helpers supported for program type sock_ops:
eBPF helpers supported for program type sk_skb:
eBPF helpers supported for program type cgroup_device:
eBPF helpers supported for program type sk_msg:
eBPF helpers supported for program type raw_tracepoint:
eBPF helpers supported for program type cgroup_sock_addr:
eBPF helpers supported for program type lwt_seg6local:
eBPF helpers supported for program type lirc_mode2:
eBPF helpers supported for program type sk_reuseport:
eBPF helpers supported for program type flow_dissector:
eBPF helpers supported for program type cgroup_sysctl:
eBPF helpers supported for program type raw_tracepoint_writable:
eBPF helpers supported for program type cgroup_sockopt:
eBPF helpers supported for program type tracing:
eBPF helpers supported for program type struct_ops:
eBPF helpers supported for program type ext:
eBPF helpers supported for program type lsm:
eBPF helpers supported for program type sk_lookup:
```

是否支援 BTF (這對 cilium/ebpf 至關重要)
如果檔案存在，恭喜你，你可以享受 CO-RE 的便利。如果不存在，你需要在 bpf2go 時關閉 BTF 選項，並依賴 header files。
```
$ ls -l /sys/kernel/btf/vmlinux
-r--r--r-- 1 root root 5190640 Nov 26 02:56 /sys/kernel/btf/vmlinux
```