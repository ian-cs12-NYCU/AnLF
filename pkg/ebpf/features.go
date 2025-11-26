package ebpf

import (
	"math"
	"math/bits"

	"github.com/free5gc/anlf/pkg/models"
)

// ConvertToFeatures converts anlfUeMetricsT (from eBPF map) to UeFeatureVector.
// The conversion follows the rules documented in `anlf/docs/LLM.md`.
func ConvertToFeatures(m *anlfUeMetricsT, windowDuration float64) models.UeFeatureVector {
	if m == nil {
		return models.UeFeatureVector{}
	}

	pktCnt := float64(m.PacketCount)
	if pktCnt == 0 {
		// Per guidance, all-zero vector when no packets
		return models.UeFeatureVector{}
	}

	// LogPPS: log10(packet_count)
	logPPS := math.Log10(pktCnt)

	// AvgLen: bytes / packets
	avgLen := 0.0
	if m.ByteCount > 0 {
		avgLen = float64(m.ByteCount) / pktCnt
	}

	icmpRatio := float64(m.IcmpCount) / pktCnt
	tcpRatio := float64(m.TcpCount) / pktCnt
	udpRatio := float64(m.UdpCount) / pktCnt
	synRatio := float64(m.SynCount) / pktCnt
	rstRatio := float64(m.RstCount) / pktCnt

	flowRate := float64(m.NewFlowCount) / pktCnt
	if flowRate > 1.0 {
		flowRate = 1.0
	}

	fanOut := float64(bits.OnesCount64(m.DstBitmap)) / 64.0

	// pktDensity not included here; if caller wants PPS they can derive from LogPPS or provide windowDuration
	_ = windowDuration // kept to show caller can pass windowDuration in future extensions

	return models.UeFeatureVector{
		LogPPS:    math.Round(logPPS*10000) / 10000,
		AvgLen:    math.Round(avgLen*10000) / 10000,
		IcmpRatio: math.Round(icmpRatio*10000) / 10000,
		TcpRatio:  math.Round(tcpRatio*10000) / 10000,
		UdpRatio:  math.Round(udpRatio*10000) / 10000,
		SynRatio:  math.Round(synRatio*10000) / 10000,
		RstRatio:  math.Round(rstRatio*10000) / 10000,
		FlowRate:  math.Round(flowRate*10000) / 10000,
		FanOut:    math.Round(fanOut*10000) / 10000,
	}
}
