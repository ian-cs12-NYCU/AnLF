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

	// Uplink metrics
	ulPktCnt := float64(m.PacketCount)
	dlPktCnt := float64(m.DlPacketCount)

	if ulPktCnt == 0 && dlPktCnt == 0 {
		// Per guidance, all-zero vector when no packets
		return models.UeFeatureVector{}
	}

	// LogPPS: log10(packet_count)
	logPPS := 0.0
	if ulPktCnt > 0 {
		logPPS = math.Log10(ulPktCnt)
	}

	// AvgLen: bytes / packets
	avgLen := 0.0
	if m.ByteCount > 0 && ulPktCnt > 0 {
		avgLen = float64(m.ByteCount) / ulPktCnt
	}

	icmpRatio := 0.0
	tcpRatio := 0.0
	udpRatio := 0.0
	synRatio := 0.0
	rstRatio := 0.0
	flowRate := 0.0

	if ulPktCnt > 0 {
		icmpRatio = float64(m.IcmpCount) / ulPktCnt
		tcpRatio = float64(m.TcpCount) / ulPktCnt
		udpRatio = float64(m.UdpCount) / ulPktCnt
		synRatio = float64(m.SynCount) / ulPktCnt
		rstRatio = float64(m.RstCount) / ulPktCnt

		flowRate = float64(m.NewFlowCount) / ulPktCnt
		if flowRate > 1.0 {
			flowRate = 1.0
		}
	}

	fanOut := float64(bits.OnesCount64(m.DstBitmap)) / 64.0

	// Downlink metrics
	dlPPS := 0.0
	dlAvgLen := 0.0
	ppsRatio := 0.0
	byteRatio := 0.0
	ackRatio := 0.0

	if dlPktCnt > 0 {
		// DL PPS (not log scale, just the count)
		dlPPS = dlPktCnt

		// DL Average packet length
		if m.DlByteCount > 0 {
			dlAvgLen = float64(m.DlByteCount) / dlPktCnt
		}

		// PPS Ratio: DL/UL
		if ulPktCnt > 0 {
			ppsRatio = dlPktCnt / ulPktCnt
		}

		// Byte Ratio: DL/UL
		if m.ByteCount > 0 {
			byteRatio = float64(m.DlByteCount) / float64(m.ByteCount)
		}

		// ACK Ratio: ACK packets / DL TCP packets
		if m.DlTcpCount > 0 {
			ackRatio = float64(m.DlAckCount) / float64(m.DlTcpCount)
		}
	}

	return models.UeFeatureVector{
		// Uplink features
		LogPPS:      math.Round(logPPS*10000) / 10000,
		AvgLen:      math.Round(avgLen*10000) / 10000,
		IcmpRatio:   math.Round(icmpRatio*10000) / 10000,
		TcpRatio:    math.Round(tcpRatio*10000) / 10000,
		UdpRatio:    math.Round(udpRatio*10000) / 10000,
		SynRatio:    math.Round(synRatio*10000) / 10000,
		RstRatio:    math.Round(rstRatio*10000) / 10000,
		NewFlowRate: math.Round(flowRate*10000) / 10000,
		FanOut:      math.Round(fanOut*10000) / 10000,
		// Downlink features
		DlPPS:     math.Round(dlPPS*10000) / 10000,
		DlAvgLen:  math.Round(dlAvgLen*10000) / 10000,
		PPSRatio:  math.Round(ppsRatio*10000) / 10000,
		ByteRatio: math.Round(byteRatio*10000) / 10000,
		AckRatio:  math.Round(ackRatio*10000) / 10000,
	}
}
