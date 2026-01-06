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
	ulLogPPS := 0.0
	if ulPktCnt > 0 {
		ulLogPPS = math.Log10(ulPktCnt)
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
	dlLogPPS := 0.0
	dlAvgLen := 0.0
	ppsRatio := 0.0
	byteRatio := 0.0
	ackRatio := 0.0

	if dlPktCnt > 0 {
		// DL PPS (log scale)
		dlLogPPS = math.Log10(dlPktCnt)

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
		// Uplink features (rounded to 2 decimal places for LLM input consistency)
		UlLogPPS:    math.Round(ulLogPPS*100) / 100,
		AvgLen:      math.Round(avgLen*100) / 100,
		IcmpRatio:   math.Round(icmpRatio*100) / 100,
		TcpRatio:    math.Round(tcpRatio*100) / 100,
		UdpRatio:    math.Round(udpRatio*100) / 100,
		SynRatio:    math.Round(synRatio*100) / 100,
		RstRatio:    math.Round(rstRatio*100) / 100,
		NewFlowRate: math.Round(flowRate*100) / 100,
		FanOut:      math.Round(fanOut*100) / 100,
		// Downlink features (rounded to 2 decimal places for LLM input consistency)
		DlLogPPS:  math.Round(dlLogPPS*100) / 100,
		DlAvgLen:  math.Round(dlAvgLen*100) / 100,
		PPSRatio:  math.Round(ppsRatio*100) / 100,
		ByteRatio: math.Round(byteRatio*100) / 100,
		AckRatio:  math.Round(ackRatio*100) / 100,
	}
}
