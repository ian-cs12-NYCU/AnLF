package ebpf

import (
	"testing"
)

func TestConvertToFeatures_ZeroPackets(t *testing.T) {
	m := &anlfUeMetricsT{}
	fv := ConvertToFeatures(m, 1.0)
	if fv.LogPPS != 0 || fv.AvgLen != 0 || fv.NewFlowRate != 0 || fv.FanOut != 0 {
		t.Fatalf("expected zero vector when PacketCount==0, got %+v", fv)
	}
	// Check downlink features are also zero
	if fv.DlPPS != 0 || fv.DlAvgLen != 0 || fv.PPSRatio != 0 || fv.ByteRatio != 0 || fv.AckRatio != 0 {
		t.Fatalf("expected zero downlink features when PacketCount==0, got %+v", fv)
	}
}

func TestConvertToFeatures_Normal(t *testing.T) {
	m := &anlfUeMetricsT{
		PacketCount:  100,
		ByteCount:    5000, // avg 50
		TcpCount:     80,
		UdpCount:     15,
		IcmpCount:    5,
		SynCount:     20,
		RstCount:     2,
		NewFlowCount: 50,
		DstBitmap:    0b00001111, // 4 ones -> fanout = 4/64
	}

	fv := ConvertToFeatures(m, 1.0)

	if fv.LogPPS <= 0 {
		t.Fatalf("expected LogPPS > 0, got %v", fv.LogPPS)
	}

	if fv.AvgLen < 49.9 || fv.AvgLen > 50.1 {
		t.Fatalf("avgLen expected ~50, got %v", fv.AvgLen)
	}

	if fv.TcpRatio < 0.79 || fv.TcpRatio > 0.81 {
		t.Fatalf("tcpRatio expected ~0.8, got %v", fv.TcpRatio)
	}

	if fv.NewFlowRate < 0.49 || fv.NewFlowRate > 0.51 {
		t.Fatalf("newFlowRate expected ~0.5, got %v", fv.NewFlowRate)
	}

	expectedFanOut := float64(4) / 64.0
	if fv.FanOut < expectedFanOut-0.0002 || fv.FanOut > expectedFanOut+0.0002 {
		t.Fatalf("fanOut expected %v, got %v", expectedFanOut, fv.FanOut)
	}
}

func TestConvertToFeatures_FlowRateCap(t *testing.T) {
	m := &anlfUeMetricsT{
		PacketCount:  10,
		NewFlowCount: 20, // ratio 2.0 -> should be capped to 1.0
	}
	fv := ConvertToFeatures(m, 1.0)
	if fv.NewFlowRate != 1.0 {
		t.Fatalf("newFlowRate expected capped 1.0, got %v", fv.NewFlowRate)
	}
}

func TestConvertToFeatures_DownlinkMetrics(t *testing.T) {
	m := &anlfUeMetricsT{
		// Uplink metrics
		PacketCount:  1000,
		ByteCount:    50000,
		TcpCount:     800,
		NewFlowCount: 100,
		DstBitmap:    0xFF, // 8 ones

		// Downlink metrics
		DlPacketCount: 2000,
		DlByteCount:   150000,
		DlTcpCount:    1500,
		DlAckCount:    1200,
	}

	fv := ConvertToFeatures(m, 1.0)

	// Check uplink features
	if fv.LogPPS <= 0 {
		t.Fatalf("expected LogPPS > 0, got %v", fv.LogPPS)
	}

	// Check downlink features
	if fv.DlPPS != 2000 {
		t.Fatalf("expected DlPPS=2000, got %v", fv.DlPPS)
	}

	expectedDlAvgLen := 150000.0 / 2000.0
	if fv.DlAvgLen < expectedDlAvgLen-0.1 || fv.DlAvgLen > expectedDlAvgLen+0.1 {
		t.Fatalf("expected DlAvgLen=%.1f, got %v", expectedDlAvgLen, fv.DlAvgLen)
	}

	expectedPPSRatio := 2000.0 / 1000.0
	if fv.PPSRatio < expectedPPSRatio-0.01 || fv.PPSRatio > expectedPPSRatio+0.01 {
		t.Fatalf("expected PPSRatio=%.2f, got %v", expectedPPSRatio, fv.PPSRatio)
	}

	expectedByteRatio := 150000.0 / 50000.0
	if fv.ByteRatio < expectedByteRatio-0.01 || fv.ByteRatio > expectedByteRatio+0.01 {
		t.Fatalf("expected ByteRatio=%.2f, got %v", expectedByteRatio, fv.ByteRatio)
	}

	expectedAckRatio := 1200.0 / 1500.0
	if fv.AckRatio < expectedAckRatio-0.01 || fv.AckRatio > expectedAckRatio+0.01 {
		t.Fatalf("expected AckRatio=%.2f, got %v", expectedAckRatio, fv.AckRatio)
	}
}

func TestConvertToFeatures_DownlinkAsymmetric(t *testing.T) {
	// Test asymmetric traffic pattern (attack scenario)
	m := &anlfUeMetricsT{
		PacketCount:   10000, // High uplink
		ByteCount:     500000,
		DlPacketCount: 50,   // Very low downlink (asymmetric)
		DlByteCount:   3000, // Small responses
		DlTcpCount:    40,
		DlAckCount:    5, // Few ACKs (attack sign)
	}

	fv := ConvertToFeatures(m, 1.0)

	// Should have very low ratios indicating attack
	if fv.PPSRatio > 0.1 {
		t.Fatalf("expected low PPSRatio for attack, got %v", fv.PPSRatio)
	}

	if fv.ByteRatio > 0.1 {
		t.Fatalf("expected low ByteRatio for attack, got %v", fv.ByteRatio)
	}

	if fv.AckRatio > 0.2 {
		t.Fatalf("expected low AckRatio for attack, got %v", fv.AckRatio)
	}
}
