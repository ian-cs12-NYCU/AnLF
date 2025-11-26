package ebpf

import (
	"testing"
)

func TestConvertToFeatures_ZeroPackets(t *testing.T) {
	m := &anlfUeMetricsT{}
	fv := ConvertToFeatures(m, 1.0)
	if fv.LogPPS != 0 || fv.AvgLen != 0 || fv.FlowRate != 0 || fv.FanOut != 0 {
		t.Fatalf("expected zero vector when PacketCount==0, got %+v", fv)
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

	if fv.FlowRate < 0.49 || fv.FlowRate > 0.51 {
		t.Fatalf("flowRate expected ~0.5, got %v", fv.FlowRate)
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
	if fv.FlowRate != 1.0 {
		t.Fatalf("flowRate expected capped 1.0, got %v", fv.FlowRate)
	}
}
