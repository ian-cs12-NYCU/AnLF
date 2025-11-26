package monitor

import (
	"time"

	"github.com/free5gc/anlf/pkg/ebpf"
	"github.com/free5gc/anlf/pkg/models"
)

// ConvertToTrafficRecord converts eBPF metrics to UeTrafficRecord
// This combines feature extraction (from ebpf package) with metadata enrichment
func ConvertToTrafficRecord(
	ueIp string,
	supi string,
	metrics *ebpf.UeMetrics,
	windowDuration float64,
) *models.UeTrafficRecord {
	// UeMetrics is a type alias for anlfUeMetricsT, so we can pass it directly
	features := ebpf.ConvertToFeatures(metrics, windowDuration)

	return &models.UeTrafficRecord{
		UeFeatureVector: features,
		Timestamp:       time.Now().Unix(),
		Supi:            supi,
		UeIp:            ueIp,
	}
}
