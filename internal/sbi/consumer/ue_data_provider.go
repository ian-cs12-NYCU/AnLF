package consumer

// UeDataProvider is an interface for providing UE IP to SUPI mapping
type UeDataProvider interface {
	GetSupi(ueIp string) string
	GetUeCount() int
	GetAllUeIps() []string
}
