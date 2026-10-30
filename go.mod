module qtbench

go 1.26.9

replace github.com/hphuc15/mqttOQ => ./lib/mqttOQ

require github.com/hphuc15/mqttOQ v0.0.0-00010101000000-000000000000

require (
	github.com/quic-go/quic-go v0.64.1 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
