module golang.zx2c4.com/wireguard

go 1.20

require (
	golang.org/x/crypto v0.11.0
	golang.org/x/net v0.12.0
	golang.org/x/sys v0.10.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20221203005347-703fd9b7fbc0
)

require (
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
)

require (
	github.com/cloudflare/circl v1.3.3
	github.com/google/btree v1.1.2 // indirect
	github.com/lukechampine/fastxor v0.0.0-20210322201628-b664bed5a5cc
	golang.org/x/time v0.3.0 // indirect
)

replace github.com/cloudflare/circl => ../circl/
