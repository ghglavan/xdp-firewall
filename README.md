# xdp-firewall

## Requrements: 
`llvm` `clang` `libnetfilter-queue`

on arch linux do:
```bash
sudo pacman -S llvm clang libnetfilter_queue
```

## Tasks

For now we have sample programs for nfq, xdp and af_xdp.

PRIORITIZED TASKS:
- [x] add samples for netfilter-queue, xdp and af_xdp
- [ ] add samples for dpdk and dpdk + xdp
- [ ] create a common interface for all source_* programs
- [ ] use the interface to create a stateful firewall
- [ ] create a test environment
- [ ] write performance tests for common usecases (accept, drop, (forward))
- [ ] create a interface to set rules for the firewall (like iptables)


NON PRIORITIZED TASKS:
- [ ] use cmake instead of make
- [ ] build source_* as a separate library and create rust crates
- [ ] rewrite everything in rust