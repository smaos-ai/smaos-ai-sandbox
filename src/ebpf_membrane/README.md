# SMAOS eBPF Kernel Membrane

This directory contains a tiny eBPF (XDP) enforcement demo. 

## How it works
The `xdp_admissibility_drop.c` program attaches to the network interface at the driver level (before the OS network stack). It inspects incoming TCP packets. If the destination port is registered in the `admissibility_map` with a `DENY` flag (e.g., because the SMAOS agent's Trust Passport TTL expired), the packet is instantly dropped (`XDP_DROP`).

## Why this is a Moat
User-space proxies can be bypassed if an agent escapes its container or finds an alternative routing path. By dropping packets directly in the kernel using eBPF, SMAOS physically enforces admissibility at the physics layer. No unverified packets can breach the loopback membrane.
