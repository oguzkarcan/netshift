# netshift

Cut a device's **internet** while leaving its **Wi-Fi** connected — from the terminal.

```
╭ netshift ───────────────────────────────────────────────────────────────────────────────── block ╮
│ wlan0  192.168.1.20/255.255.255.0   gw 192.168.1.1                                     8 devices │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│      #  HOST                IP                                                                   │
│▌[ ]  1  router.lan          192.168.1.1                                                ● gateway │
│ [ ]  2  macbook             192.168.1.20                                          ● this machine │
│ [ ]  3  iphone-ozzy         192.168.1.31                                                    ● up │
│ [ ]  4  ipad                192.168.1.34                                                    ● up │
│ [ ]  5  tv-salon            192.168.1.42                                             ● CUT 01:23 │
│ [ ]  6  yazici              192.168.1.55                                                    ● up │
│ [ ]  7  priz-01             192.168.1.61                                                    ● up │
│ [ ]  8  kamera-giris        192.168.1.77                                                    ● up │
│                                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
  space select · b cut · r restore · s rescan · m mode · ? help · q quit
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

No deauth, no router login, no app on the target device. The device keeps its Wi-Fi
association and simply cannot reach the internet.

> **Authorized use only.** This tool is written for networks you own or are explicitly
> allowed to administer, and for devices you control. Running it on someone else's
> network against devices whose owners have not agreed is unauthorised network
> interference — a form of denial of service, and a crime in many jurisdictions.
> In class, target your own phone, not the person next to you.

## How it works

Before a device can reach the internet it asks, over ARP, "which MAC address belongs to
the gateway?". `netshift` answers that question on the gateway's behalf with a MAC
address that does not exist on the LAN (`02:00:00:00:00:01`). The device's frames die at
layer 2:

```
   phone  ──"gateway is 02:00:...:01"──►  (nobody answers)   ✗ internet
      │
      └── Wi-Fi association: untouched, full signal, same IP
```

That is why the Wi-Fi icon stays full and the device ends up "connected, no internet" —
exactly the behaviour you want. In `block` mode traffic does **not** pass through your
machine, so you never take a man-in-the-middle position and `ip_forward` stays off.

`mitm` mode is the second act of the demo: it poisons both directions, enables
`ip_forward` and actually relays the traffic through this machine, so you can show *why*
ARP spoofing is dangerous while packets keep flowing.

## Install

Linux (Arch/Omarchy):

```bash
sudo pacman -S python-scapy          # or let run.sh build a venv
```

macOS:

```bash
brew install python3
```

Then, from the repository:

```bash
./run.sh              # first run creates .venv and installs scapy
sudo ./run.sh scan
```

Or install it permanently:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
sudo .venv/bin/netshift scan
```

`scapy` needs raw sockets, so the tool must run as root. `run.sh` re-executes itself with
`sudo` for you; it will not run privileged commands without your password.

## Quick start

```bash
sudo ./run.sh                      # the interface (no arguments launches the TUI)
sudo ./run.sh scan                 # plain list: IP, MAC, vendor, hostname
sudo ./run.sh block 192.168.1.42 --duration 5m
sudo ./run.sh mitm 192.168.1.42    # traffic relayed through this machine (demo)
sudo ./run.sh heal                 # repair ARP entries after a crash
```

The interface is entirely keyboard driven — no commands to type:

| Key | Action |
| --- | --- |
| `↑`/`↓` or `k`/`j` | move between devices |
| `space` | select / deselect |
| `b` | cut internet for the selected devices (confirmation dialog) |
| `r` | restore every cut device |
| `s` | rescan (also every 20 s in the background) |
| `m` | switch mode: `block` ↔ `mitm` |
| `enter` | device details |
| `?` | help screen |
| `q` | quit (restores everything on the way out) |

Scans run in a background thread, so the cursor never freezes; the table appears as soon
as the ARP sweep finishes and hostnames fill in a moment later. On terminals 110+ columns
wide a details panel for the focused device appears on the right; below 80 columns the
table drops columns and stays readable down to roughly 60×18.

Vendor names come from a one-off download:

```bash
sudo ./run.sh oui-update           # IEEE OUI registry → ~/.cache/netshift/oui.csv
```

### Hostnames are best-effort

There is no single place on a LAN that knows what every device is called, so `netshift`
asks several sources and keeps the first answer:

| Source | Catches |
| --- | --- |
| system resolver (PTR) | router DNS, `/etc/hosts`, mDNS on macOS |
| direct mDNS PTR query | Apple gear, avahi/Bonjour hosts, modern Android |
| `avahi-resolve` | devices that only answer unicast mDNS (used when avahi runs) |
| NBNS node status | Windows and Samba machines |
| SSDP/UPnP `friendlyName` | TVs, printers, NAS boxes |

The union is what makes names appear: on a typical home LAN the router publishes no PTR
records at all, and the devices themselves are the only ones who know their names.

Resolved names are cached per MAC in `~/.cache/netshift/hosts.json`, so they survive DHCP
address changes and show up instantly on later scans. A device that answers none of the
sources stays unnamed — the table then falls back to the vendor name. `scan --no-names`
skips resolution entirely when you only want IPs and MACs.

## Commands

```
netshift                            # the interface (same as `tui`)
netshift tui    [--mode block|mitm] # interface, with an explicit mode
netshift scan   [--iface X] [--gateway IP] [--no-names]
netshift block  <IP...> [--mac MAC...] [--duration 15m] [--yes]
netshift mitm   <IP...> [--mac MAC...] [--duration 15m]
netshift heal
netshift oui-update
```

When `--duration` elapses the ARP entries are restored automatically. `Ctrl+C`, `SIGTERM`
and a normal quit all perform the same cleanup; after a `kill -9`, run `netshift heal`.

## A five-minute classroom demo

1. `sudo ./run.sh` — let the device list fill in.
2. Select your own phone (`space`), then press `b` and confirm.
3. On the phone: the Wi-Fi icon is **still full**, but pages do not load. Toggle airplane
   mode and back — Wi-Fi reconnects, the internet still does not. That contrast is the point.
4. Show that nothing was installed on the phone and no firewall rule exists anywhere:
   the attack lives entirely at layer 2, on ARP's assumption that nobody lies.
5. Press `r`; the phone is back online within seconds.
6. Second act: `sudo ./run.sh mitm <device>` plus
   `sudo tcpdump -i <iface> -n host <device>` to show plain HTTP/DNS being readable
   (HTTPS payload stays encrypted, but destinations and DNS do not).
7. Close on the fix: ARP has no authentication, so the defence is **Dynamic ARP
   Inspection**, static ARP entries, 802.1X and segmented VLANs — not HTTPS.

## Limits (the honest list)

- **IPv6**: the tool works on IPv4 ARP. If the network hands out IPv6, the device may keep
  reaching the internet over it; `block` will look broken. Disable IPv6 for the demo or
  handle router advertisements separately.
- **Client isolation** (typical on café and corporate guest Wi-Fi) hides devices from each
  other at layer 2; the tool will not work there — and it should not.
- Devices with a **static ARP entry** ignore the poisoning.
- If the device sleeps, leaves the network or randomises its MAC, rescan.
- Managed switches with **Dynamic ARP Inspection** drop the forged replies.
- `block` mode cuts **new** connections; an existing TCP session may keep sending for a
  few seconds until the ARP cache is refreshed.

## Why not just use the router?

If you administer the network, the router is the right place: one `nft` or MAC rule,
it keeps working while your laptop is off, and it is auditable. `netshift` deliberately
does not touch the router — its purpose is to demonstrate **the protocol itself**, which
is the shortest way to explain why ARP needs verification.

## License

MIT.
