# erpwifi: ERPNext sign-in for the Trident network on core-01

Everyone who connects to **WiFi (vlan81, 192.168.81.0/24)** or **wired LAN
(bridge1, 192.168.80.0/24)** must sign in with their **ERPNext** account
before they get internet or internal access. Guests use **voucher codes**,
which give internet only. Limits come from the person's ERPNext role or
department. The admin dashboard shows who is online and lets you kick or block
users and devices, create and print vouchers, see usage, and read the sign-in
log.

The service runs as a container **on the router** (core-01, RB5009, RouterOS
7.20.5). The subnets, DHCP, APs and VLANs stay as they are.

```
 WiFi 192.168.81.x (vlan81) ┐                          ┌─▶ ERPNext  /api/method/login
 wired 192.168.80.x (bridge1)┴▶ core-01 hotspot ──RADIUS─▶ erpwifi container 172.31.250.2
                                (sign-in page)  ◀─Disconnect (Kick)─┘  dashboard :8080 (WIFI-ADMINS)
 cameras .30, PBX .50, switches/APs .6 ──▶ bypassed by MAC (from the static ARP list)
```

## How it fits the current setup

| Existing setup | What erpwifi does |
|---|---|
| Static-ARP MAC whitelist (`arp=reply-only`, `add-arp` off) | Left in place. A device still needs its static ARP entry **and** a sign-in. For vlan81, `openWifiArp="yes"` makes the sign-in the only gate, which voucher guests with new phones need. bridge1 is never changed. |
| bridge1 also carries .6 / .30 / .50 | Every static-ARP device in those subnets gets a hotspot `ip-binding type=bypassed`, so cameras, phones, switches and APs never see a sign-in page. Admin PCs and printers on .80 go in `bypassMacs`. |
| Mangle + PCQ shaping (Std-Pkt 10 Mbps/IP; Express, Restrict-Conn, Slow-Conn lists) | Stays in charge of speed. Profiles don't send a rate limit. To move a person to another tier, a profile adds their IP to an existing list (`address_list = "Express"`) while they are signed in. The hotspot's per-user dynamic queues are placed at the **bottom** (`insert-queue-before=bottom`), so they don't capture traffic ahead of the Parent tree. |
| `LAN` address list grants internal access | Signed-in staff get the same access as today. Voucher guests are put in `HS-GUEST`, and a forward rule drops `HS-GUEST → LAN`. |
| www (80) disabled, no trusted certificate | The hotspot uses its own login server, which doesn't need `/ip service www`. Sign-in is HTTP with PAP (see Security). |
| SSH to the router hijacked by dst-nat | Nothing needs SSH. You paste scripts in Winbox/Terminal, upload files in Winbox Files, and the router downloads the portal pages itself with `/tool fetch`. |
| Router log is short-lived | The dashboard's sign-in log (SQLite on the router) is the audit trail. |

## When something is down

* **Container down:** nobody new can sign in. People already online stay
  online. The `wifi-breakglass` local hotspot user (set `breakGlassPassword`)
  is checked by the router itself, so it still works. Admin PCs in
  `bypassMacs` never need to sign in. Winbox by MAC works from bridge1
  whatever happens.
* **ERPNext unreachable:** with `offline_grace_hours = 12`, anyone who signed
  in successfully in the last 12 hours with the same password gets back in,
  with their last profile. Blocks still apply. Set it to 0 to refuse everyone
  instead (fail closed).
* **Undo everything:** run `core01-2-hotspot-rollback.rsc`. The network goes
  straight back to how it is today. `core01-1-container-rollback.rsc` then
  removes the container.

## Install

Before anyone signs in, wired PCs, printers and admin machines need to be in
`bypassMacs`. Otherwise those users will see a sign-in page on every new
session.

1. **Preflight.** This changes nothing. Paste `routeros/core01-0-preflight.rsc`
   and keep the output. It lists:
   * the device mode and the container package
   * the fasttrack rules
   * the speed-tier lists
   * how many devices will be bypassed
   * the wired .80 devices you can pick for `bypassMacs`
2. **Image.** The `erpwifi image` GitHub workflow builds arm64 and amd64
   images and pushes them to `ghcr.io/97newest/erpwifi:latest` from `main`.
   Make the package public in GitHub (Packages → erpwifi → settings), or give
   the router registry credentials.
3. **One-time router preparation.** Someone has to be at the router, and it
   causes a short outage, so do it after hours:
   ```
   /system/package/enable container
   /system/device-mode/update container=yes
   ```
   Then press the reset button briefly, or pull the power, within 5 minutes.
4. **Config.** Copy `deploy/config.example.toml` to `config.toml` and fill in:
   * the ERPNext URL and API key
   * a long random RADIUS secret
   * the dashboard password hash
   * your rules

   Upload it in Winbox → Files to `erpwifi/data/config.toml`.
5. **Container.** Paste `routeros/core01-1-container.rsc`. Wait until
   `/container/print` shows it stopped (extracted), then start it with
   `/container/start [find where interface=veth-erpwifi]`. Check it with
   `/tool/fetch url=http://172.31.250.2:8080/healthz output=user`.
6. **Hotspot.** Set the variables in `routeros/core01-2-hotspot.rsc`, then
   paste it. Both hotspot servers are created **disabled**.
7. **Roll out in stages.**
   1. Run `/ip/hotspot/enable hs-erpwifi-wifi` and test with a phone: a staff
      account, a wrong password and a voucher.
   2. Check `/queue/simple/print`: the Parent tree is still first, and the
      hotspot queues are at the bottom.
   3. Check that cameras, phones and the APs still work.
   4. Only then run `/ip/hotspot/enable hs-erpwifi-lan` for wired.
8. **Dashboard.** Open `http://172.31.250.2:8080` from a `WIFI-ADMINS`
   address (192.168.6.0/24 plus the list in the container script).

## Security

* ERPNext needs the real password, so the hotspot uses **PAP over HTTP**
  (`login-by=http-pap`).
  * On WiFi, WPA2 encrypts the radio link.
  * On wired .80, and between WPA2 clients that share the PSK, the password
    crosses the LAN unencrypted to the router.
  * Router → container uses RADIUS password hiding with the shared secret.
    Container → ERPNext uses HTTPS.
  * To encrypt the sign-in page as well, add `https` to `login-by` with a
    certificate for `wifi.trident.local` that the clients trust (install the
    router CA on company devices), or with a public name.
* No API or write user is created on the router. Kick and block use RADIUS
  Disconnect, which is accepted only from the container.
* Nothing here touches Winbox exposure, the plaintext API on 8728, or
  password policy (the open router findings).

## Development

```sh
pip install -e '.[test]'
pytest
```

The tests start the real RADIUS server and talk to it the way RouterOS does:
PAP with Message-Authenticator, accounting Start/Interim/Stop/Accounting-On,
and session-ID reuse after a reboot. They use a fake ERPNext
(`tests/fake_erpnext.py`) and a fake router (`tests/fake_router.py`) that
answers Disconnect-Requests.
