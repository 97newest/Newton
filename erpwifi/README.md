# erpwifi: WiFi sign-in with ERPNext accounts on a MikroTik hotspot

Staff connect to the WiFi, get the router's captive portal, and sign in with
their **ERPNext** username/email and password. Guests use a **voucher code**.
Each person gets speed, time, data and device limits based on their ERPNext
role or department. An **admin dashboard** shows who is online and lets you
kick or block users and devices, create and print vouchers, see usage and read
the sign-in log.

Built for a MikroTik RB5009 on RouterOS 7.20, where it runs as a container on
the router itself. It also runs on any Linux box or VM next to the router.

```
 phone ──WiFi──▶ RB5009 hotspot (captive portal: hotspot/login.html)
                    │  RADIUS auth + accounting (UDP 1812/1813)
                    ▼
               erpwifi container 172.31.250.2 ──HTTPS──▶ ERPNext /api/method/login
                    │  Disconnect-Request (UDP 3799) for "Kick"      + User/Employee lookup
                    └─ dashboard :8080 (admin LAN only), SQLite in /data
```

## How it works

* **Sign-in.** The hotspot sends the username and password to erpwifi over
  RADIUS (PAP). erpwifi checks them with ERPNext's normal login endpoint, then
  logs that ERPNext session out again. With an API key it also reads the
  user's roles and their Employee record's department and status. Disabled
  users and employees whose status is not *Active* are refused.
* **Limits.** `[[rules]]` map a role, department or specific user to a
  `[profiles.*]` entry. The first match wins, and everyone else gets
  `policy.default_profile`. A profile sets:
  * `rate_limit` (sent to the router as `Mikrotik-Rate-Limit`)
  * `session_timeout` and `idle_timeout`
  * `daily_data_mb`: the remaining allowance is sent as `Mikrotik-Total-Limit`
  * `daily_time_min`
  * `max_devices`: how many devices can be online at once

  Daily usage comes from RADIUS accounting.
* **Vouchers.** These are 8-character codes such as `K7MQ2XRP`. A voucher's
  validity starts on first use. Each voucher has its own device count and an
  optional data cap, and you can revoke it at any time.
* **Dashboard.** Kick, block and revoke send an RFC 5176 Disconnect-Request to
  the router, so the person is dropped at once.

## Setup on the RB5009

1. **Build the image** for arm64 on any machine with Docker:
   ```sh
   docker buildx build --platform linux/arm64 -t erpwifi:arm64 \
     --output type=docker,dest=erpwifi-arm64.tar .
   ```
2. **Write the config.** Start from `deploy/config.example.toml`:
   * Set `erpnext.url`.
   * In ERPNext, open *User → API Access → Generate Keys* on a user that can
     read User and Employee, and paste the key and secret into `api_key` and
     `api_secret`.
   * Set the RADIUS secret, your profiles and your rules.
   * Run `erpwifi hash-password` and paste the result into
     `admin_password_hash`.
   * Check the file with `erpwifi -c config.toml check-config`, and test a
     real account with `erpwifi -c config.toml check-erp jane@yourco.com`.
3. **Prepare the router.**
   * Install the `container` package.
   * Run `/system/device-mode/update container=yes` and confirm by pressing
     the reset button.
   * Plug in a USB stick formatted as ext4.
   * Upload `erpwifi-arm64.tar` to `usb1/` and `config.toml` to
     `usb1/erpwifi/`.
4. **Run `routeros/1-container.rsc`.** It creates the container network
   (`172.31.250.0/30`), the NAT and firewall rules, and the container. Then
   start the container with `/container start [find comment=erpwifi]`.
5. **Create the hotspot** if you don't have one: `/ip hotspot setup` on your
   WiFi bridge or VLAN. Put it on its own subnet, not 192.168.6.0/24.
6. **Run `routeros/2-hotspot.rsc`** with the same secret. Then copy
   `hotspot/*.html` into the router's `hotspot-erp` directory (Winbox → Files,
   or `scp hotspot/*.html admin@192.168.6.1:hotspot-erp/`).
7. Open the dashboard at `http://172.31.250.2:8080` from the admin LAN.

### Security notes

* ERPNext has to see the real password, so the hotspot must use **PAP**
  (`login-by=http-pap`). On an open SSID, add `https` to `login-by` with a
  certificate on the hotspot profile, or use WPA2/WPA3 on the SSID, so
  passwords aren't sent in clear over the air. Between the router and the
  container, RADIUS hides the password with the shared secret, and the
  container talks to ERPNext over HTTPS.
* Use a long random RADIUS secret. Requests from unknown addresses or with the
  wrong secret are dropped.
* If ERPNext rate-limits logins (HTTP 429), users see "Sign-in service
  unavailable". Raise the limit in ERPNext if many people sign in at once,
  for example at the start of a shift.

## Development

```sh
pip install -e '.[test]'
pytest
```

The tests start the real RADIUS server and talk to it the way RouterOS does:
PAP with Message-Authenticator, accounting Start/Interim/Stop and
Accounting-On. They run against a fake ERPNext (`tests/fake_erpnext.py`), and
a fake router (`tests/fake_router.py`) that also answers Disconnect-Requests.
