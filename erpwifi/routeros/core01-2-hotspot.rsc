# erpwifi step 2 on core-01: make everyone on WiFi (vlan81, 192.168.81.0/24)
# and wired LAN (bridge1, 192.168.80.0/24) sign in.
# Rollback: core01-2-hotspot-rollback.rsc
#
# Needs step 1 running (http://172.31.250.2/healthz answers).
# Both hotspot servers are created DISABLED. Enable WiFi first, test, then wired:
#   /ip/hotspot/enable hs-erpwifi-wifi
#   /ip/hotspot/enable hs-erpwifi-lan

:local radiusSecret "CHANGE-same-as-config.toml"
:local dnsName "wifi.trident.local"
# bridge1 also carries switch management, cameras and PBX phones. Every device
# with a static ARP entry in these subnets is bypassed (no sign-in needed).
:local bypassSubnets {192.168.6.0/24;192.168.30.0/24;192.168.50.0/24}
# MACs on .80/.81 that must never be asked to sign in: admin PCs, printers,
# shared machines. Format "AA:BB:CC:DD:EE:FF".
:local bypassMacs [:toarray ""]
# Local hotspot user that works even when the container or ERPNext is down.
# Leave "" to skip. Pick a long password and keep it in the admin vault.
:local breakGlassPassword ""
# vlan81 only talks to devices with a hand-made static ARP entry. Guests with
# vouchers have none, so they can't reach the sign-in page. "yes" lets the
# router learn ARP on vlan81 (sign-in becomes the gate instead). bridge1 is
# never changed.
:local openWifiArp "no"

:if ($radiusSecret = "CHANGE-same-as-config.toml") do={ :error "Set radiusSecret first" }

/radius add service=hotspot address=172.31.250.2 src-address=172.31.250.1 secret=$radiusSecret \
    authentication-port=1812 accounting-port=1813 timeout=6s comment="erpwifi"
# Lets the dashboard disconnect users (RFC 5176). Only the RADIUS server above
# is accepted, and the input rule from step 1 allows it.
/radius/incoming set accept=yes port=3799

# Sign-in pages, downloaded from the container.
:foreach f in={"login.html";"alogin.html";"status.html";"logout.html";"error.html";"redirect.html";"rlogin.html"} do={
    /tool/fetch url=("http://172.31.250.2/hotspot/" . $f) dst-path=("erpwifi-hotspot/" . $f)
}

# Users signed in through RADIUS land in this profile. Device limits come from
# erpwifi, so the router allows several logins per user. MAC cookies would let
# people back in without asking ERPNext, so they stay off.
/ip/hotspot/user/profile add name=erpwifi shared-users=unlimited add-mac-cookie=no status-autorefresh=1m
# Hotspot makes one dynamic queue per user. Putting them at the bottom keeps the
# existing Parent/PCQ queues (and per-device queues) in charge of speed.
:do { /ip/hotspot/user/profile set [find name=erpwifi] insert-queue-before=bottom } on-error={ :put "WARNING: could not set insert-queue-before=bottom; check /queue/simple order" }

/ip/hotspot/profile add name=hsprof-erpwifi-lan hotspot-address=192.168.80.1 dns-name=$dnsName \
    html-directory=erpwifi-hotspot login-by=http-pap use-radius=yes radius-accounting=yes radius-interim-update=5m
/ip/hotspot/profile add name=hsprof-erpwifi-wifi hotspot-address=192.168.81.1 dns-name=$dnsName \
    html-directory=erpwifi-hotspot login-by=http-pap use-radius=yes radius-accounting=yes radius-interim-update=5m

# address-pool=none: devices keep the addresses the existing DHCP servers give them.
/ip/hotspot add name=hs-erpwifi-wifi interface=vlan81 profile=hsprof-erpwifi-wifi address-pool=none idle-timeout=5m disabled=yes
/ip/hotspot add name=hs-erpwifi-lan interface=bridge1 profile=hsprof-erpwifi-lan address-pool=none idle-timeout=5m disabled=yes

:local bypassed 0
:foreach a in=[/ip/arp/find where interface=bridge1 and dynamic=no] do={
    :local ip [/ip/arp/get $a address]
    :local mac [/ip/arp/get $a mac-address]
    :foreach net in=$bypassSubnets do={
        :if (([:len $mac] > 0) && ($ip in $net)) do={
            :do {
                /ip/hotspot/ip-binding add server=hs-erpwifi-lan mac-address=$mac type=bypassed comment=("erpwifi bypass " . $ip)
                :set bypassed ($bypassed + 1)
            } on-error={}
        }
    }
}
:foreach mac in=$bypassMacs do={
    /ip/hotspot/ip-binding add mac-address=$mac type=bypassed comment="erpwifi bypass (manual)"
}
:put ("Bypassed " . $bypassed . " infrastructure devices on bridge1, " . [:len $bypassMacs] . " manual")

# Before signing in, people may open the visitor request page (and nothing else).
/ip/hotspot/walled-garden/ip add dst-address=172.31.250.2 protocol=tcp dst-port=8081 action=accept comment="erpwifi visitor request page"

# Voucher and pass guests are put in HS-GUEST: internet only, no SAP/file
# server/cameras/PBX, and no dashboard login page.
/ip/firewall/filter add chain=forward action=drop src-address-list=HS-GUEST dst-address-list=LAN place-before=0 comment="erpwifi: guests internet only"
/ip/firewall/filter add chain=forward action=drop src-address-list=HS-GUEST dst-address=172.31.250.2 protocol=tcp dst-port=80 place-before=0 comment="erpwifi: guests no dashboard"

:if ([:len $breakGlassPassword] > 0) do={
    /ip/hotspot/user add name=wifi-breakglass password=$breakGlassPassword profile=erpwifi comment="erpwifi break-glass, works without the container"
}

:if ($openWifiArp = "yes") do={
    /interface/vlan set [find name=vlan81] arp=enabled
    :put "vlan81 ARP set to enabled"
}

:put "Ready. Enable WiFi first: /ip/hotspot/enable hs-erpwifi-wifi"
