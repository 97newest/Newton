# erpwifi step 1 on core-01: run the sign-in service as a container.
# Rollback: core01-1-container-rollback.rsc
#
# One-time preparation (needs someone at the router, causes one short outage;
# do it after hours):
#   /system/package/enable container
#   /system/device-mode/update container=yes
#   then, within 5 minutes, press the reset button briefly or pull the power.
#   The reboot activates both the package and container mode.
#
# Before pasting this script:
#   - fill in config.toml (from deploy/config.example.toml) and upload it in
#     Winbox > Files to erpwifi/data/config.toml
#   - check the variables below

:local registry "https://ghcr.io"
:local image "97newest/erpwifi:latest"
# Networks (besides 192.168.6.0/24) allowed to open the dashboard. The
# dashboard asks for an admin account or an ERP user with an admin role.
:local adminAddresses {"192.168.80.0/24";"192.168.81.0/24"}
# Set if ERPNext runs on an internal server, e.g. "192.168.5.5". Leave "" if
# ERPNext is on the internet.
:local erpnextLanIp ""

/interface/bridge add name=br-erpwifi comment="erpwifi"
/ip/address add address=172.31.250.1/30 interface=br-erpwifi comment="erpwifi"
/interface/veth add name=veth-erpwifi address=172.31.250.2/30 gateway=172.31.250.1 comment="erpwifi"
/interface/bridge/port add bridge=br-erpwifi interface=veth-erpwifi comment="erpwifi"

/ip/firewall/address-list add list=WIFI-ADMINS address=192.168.6.0/24 comment="erpwifi"
:foreach a in=$adminAddresses do={ /ip/firewall/address-list add list=WIFI-ADMINS address=$a comment="erpwifi" }

# The container's address is not in the LAN list, so it needs its own rules.
# Each goes to the top; the drop is added first so it ends up below the accepts.
# Internet traffic is already masqueraded by the existing pppoe-faiba srcnat rule.
/ip/firewall/filter add chain=forward action=drop dst-address=172.31.250.2 connection-state=new place-before=0 comment="erpwifi: dashboard closed to everyone else"
/ip/firewall/filter add chain=forward action=accept dst-address=172.31.250.2 protocol=tcp dst-port=80 src-address-list=WIFI-ADMINS place-before=0 comment="erpwifi: dashboard for WIFI-ADMINS"
/ip/firewall/filter add chain=forward action=accept dst-address=172.31.250.2 protocol=tcp dst-port=8081 src-address-list=LAN place-before=0 comment="erpwifi: visitor request page"
/ip/firewall/filter add chain=forward action=accept src-address=172.31.250.2 out-interface-list=WAN place-before=0 comment="erpwifi: container to internet (ERPNext, image)"
:if ([:len $erpnextLanIp] > 0) do={
    /ip/firewall/filter add chain=forward action=accept src-address=172.31.250.2 dst-address=$erpnextLanIp protocol=tcp dst-port=80,443 place-before=0 comment="erpwifi: container to ERPNext"
}
/ip/firewall/filter add chain=input action=accept src-address=172.31.250.2 protocol=udp dst-port=53,3799 place-before=0 comment="erpwifi: container DNS and Disconnect"

/container/config set registry-url=$registry tmpdir=erpwifi/tmp
# RAM cap; the property name differs between 7.x releases.
:do { /container/config set memory-high=256M } on-error={ :do { /container/config set ram-high=256M } on-error={ :put "note: could not set container RAM limit" } }

# RouterOS 7.20 renamed some container properties; try both spellings.
:do {
    /container/mounts add name=erpwifi-data src=erpwifi/data dst=/data
} on-error={
    /container/mounts add list=erpwifi-data src=erpwifi/data dst=/data
}
:do {
    /container add remote-image=$image interface=veth-erpwifi root-dir=erpwifi/root mounts=erpwifi-data dns=172.31.250.1 start-on-boot=yes logging=yes
} on-error={
    /container add remote-image=$image interface=veth-erpwifi root-dir=erpwifi/root mountlists=erpwifi-data dns=172.31.250.1 start-on-boot=yes logging=yes
}

# Friendly address for the dashboard: http://wifi-admin.trident.local
/ip/dns/static add name=wifi-admin.trident.local address=172.31.250.2 comment="erpwifi"

:put "Image is downloading. Watch: /container/print   (status goes extracting -> stopped)"
:put "Then start it:   /container/start [find where interface=veth-erpwifi]"
:put "Check it:        /tool/fetch url=http://172.31.250.2/healthz output=user"
