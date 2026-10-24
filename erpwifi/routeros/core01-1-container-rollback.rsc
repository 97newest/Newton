# Undo core01-1-container.rsc. Run core01-2-hotspot-rollback.rsc first if the
# hotspot was set up. Keeps erpwifi/data (config, database); remove it by hand
# with /file/remove erpwifi if wanted. Leaves the container package and
# device mode as they are.

:foreach c in=[/container/find where interface=veth-erpwifi] do={
    :do { /container/stop $c } on-error={}
}
:delay 5s
/container/remove [find where interface=veth-erpwifi]
:do { /container/mounts/remove [find where src="erpwifi/data"] } on-error={}
/ip/firewall/filter/remove [find where comment~"^erpwifi: (dashboard|container)"]
/ip/firewall/address-list/remove [find where list=WIFI-ADMINS and comment="erpwifi"]
/interface/bridge/port/remove [find where interface=veth-erpwifi]
/interface/veth/remove [find where name=veth-erpwifi]
/ip/address/remove [find where comment="erpwifi" and interface=br-erpwifi]
/interface/bridge/remove [find where name=br-erpwifi]
:put "erpwifi container removed"
