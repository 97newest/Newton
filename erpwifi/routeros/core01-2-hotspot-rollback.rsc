# Undo core01-2-hotspot.rsc. Everyone goes back to the current setup at once.
/ip/hotspot/remove [find where name~"^hs-erpwifi"]
/ip/hotspot/ip-binding/remove [find where comment~"^erpwifi"]
/ip/hotspot/profile/remove [find where name~"^hsprof-erpwifi"]
/ip/hotspot/user/remove [find where comment~"^erpwifi"]
/ip/hotspot/user/profile/remove [find where name=erpwifi]
/ip/firewall/filter/remove [find where comment="erpwifi: guests internet only"]
/ip/firewall/address-list/remove [find where list=HS-GUEST]
/radius/remove [find where comment="erpwifi"]
/radius/incoming set accept=no
# vlan81 was arp=reply-only before (MAC whitelisting).
/interface/vlan set [find name=vlan81] arp=reply-only
/file/remove [find where name~"^erpwifi-hotspot"]
:put "erpwifi hotspot removed"
