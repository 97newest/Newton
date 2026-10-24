# erpwifi preflight for core-01 ("0. Firewall"). READ-ONLY: prints what the
# other scripts depend on and changes nothing. Paste it, then send the output
# to whoever is doing the install.

:put "== RouterOS / storage / RAM =="
/system/resource/print
:put "== device mode (needs container=yes) =="
/system/device-mode/print
:put "== container package (needs to be enabled) =="
/system/package/print where name=container
:put "== interfaces the hotspot uses =="
/interface/print where name=bridge1 or name=vlan81
/ip/address/print where interface=bridge1 or interface=vlan81
:put "== 172.31.250.0/30 must be unused (container network) =="
/ip/address/print where address~"^172\\.31\\.250\\."
:put "== existing hotspot and RADIUS (expected: none) =="
/ip/hotspot/print
/radius/print
:put "== fasttrack rules (fasttracked traffic skips hotspot accounting) =="
/ip/firewall/filter/print where action=fasttrack-connection
:put "== speed-tier address lists used by the profiles =="
:foreach l in={"Express";"Restrict-Conn";"Slow-Conn"} do={
    :put ($l . ": " . [:len [/ip/firewall/address-list/find where list=$l]] . " entries, " . \
        [:len [/ip/firewall/mangle/find where src-address-list=$l or dst-address-list=$l]] . " mangle rules")
}
:put "== static ARP entries on bridge1 per subnet (.6/.30/.50 become hotspot bypasses) =="
:foreach net in={192.168.6.0/24;192.168.30.0/24;192.168.50.0/24;192.168.80.0/24} do={
    :local n 0
    :foreach a in=[/ip/arp/find where interface=bridge1 and dynamic=no] do={
        :if ([/ip/arp/get $a address] in $net) do={ :set n ($n + 1) }
    }
    :put ([:tostr $net] . ": " . $n)
}
:put "== static ARP entries on vlan81 =="
:put [:len [/ip/arp/find where interface=vlan81 and dynamic=no]]
:put "== wired 192.168.80.x devices (static ARP): pick admin PCs, printers, servers for bypassMacs =="
/ip/arp/print where interface=bridge1 and dynamic=no and address in 192.168.80.0/24
