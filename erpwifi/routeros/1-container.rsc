# erpwifi on MikroTik RB5009 (RouterOS 7.20.x, arm64) - run the system as a container.
#
# Before running this script:
#  1. Install the "container" package (System > Packages, or upload
#     container-7.20.5-arm64.npk from the "Extra packages" zip and reboot).
#  2. Enable container mode: /system/device-mode/update container=yes
#     then confirm by pressing the reset button briefly (or cold reboot) within 5 minutes.
#  3. Plug in a USB stick (ext4-formatted via Disks), shown as usb1. Internal
#     flash works too but SQLite writes wear it; change $disk if needed.
#  4. Upload erpwifi-arm64.tar to usb1/ and your filled-in config.toml to usb1/erpwifi/.
#
# Then: /import file-name=1-container.rsc

:local disk "usb1"
:local adminLan "192.168.6.0/24"

/interface/bridge add name=br-containers comment="erpwifi"
/ip/address add address=172.31.250.1/30 interface=br-containers comment="erpwifi"
/interface/veth add name=veth-erpwifi address=172.31.250.2/30 gateway=172.31.250.1 comment="erpwifi"
/interface/bridge/port add bridge=br-containers interface=veth-erpwifi comment="erpwifi"

# Container reaches ERPNext through the router's normal internet/LAN routing.
/ip/firewall/nat add chain=srcnat action=masquerade src-address=172.31.250.0/30 comment="erpwifi outbound"

# Allow: Disconnect requests (dashboard "Kick") from the container to the router,
# the container's outbound traffic, and the dashboard from the admin LAN only.
# Each rule goes to the top, so the drop is added first and ends up below the accepts.
/ip/firewall/filter add chain=forward dst-address=172.31.250.2 action=drop place-before=0 comment="erpwifi: dashboard closed to everyone else"
/ip/firewall/filter add chain=forward dst-address=172.31.250.2 protocol=tcp dst-port=8080 src-address=$adminLan action=accept place-before=0 comment="erpwifi dashboard"
/ip/firewall/filter add chain=forward src-address=172.31.250.2 action=accept place-before=0 comment="erpwifi outbound"
/ip/firewall/filter add chain=input in-interface=br-containers protocol=udp dst-port=3799 action=accept place-before=0 comment="erpwifi CoA"

/container/config set tmpdir=($disk . "/container-tmp")
# RouterOS 7.20: if "name=" / "mounts=" are rejected here, your build uses the
# newer "list=" / "mountlists=" names; run "/container/mounts add ?" to check.
/container/mounts add name=erpwifi-data src=($disk . "/erpwifi") dst=/data
/container add file=($disk . "/erpwifi-arm64.tar") interface=veth-erpwifi \
    root-dir=($disk . "/erpwifi-root") mounts=erpwifi-data \
    start-on-boot=yes logging=yes comment="erpwifi"

:put "Container is extracting; watch /container print. Then: /container start [find comment=erpwifi]"
