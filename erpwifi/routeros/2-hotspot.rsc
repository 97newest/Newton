# Point the existing hotspot at erpwifi. Run after 1-container.rsc and after the
# hotspot exists (create one with /ip hotspot setup on your WiFi bridge/VLAN).
#
# /import file-name=2-hotspot.rsc

:local radiusIp "172.31.250.2"
:local secret "CHANGE-to-a-long-random-string"
:local hsProfile "hsprof1"

/radius add service=hotspot address=$radiusIp src-address=172.31.250.1 secret=$secret \
    authentication-port=1812 accounting-port=1813 timeout=6s comment="erpwifi"
# Lets the dashboard kick users (RFC 5176 Disconnect-Request).
/radius incoming set accept=yes port=3799

# PAP is required: ERPNext must see the real password. Add "https" (with an
# ssl-certificate on the profile) so it is encrypted between phone and router.
/ip hotspot profile set [find name=$hsProfile] use-radius=yes radius-accounting=yes \
    radius-interim-update=5m login-by=http-pap html-directory=hotspot-erp

# Device limits come from erpwifi, so let the router allow several logins per
# username. MAC cookies would re-login without asking ERPNext; keep them off.
/ip hotspot user profile set [find default=yes] shared-users=unlimited add-mac-cookie=no


:put "Upload the hotspot/*.html files into the hotspot-erp directory, then sign in from a phone."
