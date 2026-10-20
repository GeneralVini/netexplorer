#!/bin/sh
# Provision the dedicated Linux service account and the reviewed ARP-only policy.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$(id -u)" -eq 0 ] || { echo 'Run setup through make setup (administrator privileges required).' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Dedicated-account setup currently supports Linux only.' >&2; exit 1; }
[ "$#" -le 1 ] || { echo 'Only one interface argument is accepted.' >&2; exit 1; }
/bin/sh scripts/setup-tools-linux.sh
for utility in useradd usermod groupadd getent passwd visudo install ip; do
 command -v "$utility" >/dev/null || { echo "Required setup utility missing: $utility" >&2; exit 1; }
done
iface=${1:-}
if [ -z "$iface" ]; then
 iface=$(ip -4 route show default | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}')
fi
case "$iface" in ''|lo|*[!a-zA-Z0-9_.-]*|-*) echo 'Specify a valid LAN interface: make setup INTERFACE=eth0' >&2; exit 1;; esac
[ "${#iface}" -le 15 ] && [ -d "/sys/class/net/$iface" ] || { echo 'LAN interface does not exist.' >&2; exit 1; }
shell=/usr/sbin/nologin
[ -x "$shell" ] || shell=/sbin/nologin
[ -x "$shell" ] || { echo 'nologin is unavailable; refusing to create a login-enabled account.' >&2; exit 1; }
# Refuse to repurpose an ordinary login account with the same name.
if getent passwd netexplorer >/dev/null; then
 uid=$(id -u netexplorer)
 [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ] || { echo 'Existing netexplorer is not a system account; refusing to repurpose it.' >&2; exit 1; }
fi
# Preserve existing administrator policy instead of silently replacing it.
policy="netexplorer ALL=(root) NOPASSWD: /usr/local/libexec/netexplorer-arp $iface"
if [ -e /etc/sudoers.d/netexplorer ]; then
 existing=$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /etc/sudoers.d/netexplorer)
 [ "$existing" = "$policy" ] || { echo 'Existing netexplorer sudoers policy differs; review it before setup.' >&2; exit 1; }
fi
getent group netexplorer >/dev/null || groupadd --system netexplorer
if ! getent passwd netexplorer >/dev/null; then
 useradd --system --gid netexplorer --home-dir /var/lib/netexplorer --shell "$shell" --no-create-home netexplorer
fi
usermod --gid netexplorer --groups '' --home /var/lib/netexplorer --shell "$shell" --lock netexplorer
install -d -o netexplorer -g netexplorer -m 0750 /var/lib/netexplorer /var/lib/netexplorer/vendors
install -d -o root -g root -m 0755 /opt/netexplorer
[ -d /usr/local/libexec ] || install -d -o root -g root -m 0755 /usr/local/libexec
[ -d /etc/sudoers.d ] || install -d -o root -g root -m 0750 /etc/sudoers.d
install -o root -g root -m 0755 bin/netexplorer /opt/netexplorer/netexplorer
install -o root -g root -m 0755 bin/netexplorer-arp /usr/local/libexec/netexplorer-arp
staged=$(mktemp /etc/sudoers.d/.netexplorer.XXXXXX)
trap 'rm -f "$staged"' EXIT HUP INT TERM
printf '%s\n' "$policy" > "$staged"
visudo -cf "$staged"
chmod 0440 "$staged"
if [ ! -e /etc/sudoers.d/netexplorer ]; then
 mv "$staged" /etc/sudoers.d/netexplorer
else
 chown root:root /etc/sudoers.d/netexplorer
 chmod 0440 /etc/sudoers.d/netexplorer
fi
visudo -c
# Assert the account contract, including absence of supplementary memberships.
[ "$(getent passwd netexplorer | cut -d: -f7)" = "$shell" ]
[ "$(passwd -S netexplorer | awk '{print $2}')" = L ]
[ "$(id -Gn netexplorer)" = netexplorer ]
printf 'Setup complete: netexplorer has a locked password, nologin shell and ARP-only sudo access on %s.\n' "$iface"
printf 'Start with make run. Optional tool availability: make doctor.\n'
