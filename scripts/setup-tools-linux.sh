#!/bin/sh
# Install fixed runtime packages from the distribution's configured repositories.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
mode=${1:-install}
case "$mode" in install|--dry-run) ;; *) echo 'Usage: setup-tools-linux.sh [--dry-run]' >&2; exit 1;; esac
[ "$(uname -s)" = Linux ] || { echo 'Tool setup supports Linux only.' >&2; exit 1; }
[ "$mode" = --dry-run ] || [ "$(id -u)" -eq 0 ] || { echo 'Administrator privileges are required to install packages.' >&2; exit 1; }
# Read distribution identifiers as data; do not execute os-release contents.
release=/etc/os-release
ids=$(sed -n 's/^ID=//p;s/^ID_LIKE=//p' "$release" | tr -d '\"\047')
family=
for distro in $ids; do
 case "$distro" in
 ubuntu|debian|linuxmint|kali|pop) family=apt; break;;
 fedora|rhel|centos|rocky|almalinux) family=dnf; break;;
 arch|manjaro|endeavouros) family=pacman; break;;
 opensuse|opensuse-tumbleweed|opensuse-leap|suse) family=zypper; break;;
 esac
done
[ -n "$family" ] || { echo 'Unsupported distribution: install nmap, arp-scan, smbclient and an OpenSSH client using its package manager.' >&2; exit 1; }
set --
for tool in nmap arp-scan smbclient ssh ip useradd visudo; do
 if command -v "$tool" >/dev/null; then printf '[OK] %s\n' "$tool"; continue; fi
 case "$family:$tool" in
 *:nmap|*:arp-scan) package=$tool;;
 apt:smbclient|pacman:smbclient) package=smbclient;;
 dnf:smbclient|zypper:smbclient) package=samba-client;;
 apt:ssh) package=openssh-client;; dnf:ssh) package=openssh-clients;; pacman:ssh|zypper:ssh) package=openssh;;
 dnf:ip) package=iproute;; *:ip) package=iproute2;;
 apt:useradd) package=passwd;; dnf:useradd) package=shadow-utils;; *:useradd) package=shadow;;
 *:visudo) package=sudo;;
 *) echo "No package mapping for $tool on $family" >&2; exit 1;;
 esac
 printf '[MISSING] %s -> %s\n' "$tool" "$package"
 set -- "$@" "$package"
done
if [ "$#" -gt 0 ]; then
 manager=$family
 [ "$family" != apt ] || manager=apt-get
 command -v "$manager" >/dev/null 2>&1 || { echo "Package manager unavailable: $manager" >&2; exit 1; }
 if [ "$mode" = --dry-run ]; then printf 'Would install via %s:' "$family";printf ' %s' "$@";printf '\n';else
  case "$family" in
  apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@";;
  dnf) dnf install -y "$@";;
  pacman) pacman -S --needed --noconfirm "$@";;
  zypper) zypper --non-interactive install --no-recommends "$@";;
  esac
 fi
else printf 'All runtime packages are already available; no installation needed.\n';fi
if [ "$mode" != --dry-run ]; then
 for tool in nmap arp-scan smbclient ssh ip useradd visudo; do
  command -v "$tool" >/dev/null || { echo "Installation incomplete: $tool remains unavailable. Check configured distribution repositories." >&2; exit 1; }
 done
fi
# These are diagnostic/development references, not application runtime dependencies.
for tool in pwsh showmount gssdp-discover gupnp-av-cp; do
 if command -v "$tool" >/dev/null;then printf '[OPTIONAL OK] %s\n' "$tool";else printf '[OPTIONAL] %s is not required by the current runtime.\n' "$tool";fi
done
printf 'Windows collection uses SSH and PowerShell on Windows; local pwsh is optional.\n'
