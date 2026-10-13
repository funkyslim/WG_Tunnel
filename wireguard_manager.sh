#!/usr/bin/env bash
# =============================================================================
# WireGuard Manager — Person 1 / Ubuntu 24.04
# =============================================================================
# Purpose:
#   Let Person 2's Keenetic LAN clients use this Ubuntu computer as their
#   IPv4 Internet exit via a WireGuard tunnel initiated by this computer.
#
# Network defaults:
#   Person 1 LAN: 192.168.1.0/24       Person 2 LAN: 192.168.2.0/24
#   Ubuntu WG:    10.77.0.1/24         Keenetic WG:  10.77.0.2/32
#   Remote WireGuard UDP listening port: 7214
#
# Menu:
#   Setup  - validate inputs, install prerequisites, configure VPN/NAT/firewall
#   Delete - remove configuration and rules owned by this script
#   Exit   - make no changes
#
# This script does NOT configure the Keenetic router. Exchange public keys
# manually and set up its WireGuard peer and connection policy separately.
# Run as root: sudo bash wireguard_manager.sh
#
# Security: never share the generated PRIVATE key. All files/state are
# written with restrictive permissions. Existing wg0 setups are not overwritten.
# =============================================================================
set -Eeuo pipefail
umask 077

# -----------------------------------------------------------------------------
# Constants: paths and default network settings
# -----------------------------------------------------------------------------
WG=wg0
WG_DIR=/etc/wireguard
CONF="$WG_DIR/$WG.conf"
PRIVATE="$WG_DIR/person1-private.key"
PUBLIC="$WG_DIR/person1-public.key"
SYSCTL_FILE=/etc/sysctl.d/99-person1-wireguard-forward.conf
STATE_DIR=/var/lib/person1-wireguard-manager
STATE="$STATE_DIR/state"
PORT=7214
P1_LAN_DEFAULT=192.168.1.0/24
P2_LAN_DEFAULT=192.168.2.0/24
P1_WG_DEFAULT=10.77.0.1/24
P2_WG_DEFAULT=10.77.0.2/32

# -----------------------------------------------------------------------------
# Console prompts and status messages
# -----------------------------------------------------------------------------
info() {
    printf '\n[INFO] %s\n' "$*"
}

warn() {
    printf '\n[WARN] %s\n' "$*" >&2
}

fail() {
    printf '\n[ERROR] %s\n' "$*" >&2
    return 1
}

need_root() {
    if (( EUID != 0 )); then
        warn 'Run with sudo: sudo bash wireguard_manager.sh'
        return 1
    fi
}

# Ask for a value; accept the suggested default when the answer is blank.
ask() {
    local var="$1"
    local label="$2"
    local default="${3:-}"
    local value

    read -r -p "$label${default:+ [$default]}: " value
    printf -v "$var" '%s' "${value:-$default}"
}

# Destructive steps default to No.
confirm() {
    local answer
    read -r -p "$1 [y/N]: " answer
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# -----------------------------------------------------------------------------
# Installation state: record exactly what this manager owns
# -----------------------------------------------------------------------------
write_state() {
  mkdir -p -m 700 "$STATE_DIR"
  : > "$STATE"
  local v
  for v in WAN P1_LAN P2_LAN P1_WG P2_WG ENDPOINT P2_KEY FIREWALL ORIGINAL_FORWARD PACKAGES_INSTALLED UFW_RULE1 UFW_RULE2; do
    printf '%s=%q\n' "$v" "${!v:-}" >> "$STATE"
  done
  chmod 600 "$STATE"
}
load_state() {
  [[ -f "$STATE" ]] || { warn 'No installation owned by this script was found; nothing to delete.'; return 1; }
  # Protected root-owned state file written by this script, never user-supplied values.
  # shellcheck disable=SC1090
  source "$STATE"
}
# Validate the remote public key's Base64 shape AND decoded 32-byte length.
valid_key() {
  [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  [[ $(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c) -eq 32 ]]
}
# Ensure LAN networks do not overlap and tunnel addresses are distinct.
check_cidrs() {
  python3 - "$P1_LAN" "$P2_LAN" "$P1_WG" "$P2_WG" <<'PY'
import ipaddress,sys
try:
    a,b,c,d=[ipaddress.ip_network(s,strict=False) for s in sys.argv[1:]]
    assert all(x.version==4 for x in (a,b,c,d))
    assert not a.overlaps(b), 'The two LANs overlap'
    assert not any(x.overlaps(y) for x in (a,b) for y in (c,d)), 'WG IPs overlap a LAN'
    assert c.prefixlen in (24,32), 'Person 1 tunnel must be /24 or /32'
    assert d.prefixlen==32, 'Person 2 tunnel host must be /32'
    assert c.network_address != d.network_address or c.prefixlen != d.prefixlen, 'WG peers share an IP'
    assert ipaddress.ip_interface(sys.argv[3]).ip != ipaddress.ip_interface(sys.argv[4]).ip, 'WG peers share an IP'
    # Require both WireGuard hosts in same /24; config uses P1 /24 by default.
    assert ipaddress.ip_interface(sys.argv[4]).ip in ipaddress.ip_network(str(ipaddress.ip_interface(sys.argv[3]).ip)+'/24', strict=False), 'WG peers not in same /24'
except (ValueError,AssertionError) as exc:
    sys.exit('Invalid addressing: '+str(exc))
PY
}
# -----------------------------------------------------------------------------
# Preflight: read-only checks, before modifying the Ubuntu host
# -----------------------------------------------------------------------------
# Checks Ubuntu release, dependencies, routes, collisions, keys and firewalls.
preflight() {
  need_root || return 1
  [[ -f /etc/os-release ]] || fail 'Cannot identify operating system.' || return 1
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { fail 'This script supports Ubuntu 24.04 only.'; return 1; }
  for command in ip python3 base64 getent systemctl apt-get dpkg-query; do
    command -v "$command" >/dev/null || { fail "Missing required command: $command"; return 1; }
  done
  [[ ! -e "$STATE" && ! -e "$CONF" && ! -e "$PRIVATE" && ! -e "$PUBLIC" && ! -e "$SYSCTL_FILE" ]] || { fail 'Existing owned files or wg0.conf detected. Delete through this menu first, or resolve the collision manually.'; return 1; }
  [[ ! -e "$STATE_DIR" ]] || { fail 'Old state directory exists; resolve before setup to avoid modifying foreign files.'; return 1; }
  ! ip link show "$WG" >/dev/null 2>&1 || { fail 'wg0 already exists.'; return 1; }
  ip link show dev "$WAN" >/dev/null 2>&1 || { fail "Network interface '$WAN' does not exist."; return 1; }
  [[ "$WAN" =~ ^[a-zA-Z0-9_.:-]{1,15}$ && "$WAN" != "$WG" ]] || { fail 'Invalid outbound interface name.'; return 1; }
  [[ "$ENDPOINT" =~ ^[A-Za-z0-9.-]+$ && "$ENDPOINT" != -* ]] || { fail 'Endpoint must be IPv4 or DNS hostname (no port/scheme/path).'; return 1; }
  getent ahostsv4 "$ENDPOINT" >/dev/null || { fail 'Endpoint does not currently resolve to IPv4; fix DNS before setup.'; return 1; }
  local endpoint_ip endpoint_route
  endpoint_ip=$(getent ahostsv4 "$ENDPOINT" | awk 'NR==1{print $1}')
  endpoint_route=$(ip -4 route get "$endpoint_ip" 2>/dev/null) || { fail 'Cannot route to Keenetic endpoint.'; return 1; }
  [[ " $endpoint_route " == *" dev $WAN "* ]] || { fail "Keenetic endpoint is not currently routed via $WAN: $endpoint_route"; return 1; }
  [[ "$PORT" == 7214 ]] || { fail 'Internal UDP port mismatch.'; return 1; }
  valid_key "$P2_KEY" || { fail 'Keenetic public key is not a 32-byte base64 WireGuard key.'; return 1; }
  check_cidrs || return 1
  local route
  route=$(ip -4 route get 1.1.1.1 2>/dev/null) || { fail 'No working IPv4 route to a public destination.'; return 1; }
  [[ " $route " == *" dev $WAN "* ]] || { fail "Expected outbound interface $WAN, but: $route"; return 1; }
  local p2route
  p2route=$(ip -4 route get "${P2_LAN%/*}" 2>/dev/null || true)
  if [[ " $p2route " == *" dev $WAN "* && " $p2route " == *' via '* ]]; then
    warn "An existing route may already cover Person 2 LAN: $p2route"
  fi
  local p1subnet
  p1subnet=$(ip -4 -o addr show dev "$WAN")
  [[ -n "$p1subnet" ]] || { fail 'Outbound interface has no IPv4 address.'; return 1; }
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    fail 'firewalld is active. This script supports UFW or iptables, not firewalld.'; return 1
  fi
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    FIREWALL=ufw
    # UFW itself must not force IPv4 forwarding back to 0 on reload.
    if [[ -f /etc/ufw/sysctl.conf ]] && grep -Eq '^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=[[:space:]]*0([[:space:]]|$)' /etc/ufw/sysctl.conf; then
      fail 'Active UFW explicitly disables forwarding in /etc/ufw/sysctl.conf. Set it to 1 and rerun; refusing to rewrite a shared UFW config.'; return 1
    fi
  else
    FIREWALL=iptables
  fi
  # Do not manage a complex native nftables firewall as if it were empty.
  if [[ "$FIREWALL" == iptables ]] && command -v nft >/dev/null && systemctl is-active --quiet nftables 2>/dev/null; then
    fail 'Native nftables.service is active; configure forwarding there rather than mixing firewall managers.'; return 1
  fi
  ORIGINAL_FORWARD=$(sysctl -n net.ipv4.ip_forward)
  PACKAGES_INSTALLED=''
  for p in wireguard-tools iptables; do
    if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -qx 'install ok installed'; then
      PACKAGES_INSTALLED+=" $p"
    fi
  done
  info "Preflight passed. Firewall mode: $FIREWALL. Outbound NIC: $WAN."
  printf 'Existing default route: %s\n' "$route"
}

# -----------------------------------------------------------------------------
# Firewall cleanup helpers: remove only specifically tagged / tracked rules
# -----------------------------------------------------------------------------
remove_manual_rule() {
  local table="$1"; shift
  if [[ "$table" == filter ]]; then
    while iptables -C "$@" 2>/dev/null; do iptables -D "$@" || break; done
  else
    while iptables -t "$table" -C "$@" 2>/dev/null; do iptables -t "$table" -D "$@" || break; done
  fi
}
cleanup_rules() {
  command -v iptables >/dev/null || return 0
  # Deletion uses comment match, so no unrelated rules are removed.
  remove_manual_rule nat POSTROUTING -s "$P2_LAN" -o "$WAN" -m comment --comment person1wg-nat-lan -j MASQUERADE
  remove_manual_rule nat POSTROUTING -s "$P2_WG" -o "$WAN" -m comment --comment person1wg-nat-peer -j MASQUERADE
  if [[ "$FIREWALL" == iptables ]]; then
    remove_manual_rule filter FORWARD -i "$WG" -o "$WAN" -s "$P2_LAN" -m comment --comment person1wg-fwd-lan -j ACCEPT
    remove_manual_rule filter FORWARD -i "$WG" -o "$WAN" -s "$P2_WG" -m comment --comment person1wg-fwd-peer -j ACCEPT
    remove_manual_rule filter FORWARD -i "$WAN" -o "$WG" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment person1wg-return -j ACCEPT
  fi
}
remove_ufw_rules() {
  if [[ "$FIREWALL" == ufw ]] && command -v ufw >/dev/null; then
    if [[ "${UFW_RULE1:-}" == yes ]]; then ufw --force route delete allow in on "$WG" out on "$WAN" from "$P2_LAN" to any || warn 'Review UFW LAN route rule manually.'; fi
    if [[ "${UFW_RULE2:-}" == yes ]]; then ufw --force route delete allow in on "$WG" out on "$WAN" from "$P2_WG" to any || warn 'Review UFW tunnel-peer route rule manually.'; fi
  fi
}
# Undo files/services/firewall entries created during Setup. This is also used
# for best-effort rollback if Setup fails partway through.
remove_owned() {
  systemctl disable --now "wg-quick@$WG" >/dev/null 2>&1 || true
  # If interface was started outside systemd, try graceful down too.
  if ip link show "$WG" >/dev/null 2>&1 && [[ -f "$CONF" ]]; then wg-quick down "$WG" || warn 'wg-quick down failed; inspect interface.'; fi
  cleanup_rules
  remove_ufw_rules
  rm -f -- "$CONF" "$PRIVATE" "$PUBLIC" "$SYSCTL_FILE"
  systemctl daemon-reload || true
  # Re-evaluate sysctl drop-ins; do not silently retain our enabled forwarding.
  sysctl --system >/dev/null 2>&1 || true
  if [[ "${ORIGINAL_FORWARD:-}" == 0 ]] && [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]; then
    warn 'IPv4 forwarding remains enabled by another sysctl setting; not changing that setting.'
  fi
  rm -f "$STATE"
  rmdir "$STATE_DIR" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Menu action 1: Setup
# -----------------------------------------------------------------------------
setup() {
  need_root || return 1
  if [[ -e "$STATE" || -e "$CONF" ]]; then warn 'Existing setup detected. Use Delete first.'; return 1; fi
  info 'Person 1 initiates WireGuard to Keenetic UDP 7214. Keenetic must already have its own key pair.'
  local discovered
  discovered=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
  ask WAN 'Ubuntu Internet egress interface' "$discovered"
  ask P1_LAN 'Person 1 LAN subnet' "$P1_LAN_DEFAULT"
  ask P2_LAN 'Person 2 LAN subnet' "$P2_LAN_DEFAULT"
  ask P1_WG 'Ubuntu WireGuard address/prefix' "$P1_WG_DEFAULT"
  ask P2_WG 'Keenetic WireGuard host address/prefix' "$P2_WG_DEFAULT"
  ask ENDPOINT 'Keenetic public IPv4 / DNS hostname (without :port)'
  ask P2_KEY 'Keenetic WireGuard PUBLIC key'
  preflight || return 1
  printf '\nSUMMARY: %s -> %s:%s via %s; WG local %s, peer %s; Person 2 LAN %s; firewall %s\n' "$WG" "$ENDPOINT" "$PORT" "$WAN" "$P1_WG" "$P2_WG" "$P2_LAN" "$FIREWALL"
  confirm 'Apply configuration on this Ubuntu PC?' || { info 'Setup cancelled; no changes made.'; return 0; }

  # Record the owned settings BEFORE changing the machine. A RETURN trap
  # makes a best-effort rollback if any subsequent command fails.
  UFW_RULE1=no UFW_RULE2=no
  write_state
  local success=no
  trap 'if [[ "$success" != yes ]]; then warn "Setup failed: reverting script-owned changes."; remove_owned; fi' RETURN
  if [[ -n "${PACKAGES_INSTALLED// /}" ]]; then
    apt-get update
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PACKAGES_INSTALLED
  fi
  for exe in wg wg-quick iptables sysctl; do command -v "$exe" >/dev/null || { fail "Missing $exe after package install"; return 1; }; done
  # Generate a fresh Ubuntu WireGuard identity (private/public key pair).
  install -d -m 700 "$WG_DIR"
  wg genkey > "$PRIVATE"
  wg pubkey < "$PRIVATE" > "$PUBLIC"
  chmod 600 "$PRIVATE" "$PUBLIC"
  local local_private
  local_private=$(<"$PRIVATE")
  # Persist IPv4 forwarding across boots using a dedicated sysctl drop-in.
  cat > "$SYSCTL_FILE" <<'SYS'
# Installed by wireguard_manager.sh
net.ipv4.ip_forward=1
SYS
  chmod 644 "$SYSCTL_FILE"
  sysctl -w net.ipv4.ip_forward=1
  # WireGuard tunnel and NAT. wg-quick applies PostUp/PostDown rules only
  # while this interface is enabled, not globally for every network.
  cat > "$CONF" <<CFG
# Installed by wireguard_manager.sh; modify through re-deployment, not ad hoc.
[Interface]
Address = $P1_WG
PrivateKey = $local_private
# NAT Person 2 traffic through Person 1's normal Internet uplink.
PostUp = iptables -t nat -I POSTROUTING 1 -s $P2_LAN -o $WAN -m comment --comment person1wg-nat-lan -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s $P2_LAN -o $WAN -m comment --comment person1wg-nat-lan -j MASQUERADE
PostUp = iptables -t nat -I POSTROUTING 1 -s $P2_WG -o $WAN -m comment --comment person1wg-nat-peer -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s $P2_WG -o $WAN -m comment --comment person1wg-nat-peer -j MASQUERADE
CFG
  if [[ "$FIREWALL" == iptables ]]; then
    cat >> "$CONF" <<CFG
# Explicit forward rules only when UFW is not active.
PostUp = iptables -I FORWARD 1 -i %i -o $WAN -s $P2_LAN -m comment --comment person1wg-fwd-lan -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o $WAN -s $P2_LAN -m comment --comment person1wg-fwd-lan -j ACCEPT
PostUp = iptables -I FORWARD 1 -i %i -o $WAN -s $P2_WG -m comment --comment person1wg-fwd-peer -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o $WAN -s $P2_WG -m comment --comment person1wg-fwd-peer -j ACCEPT
PostUp = iptables -I FORWARD 1 -i $WAN -o %i -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment person1wg-return -j ACCEPT
PostDown = iptables -D FORWARD -i $WAN -o %i -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment person1wg-return -j ACCEPT
CFG
  fi
  cat >> "$CONF" <<CFG

[Peer]
PublicKey = $P2_KEY
AllowedIPs = $P2_WG, $P2_LAN
Endpoint = $ENDPOINT:$PORT
PersistentKeepalive = 25
CFG
  chmod 600 "$CONF"
  # UFW manages FORWARD filtering itself when enabled; otherwise the
  # interface's PostUp/PostDown lines install narrowly scoped iptables rules.
  if [[ "$FIREWALL" == ufw ]]; then
    ufw route allow in on "$WG" out on "$WAN" from "$P2_LAN" to any
    UFW_RULE1=yes; write_state
    ufw route allow in on "$WG" out on "$WAN" from "$P2_WG" to any
    UFW_RULE2=yes; write_state
  fi
  systemctl daemon-reload
  systemctl enable --now "wg-quick@$WG"
  [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || { fail 'Forwarding unexpectedly disabled after start.'; return 1; }
  ip -4 route get 8.8.8.8 | grep -q " dev $WAN " || { fail 'Normal Internet route changed unexpectedly.'; return 1; }
  success=yes
  trap - RETURN
  info 'Ubuntu setup complete.'
  printf '\n=== COPY THIS PUBLIC KEY TO KEENETIC (never share private key) ===\n%s\n' "$(<"$PUBLIC")"
  printf '\nKeenetic: address %s; listen UDP %s; peer key = above; peer Allowed IPv4 = 0.0.0.0/0; peer Endpoint = blank.\n' "$P2_WG" "$PORT"
  printf 'Enable Internet access / DNS on Keenetic WG connection, and bind intended clients to its dedicated connection policy.\n'
  printf '\nStatus: sudo wg show ; sudo systemctl status wg-quick@wg0 --no-pager\n'
  printf 'The handshake will only appear after the Keenetic peer is configured and UDP %s is reachable.\n' "$PORT"
}

# -----------------------------------------------------------------------------
# Menu action 2: Delete (script-owned settings only)
# -----------------------------------------------------------------------------
delete_setup() {
  need_root || return 1
  load_state || return 0
  printf '\nThis will delete script-owned %s, key pair, forwarding sysctl, and firewall rules.\n' "$CONF"
  printf 'Other configuration and Keenetic settings are NOT affected.\n'
  confirm 'Delete the Ubuntu setup?' || { info 'Delete cancelled.'; return 0; }
  remove_owned
  if [[ -n "${PACKAGES_INSTALLED// /}" ]]; then
    printf '\nThe script originally installed packages:%s\n' "$PACKAGES_INSTALLED"
    if confirm 'Remove only those explicitly installed packages as well? (No autoremove)'; then
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive apt-get remove -y $PACKAGES_INSTALLED || warn 'Package removal failed; remove manually if necessary.'
    else
      warn 'Newly installed packages were retained at your request.'
    fi
  fi
  info 'Delete complete. Verify custom firewall rules if you changed the setup manually.'
}

# -----------------------------------------------------------------------------
# Menu action 3 / main interactive loop
# -----------------------------------------------------------------------------
main() {
  while :; do
    printf '\n=== Person 1 WireGuard Manager (Ubuntu 24.04, Keenetic UDP 7214) ===\n'
    printf '1) Setup\n'
    printf '2) Delete\n'
    printf '3) Exit\n'
    local choice
    read -r -p 'Choose [1-3]: ' choice || break
    case "$choice" in
      1)
        setup || warn 'Setup did not complete.'
        ;;
      2)
        delete_setup || warn 'Delete may be incomplete; inspect messages above.'
        ;;
      3)
        info 'Goodbye.'
        break
        ;;
      *)
        warn 'Invalid option. Choose 1, 2, or 3.'
        ;;
    esac
  done
}
main "$@"
