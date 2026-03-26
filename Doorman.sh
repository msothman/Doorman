#!/bin/bash
#==============================================================================
# Doorman — Enterprise Linux Security & RBAC Hardening Framework
#
# Automates CIS-benchmark-aligned server hardening with modular, idempotent
# deployment. Each module can run independently or as a full-stack deployment.
#
# Usage:
#   sudo ./Doorman.sh [OPTIONS]
#
# Options:
#   --dry-run           Preview changes without applying them
#   --modules LIST      Comma-separated modules to run (default: all)
#   --undo MODULE       Restore backup for a specific module
#   --status            Show current hardening status and exit
#   --config FILE       Path to external config file
#   --no-color          Disable colored output
#   -h, --help          Show this help message
#
# Supported: Debian/Ubuntu (apt), RHEL/CentOS/Fedora (dnf/yum)
#==============================================================================

set -euo pipefail
IFS=$'\n\t'

readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

#==============================================================================
#   CONFIGURATION DEFAULTS
#   Override via environment variables, --config file, or edit inline.
#==============================================================================

SECURITY_EMAIL="${DOORMAN_SECURITY_EMAIL:-security@company.com}"
COMPANY_NAME="${DOORMAN_COMPANY_NAME:-Company Name}"

SSH_PORT="${DOORMAN_SSH_PORT:-2222}"
ALLOWED_SSH_GROUPS="${DOORMAN_SSH_GROUPS:-enterprise-admins,security-admins,devops-engineers}"

MAX_LOGIN_ATTEMPTS="${DOORMAN_MAX_RETRIES:-3}"
BAN_TIME="${DOORMAN_BAN_TIME:-3600}"
FIND_TIME="${DOORMAN_FIND_TIME:-600}"
PASSWORD_MIN_LENGTH="${DOORMAN_PASS_MIN_LEN:-14}"
PASSWORD_MAX_AGE="${DOORMAN_PASS_MAX_AGE:-90}"
PASSWORD_MIN_AGE="${DOORMAN_PASS_MIN_AGE:-7}"
PASSWORD_WARN_DAYS="${DOORMAN_PASS_WARN:-14}"
AIDE_CHECK_TIME="${DOORMAN_AIDE_TIME:-02:00}"

# Format: "username:group:Full Name"
# Example: "jdoe:devops-engineers:Jane Doe"
ENTERPRISE_USERS=()

#==============================================================================
#   INTERNALS
#==============================================================================

LOG_FILE="/var/log/doorman/deployment-$(date +%F_%H%M%S).log"
CONFIG_DIR="/etc/doorman"
BACKUP_DIR="/var/backups/doorman"
STATE_DIR="/var/lib/doorman"
DRY_RUN=false
NO_COLOR=false
SELECTED_MODULES=""
UNDO_MODULE=""
SHOW_STATUS=false
CONFIG_FILE=""
PKG_MANAGER=""
MODULES_RUN=0
MODULES_SKIPPED=0
MODULES_FAILED=0
CLEANUP_FILES=()

# Trap: clean up partial state on interrupt
cleanup_on_exit() {
    local exit_code=$?
    if [ ${#CLEANUP_FILES[@]} -gt 0 ]; then
        local f
        for f in "${CLEANUP_FILES[@]}"; do
            rm -f "$f" 2>/dev/null
        done
    fi
    exit "$exit_code"
}
trap cleanup_on_exit INT TERM

# Colors — disabled if --no-color or non-interactive terminal
RED=""
GREEN=""
YELLOW=""
BLUE=""
CYAN=""
BOLD=""
DIM=""
RESET=""

init_colors() {
    if $NO_COLOR || [ ! -t 1 ]; then
        return 0
    fi
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
}

#==============================================================================
#   LOGGING
#==============================================================================

readonly SEP="==================================================================="
readonly SUBSEP="-------------------------------------------------------------------"

_log_file() {
    printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" >> "$LOG_FILE" 2>/dev/null || true
}

log_info() {
    printf '    %b[OK]%b   %s\n' "$GREEN" "$RESET" "$*"
    _log_file "INFO" "$*"
}

log_warn() {
    printf '    %b[WARN]%b %s\n' "$YELLOW" "$RESET" "$*"
    _log_file "WARN" "$*"
}

log_error() {
    printf '    %b[FAIL]%b %s\n' "$RED" "$RESET" "$*"
    _log_file "ERROR" "$*"
}

log_step() {
    local msg="$*"
    local pad_len=$((67 - ${#msg} - 5))
    local padding
    if [ "$pad_len" -gt 0 ]; then
        padding="$(printf '%*s' "$pad_len" '' | tr ' ' '-')"
    else
        padding=""
    fi
    printf '\n%b--- %s %s%b\n' "$BOLD" "$msg" "$padding" "$RESET"
    _log_file "STEP" "$msg"
}

log_sub() {
    printf '    %s\n' "$*"
    _log_file "INFO" "$*"
}

log_dry() {
    if $DRY_RUN; then
        printf '    %b[PREVIEW]%b %s\n' "$YELLOW" "$RESET" "$*"
        return 0
    fi
    return 1
}

error_exit() {
    log_error "$*"
    exit 1
}

#==============================================================================
#   UTILITY FUNCTIONS
#==============================================================================

print_banner() {
    printf '\n%b%s%b\n' "$BOLD" "$SEP" "$RESET"
    printf '%b  DOORMAN v%s%b\n' "$BOLD" "$VERSION" "$RESET"
    printf '  Enterprise Security Hardening Framework\n'
    printf '%s\n' "$SUBSEP"
    printf '  Host:     %s\n' "$(hostname)"
    printf '  Kernel:   %s\n' "$(uname -r)"
    printf '  Date:     %s\n' "$(date '+%F %T %Z')"
    printf '%b%s%b\n\n' "$BOLD" "$SEP" "$RESET"
}

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    else
        error_exit "Unsupported package manager. Requires apt, dnf, or yum."
    fi
    log_sub "Detected package manager: ${PKG_MANAGER}"
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -yq "$@" ;;
        dnf) dnf install -y "$@" ;;
        yum) yum install -y "$@" ;;
    esac
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "Root privileges required. Run with: sudo ${SCRIPT_NAME}"
    fi
}

stamp_module() {
    $DRY_RUN && return 0
    local module="$1"
    mkdir -p "$STATE_DIR"
    date '+%F %T' > "${STATE_DIR}/${module}.applied"
}

module_applied() {
    [ -f "${STATE_DIR}/${1}.applied" ]
}

backup_file() {
    local src="$1"
    if [ -f "$src" ]; then
        local name
        name="$(basename "$src")"
        mkdir -p "$BACKUP_DIR"
        cp -p "$src" "${BACKUP_DIR}/${name}.bak.$(date +%F_%H%M%S)"
        log_sub "Backed up ${src}"
    fi
}

should_run_module() {
    local module="$1"
    if [ -n "$SELECTED_MODULES" ]; then
        echo ",$SELECTED_MODULES," | grep -q ",$module," && return 0 || return 1
    fi
    return 0
}

add_cron_entry() {
    local schedule="$1" command="$2" marker="$3"
    if ! crontab -l 2>/dev/null | grep -qF "$marker"; then
        (crontab -l 2>/dev/null; echo "${schedule} ${command} # ${marker}") | crontab -
        log_sub "Added cron: ${marker}"
    else
        log_sub "Cron already exists: ${marker}"
    fi
}

validate_users_config() {
    local errors=0
    local entry
    for entry in "${ENTERPRISE_USERS[@]}"; do
        local fields
        fields=$(echo "$entry" | awk -F: '{print NF}')
        if [ "$fields" -ne 3 ]; then
            log_error "Invalid user entry (need user:group:name): ${entry}"
            errors=$((errors + 1))
        fi
    done
    [ "$errors" -eq 0 ]
}

validate_ssh_port() {
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        error_exit "Invalid SSH port: ${SSH_PORT} (must be 1-65535)"
    fi
}

# Detect the correct auth log path for this distribution
detect_auth_log() {
    if [ -f /var/log/auth.log ]; then
        echo "/var/log/auth.log"
    elif [ -f /var/log/secure ]; then
        echo "/var/log/secure"
    else
        echo "/var/log/auth.log"
    fi
}

# Detect the appropriate firewall ban action for fail2ban
detect_ban_action() {
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "ufw"
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        echo "firewallcmd-ipset"
    else
        echo "iptables-multiport"
    fi
}

#==============================================================================
#   MODULE: PACKAGE INSTALLATION
#   Ref: CIS 1.2 — Ensure package manager repositories are configured
#==============================================================================
mod_packages() {
    log_step "Installing security packages"

    if log_dry "Would install security packages via ${PKG_MANAGER}"; then return 0; fi

    case "$PKG_MANAGER" in
        apt)
            apt-get update -qq
            apt-get upgrade -yq
            pkg_install \
                fail2ban aide mailutils rsyslog auditd audispd-plugins \
                logwatch rkhunter chkrootkit clamav clamav-daemon \
                unattended-upgrades apt-listchanges libpam-pwquality \
                ufw curl wget jq net-tools psmisc lsof \
                apparmor apparmor-utils acct sysstat
            systemctl enable --now unattended-upgrades
            ;;
        dnf|yum)
            pkg_install epel-release || true
            pkg_install \
                fail2ban aide mailx rsyslog audit \
                logwatch rkhunter clamav clamav-update \
                firewalld curl wget jq net-tools psmisc lsof \
                libpwquality sysstat
            ;;
    esac

    stamp_module "packages"
    log_info "Security packages installed"
}

#==============================================================================
#   MODULE: RBAC GROUPS
#   Ref: CIS 5.2 — Ensure system accounts are secured
#==============================================================================
mod_rbac_groups() {
    log_step "Configuring RBAC groups"

    local groups=(
        "enterprise-admins"
        "security-admins"
        "system-admins"
        "devops-engineers"
        "developers"
        "qa-engineers"
        "data-analysts"
        "auditors"
        "interns"
    )

    local g
    for g in "${groups[@]}"; do
        if log_dry "Would create group: ${g}"; then continue; fi
        if getent group "$g" &>/dev/null; then
            log_sub "Group exists: ${g}"
        else
            groupadd "$g"
            log_sub "Created group: ${g}"
        fi
    done

    stamp_module "rbac"
    log_info "RBAC groups configured"
}

#==============================================================================
#   MODULE: USER PROVISIONING
#   Ref: CIS 5.4 — Ensure password creation requirements are configured
#==============================================================================
mod_users() {
    log_step "Provisioning enterprise users"

    if [ "${#ENTERPRISE_USERS[@]}" -eq 0 ]; then
        log_warn "No users defined in ENTERPRISE_USERS -- skipping"
        return 0
    fi

    validate_users_config || error_exit "Fix user configuration before continuing"

    local user_info
    for user_info in "${ENTERPRISE_USERS[@]}"; do
        local u g fullname
        u="$(echo "$user_info" | cut -d: -f1)"
        g="$(echo "$user_info" | cut -d: -f2)"
        fullname="$(echo "$user_info" | cut -d: -f3)"

        if log_dry "Would create user: ${u} in group ${g}"; then continue; fi

        if id "$u" &>/dev/null; then
            log_sub "User exists: ${u} -- ensuring group membership"
            usermod -aG "$g" "$u"
        else
            # Verify the target group exists before creating the user
            if ! getent group "$g" &>/dev/null; then
                log_error "Group '${g}' does not exist -- run the rbac module first"
                return 1
            fi

            useradd -m -s /bin/bash -c "$fullname" -G "$g" "$u"
            local pass
            pass="$(openssl rand -base64 16)"
            echo "${u}:${pass}" | chpasswd
            chage -d 0 "$u"
            chage -M "$PASSWORD_MAX_AGE" -m "$PASSWORD_MIN_AGE" -W "$PASSWORD_WARN_DAYS" "$u"
            log_sub "Created user: ${u} (group: ${g})"

            # Credentials printed to stdout only -- never written to disk
            printf '    %b[CRED]%b %s:%s (forced reset on first login)\n' \
                "$YELLOW" "$RESET" "$u" "$pass"
        fi
    done

    stamp_module "users"
    log_info "User provisioning complete"
}

#==============================================================================
#   MODULE: SUDOERS
#   Ref: CIS 5.3 — Ensure sudo is installed and configured
#==============================================================================
mod_sudoers() {
    log_step "Configuring role-based sudoers"

    if log_dry "Would write /etc/sudoers.d/01-doorman-rbac"; then return 0; fi

    backup_file "/etc/sudoers"

    cat > /etc/sudoers.d/01-doorman-rbac <<'SUDOERS'
# Doorman RBAC -- Granular privilege escalation by role
# Ref: CIS 5.3

Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    passwd_timeout=1
Defaults    timestamp_timeout=5

# Enterprise admins -- full access, password required
%enterprise-admins ALL=(ALL:ALL) ALL

# Security admins -- full access for incident response
%security-admins   ALL=(ALL:ALL) ALL

# System admins -- service management
%system-admins     ALL=(ALL) NOPASSWD: /usr/bin/systemctl start *, \
                                       /usr/bin/systemctl stop *, \
                                       /usr/bin/systemctl restart *, \
                                       /usr/bin/systemctl status *, \
                                       /usr/bin/journalctl

# DevOps -- deploy and service control
%devops-engineers  ALL=(ALL) NOPASSWD: /usr/bin/systemctl, \
                                       /usr/bin/journalctl, \
                                       /usr/bin/docker, \
                                       /usr/bin/crictl

# Developers -- read-only service inspection
%developers        ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, \
                                       /usr/bin/journalctl

# Auditors -- read-only log and audit access
%auditors          ALL=(ALL) NOPASSWD: /usr/bin/journalctl, \
                                       /usr/bin/last, \
                                       /usr/bin/w, \
                                       /usr/bin/ausearch, \
                                       /usr/bin/aureport

# Interns -- status checks only
%interns           ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
SUDOERS

    chmod 440 /etc/sudoers.d/01-doorman-rbac
    visudo -c || {
        rm -f /etc/sudoers.d/01-doorman-rbac
        error_exit "Sudoers syntax invalid -- removed broken config"
    }

    stamp_module "sudoers"
    log_info "Sudoers configured with role-based policies"
}

#==============================================================================
#   MODULE: SSH HARDENING
#   Ref: CIS 5.2.1-5.2.23 — SSH Server Configuration
#==============================================================================
mod_ssh() {
    log_step "Hardening SSH daemon"

    if log_dry "Would write hardened sshd_config"; then return 0; fi

    validate_ssh_port
    backup_file "/etc/ssh/sshd_config"

    # Register for cleanup in case of interrupt during write
    CLEANUP_FILES+=("/etc/ssh/sshd_config.doorman-tmp")

    # AllowGroups requires space-separated values, not commas
    local ssh_groups="${ALLOWED_SSH_GROUPS//,/ }"

    cat > /etc/ssh/sshd_config <<EOF
# Doorman SSH Hardening -- CIS Benchmark Aligned
# Generated: $(date '+%F %T')

#--- Network ---
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0

#--- Authentication (CIS 5.2.5-5.2.10) ---
PermitRootLogin no
MaxAuthTries ${MAX_LOGIN_ATTEMPTS}
MaxSessions 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AuthenticationMethods publickey

#--- Access Control (CIS 5.2.4) ---
AllowGroups ${ssh_groups}
DenyUsers root
LoginGraceTime 30
StrictModes yes

#--- Cryptographic Policy (CIS 5.2.13-5.2.16) ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

#--- Forwarding (CIS 5.2.17-5.2.22) ---
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
X11Forwarding no

#--- Session ---
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
PermitUserEnvironment no

#--- Logging (CIS 5.2.3) ---
SyslogFacility AUTH
LogLevel VERBOSE

#--- Misc ---
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression no
UseDNS no
Banner /etc/issue.net
EOF

    # Validate syntax before restarting -- auto-rollback on failure
    if ! sshd -t; then
        local bak
        bak="$(ls -t "${BACKUP_DIR}"/sshd_config.bak.* 2>/dev/null | head -1)"
        if [ -n "$bak" ]; then
            cp "$bak" /etc/ssh/sshd_config
            log_error "sshd_config invalid -- restored from backup"
        fi
        return 1
    fi

    if ! systemctl restart sshd; then
        local bak
        bak="$(ls -t "${BACKUP_DIR}"/sshd_config.bak.* 2>/dev/null | head -1)"
        if [ -n "$bak" ]; then
            cp "$bak" /etc/ssh/sshd_config
            systemctl restart sshd || true
            log_error "SSH restart failed -- restored from backup"
        fi
        return 1
    fi

    stamp_module "ssh"
    log_info "SSH hardened (port ${SSH_PORT}, pubkey-only, modern ciphers)"
}

#==============================================================================
#   MODULE: FIREWALL (UFW / firewalld)
#   Ref: CIS 3.5 — Ensure firewall is configured
#==============================================================================
mod_firewall() {
    log_step "Configuring firewall"

    if log_dry "Would configure firewall rules"; then return 0; fi

    if command -v ufw &>/dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw limit "${SSH_PORT}/tcp" comment "Doorman: SSH rate-limited"
        ufw allow 80/tcp comment "HTTP"
        ufw allow 443/tcp comment "HTTPS"
        ufw logging medium
        ufw --force enable
        log_info "UFW configured (default-deny + SSH/HTTP/HTTPS)"

    elif command -v firewall-cmd &>/dev/null; then
        systemctl enable --now firewalld
        # Add SSH port BEFORE changing default zone to avoid lockout
        firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
        # Safe to change default zone now that SSH is allowed
        firewall-cmd --set-default-zone=drop
        firewall-cmd --reload
        log_info "firewalld configured (drop zone + SSH/HTTP/HTTPS)"

    else
        log_warn "No firewall tool found -- install ufw or firewalld"
        return 1
    fi

    stamp_module "firewall"
}

#==============================================================================
#   MODULE: FAIL2BAN
#   Ref: CIS — Brute-force protection
#==============================================================================
mod_fail2ban() {
    log_step "Configuring Fail2Ban"

    if log_dry "Would write /etc/fail2ban/jail.d/doorman.conf"; then return 0; fi

    mkdir -p /etc/fail2ban/jail.d

    local auth_log ban_action
    auth_log="$(detect_auth_log)"
    ban_action="$(detect_ban_action)"

    cat > /etc/fail2ban/jail.d/doorman.conf <<EOF
# Doorman Fail2Ban Configuration

[DEFAULT]
banaction = ${ban_action}
banaction_allports = ${ban_action}
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = ${auth_log}
maxretry = ${MAX_LOGIN_ATTEMPTS}
findtime = ${FIND_TIME}
bantime  = ${BAN_TIME}

# Recidive jail -- escalates repeat offenders to 7-day bans
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ${ban_action}
bantime  = 604800
findtime = 86400
maxretry = 3
EOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban

    stamp_module "fail2ban"
    log_info "Fail2Ban configured (ban=${BAN_TIME}s, recidive=7d)"
}

#==============================================================================
#   MODULE: AUDITD
#   Ref: CIS 4.1 — Configure System Accounting (auditd)
#==============================================================================
mod_auditd() {
    log_step "Configuring audit rules"

    if log_dry "Would write /etc/audit/rules.d/99-doorman.rules"; then return 0; fi

    mkdir -p /etc/audit/rules.d

    cat > /etc/audit/rules.d/99-doorman.rules <<'AUDIT'
# Doorman Audit Rules -- CIS 4.1.3-4.1.17

# Self-audit -- detect tampering with audit configuration
-w /etc/audit/ -p wa -k audit-config
-w /etc/libaudit.conf -p wa -k audit-config
-w /etc/audisp/ -p wa -k audit-config

# Identity and authentication (CIS 4.1.4-4.1.6)
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Privilege escalation (CIS 4.1.10-4.1.11)
-w /etc/sudoers -p wa -k privilege-escalation
-w /etc/sudoers.d/ -p wa -k privilege-escalation
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege-use
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k privilege-use

# Network configuration changes (CIS 4.1.13)
-w /etc/hosts -p wa -k network-config
-w /etc/sysconfig/network -p wa -k network-config
-w /etc/network/ -p wa -k network-config
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network-config

# Login and session tracking (CIS 4.1.8-4.1.9)
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session

# Discretionary access control (CIS 4.1.14)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm-change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm-change
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm-change
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm-change

# Unauthorized file access attempts (CIS 4.1.15)
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access-denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access-denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access-denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access-denied

# Kernel module loading (CIS 4.1.16)
-w /sbin/insmod -p x -k kernel-modules
-w /sbin/rmmod -p x -k kernel-modules
-w /sbin/modprobe -p x -k kernel-modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel-modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k kernel-modules

# Cron and scheduled jobs
-w /etc/crontab -p wa -k cron-config
-w /etc/cron.d/ -p wa -k cron-config
-w /etc/cron.daily/ -p wa -k cron-config
-w /etc/cron.hourly/ -p wa -k cron-config

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd-config

# Make audit configuration immutable -- requires reboot to change (must be last)
-e 2
AUDIT

    systemctl enable --now auditd
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/99-doorman.rules

    stamp_module "auditd"
    log_info "Audit rules loaded ($(auditctl -l 2>/dev/null | wc -l) rules active)"
}

#==============================================================================
#   MODULE: KERNEL / SYSCTL HARDENING
#   Ref: CIS 3.1-3.3 — Network Parameters
#==============================================================================
mod_sysctl() {
    log_step "Applying kernel hardening (sysctl)"

    if log_dry "Would write /etc/sysctl.d/99-doorman.conf"; then return 0; fi

    backup_file "/etc/sysctl.conf"

    cat > /etc/sysctl.d/99-doorman.conf <<'SYSCTL'
# Doorman Kernel Hardening -- CIS 3.1-3.3

#--- IP Forwarding & Routing (CIS 3.1.1-3.1.2) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

#--- Packet Redirect (CIS 3.2.1-3.2.2) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

#--- Logging & Source Routing (CIS 3.2.3-3.2.5) ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

#--- ICMP Hardening (CIS 3.2.6-3.2.7) ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

#--- SYN Flood Protection (CIS 3.2.8) ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

#--- Reverse Path Filtering (CIS 3.2.9) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

#--- IPv6 Router Advertisements (CIS 3.3.1) ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

#--- Address Space Layout Randomization ---
kernel.randomize_va_space = 2

#--- Core Dump Restrictions ---
fs.suid_dumpable = 0

#--- Restrict dmesg and kernel pointers ---
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

#--- Restrict ptrace scope (prevent process snooping) ---
kernel.yama.ptrace_scope = 2

#--- Restrict BPF and perf ---
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
SYSCTL

    sysctl --system --quiet 2>/dev/null

    stamp_module "sysctl"
    log_info "Kernel parameters hardened ($(grep -c '=' /etc/sysctl.d/99-doorman.conf) settings applied)"
}

#==============================================================================
#   MODULE: PASSWORD POLICY
#   Ref: CIS 5.4.1 — Ensure password creation requirements
#==============================================================================
mod_password_policy() {
    log_step "Enforcing password policy"

    if log_dry "Would configure PAM pwquality and login.defs"; then return 0; fi

    # login.defs -- system-wide password aging (CIS 5.5.1.1-5.5.1.4)
    if [ -f /etc/login.defs ]; then
        backup_file "/etc/login.defs"
        # Use anchored patterns; append if the setting is missing
        local param
        for param in \
            "PASS_MAX_DAYS:${PASSWORD_MAX_AGE}" \
            "PASS_MIN_DAYS:${PASSWORD_MIN_AGE}" \
            "PASS_MIN_LEN:${PASSWORD_MIN_LENGTH}" \
            "PASS_WARN_AGE:${PASSWORD_WARN_DAYS}"; do
            local key="${param%%:*}" val="${param##*:}"
            if grep -qE "^${key}" /etc/login.defs; then
                sed -i "s/^${key}.*/${key}   ${val}/" /etc/login.defs
            else
                echo "${key}   ${val}" >> /etc/login.defs
            fi
        done
        log_sub "login.defs: max=${PASSWORD_MAX_AGE}d, min=${PASSWORD_MIN_AGE}d, len=${PASSWORD_MIN_LENGTH}, warn=${PASSWORD_WARN_DAYS}d"
    fi

    # PAM pwquality -- password complexity (CIS 5.4.1)
    if [ -f /etc/security/pwquality.conf ]; then
        backup_file "/etc/security/pwquality.conf"
        cat > /etc/security/pwquality.conf <<EOF
# Doorman Password Quality -- CIS 5.4.1
minlen = ${PASSWORD_MIN_LENGTH}
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
enforcing = 1
EOF
        log_sub "pwquality: minlen=${PASSWORD_MIN_LENGTH}, 3+ char classes, no repeats"
    fi

    stamp_module "password-policy"
    log_info "Password policy enforced"
}

#==============================================================================
#   MODULE: AIDE (File Integrity Monitoring)
#   Ref: CIS 1.3 — Ensure AIDE is installed
#==============================================================================
mod_aide() {
    log_step "Initializing AIDE file integrity monitoring"

    if log_dry "Would initialize AIDE database and schedule daily checks"; then return 0; fi

    if ! module_applied "aide"; then
        log_sub "Building AIDE database (this may take several minutes)..."
        aide --init 2>/dev/null || { log_warn "AIDE init failed -- check configuration"; return 1; }
        if [ -f /var/lib/aide/aide.db.new ]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
        log_sub "AIDE database initialized"
    else
        log_sub "AIDE database exists -- run 'aide --update' to refresh"
    fi

    add_cron_entry \
        "0 ${AIDE_CHECK_TIME%:*} * * *" \
        "/usr/bin/aide --check 2>&1 | /usr/bin/mail -s \"[Doorman] AIDE Report - \$(hostname)\" ${SECURITY_EMAIL}" \
        "doorman-aide-check"

    stamp_module "aide"
    log_info "AIDE configured (daily check at ${AIDE_CHECK_TIME})"
}

#==============================================================================
#   MODULE: ROOTKIT / MALWARE DETECTION
#   Ref: CIS 1.4 — Ensure additional security software is configured
#==============================================================================
mod_rootkit() {
    log_step "Configuring rootkit and malware detection"

    if log_dry "Would configure rkhunter, chkrootkit, and ClamAV"; then return 0; fi

    if command -v rkhunter &>/dev/null; then
        rkhunter --update 2>/dev/null || true
        rkhunter --propupd 2>/dev/null || true
        add_cron_entry \
            "0 3 * * *" \
            "/usr/bin/rkhunter --check --skip-keypress --report-warnings-only 2>&1 | /usr/bin/mail -s \"[Doorman] RKHunter - \$(hostname)\" ${SECURITY_EMAIL}" \
            "doorman-rkhunter"
        log_sub "rkhunter: daily scan at 03:00"
    fi

    if command -v chkrootkit &>/dev/null; then
        add_cron_entry \
            "30 3 * * *" \
            "/usr/sbin/chkrootkit 2>&1 | /usr/bin/mail -s \"[Doorman] chkrootkit - \$(hostname)\" ${SECURITY_EMAIL}" \
            "doorman-chkrootkit"
        log_sub "chkrootkit: daily scan at 03:30"
    fi

    if command -v freshclam &>/dev/null; then
        freshclam 2>/dev/null || true
        mkdir -p /var/lib/doorman/quarantine
        add_cron_entry \
            "0 4 * * 0" \
            "/usr/bin/clamscan -r /home /tmp /var --infected --move=/var/lib/doorman/quarantine --quiet 2>&1 | /usr/bin/mail -s \"[Doorman] ClamAV - \$(hostname)\" ${SECURITY_EMAIL}" \
            "doorman-clamav"
        log_sub "ClamAV: weekly scan Sundays at 04:00 (quarantine: /var/lib/doorman/quarantine)"
    fi

    stamp_module "rootkit"
    log_info "Rootkit/malware detection configured"
}

#==============================================================================
#   MODULE: LOGGING & MONITORING
#   Ref: CIS 4.2 — Configure Logging
#==============================================================================
mod_logging() {
    log_step "Configuring centralized logging"

    if log_dry "Would configure rsyslog and logrotate"; then return 0; fi

    systemctl enable --now rsyslog 2>/dev/null || true

    # Process accounting
    if command -v accton &>/dev/null; then
        local acct_file="/var/log/account/pacct"
        mkdir -p "$(dirname "$acct_file")"
        touch "$acct_file"
        accton "$acct_file" 2>/dev/null || true
        log_sub "Process accounting enabled (${acct_file})"
    fi

    # Logrotate for doorman and sudo logs
    cat > /etc/logrotate.d/doorman <<'LOGROTATE'
/var/log/doorman/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
LOGROTATE

    chmod -R g-wx,o-rwx /var/log/doorman/ 2>/dev/null || true

    stamp_module "logging"
    log_info "Logging and rotation configured"
}

#==============================================================================
#   MODULE: LEGAL BANNER
#   Ref: CIS 1.7 — Ensure login warning banner is configured
#==============================================================================
mod_banner() {
    log_step "Setting login warning banner"

    if log_dry "Would write /etc/issue.net and /etc/issue"; then return 0; fi

    cat > /etc/issue.net <<EOF
***************************************************************************
*                         AUTHORIZED ACCESS ONLY                          *
*                                                                         *
*  This system is the property of ${COMPANY_NAME}.                        *
*  Unauthorized access is prohibited and will be prosecuted to the        *
*  fullest extent of the law. All activity is monitored and logged.       *
*                                                                         *
*  By continuing, you consent to monitoring and agree to comply with      *
*  all applicable security policies.                                      *
***************************************************************************
EOF

    cp /etc/issue.net /etc/issue

    stamp_module "banner"
    log_info "Legal warning banner configured"
}

#==============================================================================
#   STATUS REPORT
#==============================================================================
show_status() {
    print_banner

    printf '%b  MODULE STATUS%b\n' "$BOLD" "$RESET"
    printf '%s\n' "$SUBSEP"

    local modules=(packages rbac users sudoers ssh firewall fail2ban auditd sysctl aide rootkit logging password-policy banner)
    local applied=0
    local total=${#modules[@]}

    local mod
    for mod in "${modules[@]}"; do
        if module_applied "$mod"; then
            local ts
            ts="$(cat "${STATE_DIR}/${mod}.applied" 2>/dev/null)"
            printf '  %b  APPLIED %b  %-20s  %b%s%b\n' "$GREEN" "$RESET" "$mod" "$DIM" "$ts" "$RESET"
            applied=$((applied + 1))
        else
            printf '  %b  PENDING %b  %s\n' "$RED" "$RESET" "$mod"
        fi
    done

    printf '%s\n' "$SUBSEP"
    printf '  %b%s/%s modules applied%b\n' "$BOLD" "$applied" "$total" "$RESET"

    printf '\n%b  SERVICE STATUS%b\n' "$BOLD" "$RESET"
    printf '%s\n' "$SUBSEP"

    # SSH
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        local port
        port="$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
        printf '  %b  ACTIVE  %b  SSH (port %s)\n' "$GREEN" "$RESET" "${port:-22}"
    else
        printf '  %b  DOWN    %b  SSH\n' "$RED" "$RESET"
    fi

    # Firewall
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        printf '  %b  ACTIVE  %b  UFW\n' "$GREEN" "$RESET"
    elif firewall-cmd --state 2>/dev/null | grep -q "running"; then
        printf '  %b  ACTIVE  %b  firewalld\n' "$GREEN" "$RESET"
    else
        printf '  %b  DOWN    %b  Firewall\n' "$RED" "$RESET"
    fi

    # Fail2Ban
    if systemctl is-active fail2ban &>/dev/null; then
        local jails
        jails="$(fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $NF}')"
        printf '  %b  ACTIVE  %b  Fail2Ban (%s jails)\n' "$GREEN" "$RESET" "${jails:-0}"
    else
        printf '  %b  DOWN    %b  Fail2Ban\n' "$RED" "$RESET"
    fi

    # Auditd
    if systemctl is-active auditd &>/dev/null; then
        local rules
        rules="$(auditctl -l 2>/dev/null | wc -l)"
        printf '  %b  ACTIVE  %b  Auditd (%s rules)\n' "$GREEN" "$RESET" "$rules"
    else
        printf '  %b  DOWN    %b  Auditd\n' "$RED" "$RESET"
    fi

    printf '%s\n\n' "$SUBSEP"
}

#==============================================================================
#   UNDO / RESTORE
#==============================================================================
undo_module() {
    local module="$1"

    require_root
    log_step "Restoring backup for: ${module}"

    case "$module" in
        ssh)
            local bak
            bak="$(ls -t "${BACKUP_DIR}"/sshd_config.bak.* 2>/dev/null | head -1)"
            [ -n "$bak" ] || error_exit "No SSH backup found in ${BACKUP_DIR}"
            cp "$bak" /etc/ssh/sshd_config
            sshd -t && systemctl restart sshd
            rm -f "${STATE_DIR}/ssh.applied"
            log_info "SSH config restored from ${bak}"
            ;;
        sudoers)
            rm -f /etc/sudoers.d/01-doorman-rbac
            rm -f "${STATE_DIR}/sudoers.applied"
            log_info "Doorman sudoers rules removed"
            ;;
        sysctl)
            rm -f /etc/sysctl.d/99-doorman.conf
            sysctl --system --quiet 2>/dev/null
            rm -f "${STATE_DIR}/sysctl.applied"
            log_info "Doorman sysctl rules removed, defaults restored"
            ;;
        firewall)
            if command -v ufw &>/dev/null; then
                ufw --force reset
                ufw --force disable
            elif command -v firewall-cmd &>/dev/null; then
                firewall-cmd --set-default-zone=public
                firewall-cmd --reload
            fi
            rm -f "${STATE_DIR}/firewall.applied"
            log_info "Firewall rules reset"
            ;;
        fail2ban)
            rm -f /etc/fail2ban/jail.d/doorman.conf
            systemctl restart fail2ban 2>/dev/null || true
            rm -f "${STATE_DIR}/fail2ban.applied"
            log_info "Doorman fail2ban rules removed"
            ;;
        auditd)
            rm -f /etc/audit/rules.d/99-doorman.rules
            augenrules --load 2>/dev/null || true
            rm -f "${STATE_DIR}/auditd.applied"
            log_info "Doorman audit rules removed"
            ;;
        banner)
            echo "" > /etc/issue.net
            echo "" > /etc/issue
            rm -f "${STATE_DIR}/banner.applied"
            log_info "Login banner cleared"
            ;;
        *)
            error_exit "Unknown module: ${module} (undoable: ssh, sudoers, sysctl, firewall, fail2ban, auditd, banner)"
            ;;
    esac
}

#==============================================================================
#   DEPLOYMENT REPORT
#==============================================================================
print_report() {
    printf '\n%b%s%b\n' "$BOLD" "$SEP" "$RESET"
    if $DRY_RUN; then
        printf '%b  PREVIEW COMPLETE%b\n' "$BOLD" "$RESET"
    elif [ "$MODULES_FAILED" -eq 0 ]; then
        printf '%b  DEPLOYMENT COMPLETE%b\n' "$BOLD" "$RESET"
    else
        printf '%b  DEPLOYMENT FINISHED WITH ERRORS%b\n' "$BOLD" "$RESET"
    fi
    printf '%s\n' "$SUBSEP"
    printf '  Host:       %s\n' "$(hostname)"
    printf '  Date:       %s\n' "$(date '+%F %T %Z')"
    printf '  Kernel:     %s\n' "$(uname -r)"
    printf '  Log:        %s\n' "$LOG_FILE"
    printf '\n'
    printf '  Applied:    %b%s%b\n' "$GREEN" "$MODULES_RUN" "$RESET"
    printf '  Skipped:    %b%s%b\n' "$YELLOW" "$MODULES_SKIPPED" "$RESET"
    printf '  Failed:     %b%s%b\n' "$RED" "$MODULES_FAILED" "$RESET"
    if $DRY_RUN; then
        printf '\n  %b[PREVIEW] No changes were applied to the system%b\n' "$YELLOW" "$RESET"
    fi
    printf '%b%s%b\n\n' "$BOLD" "$SEP" "$RESET"
}

#==============================================================================
#   CLI ARGUMENT PARSER
#==============================================================================
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)    DRY_RUN=true ;;
            --no-color)   NO_COLOR=true ;;
            --modules)    [ $# -ge 2 ] || error_exit "--modules requires a value"; SELECTED_MODULES="$2"; shift ;;
            --undo)       [ $# -ge 2 ] || error_exit "--undo requires a module name"; UNDO_MODULE="$2"; shift ;;
            --status)     SHOW_STATUS=true ;;
            --config)     [ $# -ge 2 ] || error_exit "--config requires a file path"; CONFIG_FILE="$2"; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            error_exit "Unknown option: $1 (try --help)" ;;
        esac
        shift
    done
}

usage() {
    cat <<EOF
Doorman v${VERSION} -- Enterprise Linux Security Hardening

Usage: sudo ${SCRIPT_NAME} [OPTIONS]

Options:
  --dry-run              Preview all changes without applying
  --modules LIST         Run specific modules (comma-separated)
  --undo MODULE          Restore backup for a module
  --status               Show hardening status and exit
  --config FILE          Load external configuration file
  --no-color             Disable colored output
  -h, --help             Show this help

Modules:
  packages, rbac, users, sudoers, ssh, firewall, fail2ban,
  auditd, sysctl, password-policy, aide, rootkit, logging, banner

Undoable modules:
  ssh, sudoers, sysctl, firewall, fail2ban, auditd, banner

Environment Variables:
  DOORMAN_SECURITY_EMAIL    Security team email
  DOORMAN_COMPANY_NAME      Organization name (used in banners)
  DOORMAN_SSH_PORT           SSH port (default: 2222)
  DOORMAN_SSH_GROUPS         Allowed SSH groups, comma-separated
  DOORMAN_MAX_RETRIES        Max SSH login attempts (default: 3)
  DOORMAN_BAN_TIME           Fail2Ban ban duration in seconds (default: 3600)
  DOORMAN_PASS_MIN_LEN       Minimum password length (default: 14)
  DOORMAN_PASS_MAX_AGE       Password max age in days (default: 90)

Examples:
  sudo ./Doorman.sh                            # Full deployment
  sudo ./Doorman.sh --dry-run                  # Preview changes
  sudo ./Doorman.sh --modules ssh,firewall     # SSH + firewall only
  sudo ./Doorman.sh --undo ssh                 # Restore SSH config
  sudo ./Doorman.sh --status                   # Check applied state
EOF
}

#==============================================================================
#   MAIN
#==============================================================================
main() {
    parse_args "$@"
    init_colors

    # Load external config if specified
    if [ -n "$CONFIG_FILE" ]; then
        if [ -f "$CONFIG_FILE" ]; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE"
        else
            error_exit "Config not found: ${CONFIG_FILE}"
        fi
    fi

    print_banner

    # Status mode -- no root required
    if $SHOW_STATUS; then
        show_status
        exit 0
    fi

    # Undo mode
    if [ -n "$UNDO_MODULE" ]; then
        undo_module "$UNDO_MODULE"
        exit 0
    fi

    # Root check (skip for dry-run to allow safe previews)
    if ! $DRY_RUN; then
        require_root
        mkdir -p /var/log/doorman "$CONFIG_DIR" "$BACKUP_DIR" "$STATE_DIR"
    fi

    detect_pkg_manager
    $DRY_RUN && printf '    %b[PREVIEW]%b Running in preview mode -- no changes will be applied\n\n' "$YELLOW" "$RESET"

    # Module execution
    local modules=(
        "packages:mod_packages"
        "rbac:mod_rbac_groups"
        "users:mod_users"
        "sudoers:mod_sudoers"
        "ssh:mod_ssh"
        "firewall:mod_firewall"
        "fail2ban:mod_fail2ban"
        "auditd:mod_auditd"
        "sysctl:mod_sysctl"
        "password-policy:mod_password_policy"
        "aide:mod_aide"
        "rootkit:mod_rootkit"
        "logging:mod_logging"
        "banner:mod_banner"
    )

    local entry
    for entry in "${modules[@]}"; do
        local name="${entry%%:*}"
        local func="${entry##*:}"

        if ! should_run_module "$name"; then
            MODULES_SKIPPED=$((MODULES_SKIPPED + 1))
            continue
        fi

        if $func; then
            MODULES_RUN=$((MODULES_RUN + 1))
        else
            MODULES_FAILED=$((MODULES_FAILED + 1))
            log_error "Module failed: ${name}"
        fi
    done

    print_report
}

main "$@"
