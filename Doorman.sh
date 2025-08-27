#!/bin/bash
#==============================================================================
# Project Doorman (ENTERPRISE SECURITY & RBAC DEPLOYMENT SCRIPT)
# 
# INSTRUCTIONS:
# 1. Customize the CONFIGURATION section below with your organization's settings
# 2. Run as root: sudo ./enterprise-security-setup.sh
#==============================================================================

#==============================================================================
#   CONFIGURATION - CUSTOMIZE THESE SETTINGS
#==============================================================================

SECURITY_EMAIL="security@company.com"
ADMIN_EMAIL="admin@company.com"
COMPANY_NAME="Company Name"

SSH_PORT="2222"
ALLOWED_SSH_GROUPS="enterprise-admins,security-admins,devops-engineers"

MAX_LOGIN_ATTEMPTS="3"
BAN_TIME="3600"
PASSWORD_MIN_LENGTH="12"
AIDE_CHECK_TIME="02:00"

ENTERPRISE_USERS=(
     "username:group:email"
)

#==============================================================================
#  DEPLOYMENT
#==============================================================================

set -euo pipefail
IFS=$'\n\t'

LOG_FILE="/var/log/enterprise-security-deployment.log"
CONFIG_DIR="/etc/enterprise-security"
BACKUP_DIR="/var/backups/enterprise-security"

mkdir -p "$CONFIG_DIR" "$BACKUP_DIR" /var/log/enterprise-security

log() {
    echo "$(date '+%F %T') [INFO] $*" | tee -a "$LOG_FILE"
}

error_exit() {
    echo "$(date '+%F %T') [ERROR] $*" | tee -a "$LOG_FILE"
    exit 1
}

#------------------------------------------------------------------------------
# PREREQUISITES CHECK
#------------------------------------------------------------------------------
check_prereqs() {
    [ "$EUID" -eq 0 ] || error_exit "Run as root!"
    if ! command -v apt-get >/dev/null; then
        error_exit "This script supports only Debian/Ubuntu systems."
    fi
    log "System check passed"
}

#------------------------------------------------------------------------------
# PACKAGE INSTALLATION
#------------------------------------------------------------------------------
install_packages() {
    log "Installing security packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get upgrade -yq
    apt-get install -yq fail2ban aide mailutils rsyslog auditd logwatch \
        rkhunter chkrootkit clamav clamav-daemon unattended-upgrades \
        prometheus-node-exporter curl wget jq htop net-tools psmisc lsof nmap
    systemctl enable --now unattended-upgrades
}

#------------------------------------------------------------------------------
# RBAC GROUPS
#------------------------------------------------------------------------------
setup_rbac_groups() {
    log "Creating RBAC groups..."
    for g in enterprise-admins security-admins system-admins devops-engineers \
             developers qa-engineers data-analysts auditors interns; do
        groupadd "$g" 2>/dev/null || true
    done
}

#------------------------------------------------------------------------------
# USERS
#------------------------------------------------------------------------------
setup_users() {
    log "Creating enterprise users..."
    for user_info in "${ENTERPRISE_USERS[@]}"; do
        u=$(echo "$user_info" | cut -d: -f1)
        g=$(echo "$user_info" | cut -d: -f2)
        e=$(echo "$user_info" | cut -d: -f3)
        if ! id "$u" >/dev/null 2>&1; then
            useradd -m -s /bin/bash -c "$e" "$u"
            pass=$(openssl rand -base64 12)
            echo "$u:$pass" | chpasswd
            chage -d 0 "$u"
            usermod -aG "$g" "$u"
            echo "User $u created with temp password $pass" >> "$CONFIG_DIR/initial-passwords.txt"
        fi
    done
    chmod 600 "$CONFIG_DIR/initial-passwords.txt" || true
}

#------------------------------------------------------------------------------
# SUDOERS CONFIG
#------------------------------------------------------------------------------
setup_sudoers() {
    log "Configuring sudoers..."
    cp /etc/sudoers "$BACKUP_DIR/sudoers.bak.$(date +%F)"
    cat > /etc/sudoers.d/01-enterprise-rbac <<EOF
%enterprise-admins ALL=(ALL:ALL) ALL
%security-admins   ALL=(ALL:ALL) ALL
%system-admins     ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl
%developers        ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/journalctl
%auditors          ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/bin/last, /usr/bin/w
%interns           ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
EOF
    chmod 440 /etc/sudoers.d/01-enterprise-rbac
    visudo -c || error_exit "Sudoers syntax invalid"
}

#------------------------------------------------------------------------------
# SSH HARDENING
#------------------------------------------------------------------------------
harden_ssh() {
    log "Hardening SSH..."
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak.$(date +%F)"
    cat > /etc/ssh/sshd_config <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
AllowGroups $ALLOWED_SSH_GROUPS
EOF
    systemctl restart sshd
}

#------------------------------------------------------------------------------
# FAIL2BAN
#------------------------------------------------------------------------------
configure_fail2ban() {
    log "Configuring Fail2Ban..."
    cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = $MAX_LOGIN_ATTEMPTS
bantime = $BAN_TIME
EOF
    systemctl enable --now fail2ban
}

#------------------------------------------------------------------------------
# AUDITD
#------------------------------------------------------------------------------
configure_auditd() {
    log "Configuring auditd..."
    cat > /etc/audit/rules.d/99-enterprise.rules <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
EOF
    systemctl enable --now auditd
}

#------------------------------------------------------------------------------
# AIDE
#------------------------------------------------------------------------------
setup_aide() {
    log "Initializing AIDE..."
    aide --init
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    (crontab -l 2>/dev/null; echo "0 ${AIDE_CHECK_TIME%:*} * * * /usr/bin/aide --check | mail -s 'AIDE Report' $SECURITY_EMAIL") | crontab -
}

#------------------------------------------------------------------------------
# ROOTKIT CHECKERS
#------------------------------------------------------------------------------
setup_rootkit_tools() {
    log "Setting up rootkit/malware detection..."
    rkhunter --update
    rkhunter --propupd
    freshclam || true
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/rkhunter --check --sk | mail -s 'RKHunter Report' $SECURITY_EMAIL") | crontab -
}

#------------------------------------------------------------------------------
# MAIN EXECUTION
#------------------------------------------------------------------------------
check_prereqs
install_packages
setup_rbac_groups
setup_users
setup_sudoers
harden_ssh
configure_fail2ban
configure_auditd
setup_aide
setup_rootkit_tools

log "Doorman setup completed!"