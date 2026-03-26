# Doorman

Enterprise Linux Security Hardening Framework

## Overview

Doorman is a modular Bash framework that automates CIS-benchmark-aligned server hardening for production Linux environments. It enforces role-based access control, SSH lockdown, firewall rules, intrusion detection, kernel hardening, and continuous compliance monitoring through a single idempotent deployment script.

Designed for repeatable, auditable infrastructure provisioning across Debian and RHEL-based distributions.

## Features

| Module | Description | CIS Reference |
|---|---|---|
| Package Installation | Installs and enables all required security tooling | 1.2 |
| RBAC Groups | Creates 9 role-based groups with tiered privilege boundaries | 5.2 |
| User Provisioning | Creates users with forced password reset, group assignment, aging policy | 5.4 |
| Sudoers | Granular per-role sudo policies with PTY enforcement and full I/O logging | 5.3 |
| SSH Hardening | Pubkey-only auth, modern ciphers (Ed25519, ChaCha20-Poly1305), no forwarding | 5.2.1-5.2.23 |
| Firewall | UFW or firewalld with default-deny ingress and rate-limited SSH | 3.5 |
| Fail2Ban | Brute-force protection with recidive escalation (repeat offenders get 7-day bans) | -- |
| Auditd | 45+ rules covering identity, privilege escalation, network, kernel modules, cron | 4.1.3-4.1.17 |
| Kernel Hardening | sysctl tuning for SYN cookies, ASLR, ptrace restriction, BPF hardening, ICMP lockdown | 3.1-3.3 |
| Password Policy | PAM pwquality and login.defs enforcement (14+ chars, 3 char classes, 90-day rotation) | 5.4.1 |
| AIDE | File integrity monitoring with daily scheduled checks and email reports | 1.3 |
| Rootkit Detection | rkhunter and chkrootkit daily, ClamAV weekly with quarantine | 1.4 |
| Logging | rsyslog, process accounting, logrotate for all Doorman and sudo logs | 4.2 |
| Legal Banner | Login warning banner on SSH and console | 1.7 |

## Requirements

- **OS**: Debian 11+, Ubuntu 20.04+, RHEL 8/9, CentOS Stream 8/9, Fedora 38+
- **Access**: Root privileges (sudo). Dry-run mode does not require root.
- **Network**: Internet access for package installation and signature updates
- **SSH**: Existing SSH server (openssh-server)

## Installation

```bash
git clone https://github.com/msothman/Doorman.git
cd Doorman
chmod +x Doorman.sh
```

## Usage

```
sudo ./Doorman.sh [OPTIONS]

Options:
  --dry-run              Preview all changes without applying
  --modules LIST         Run specific modules (comma-separated)
  --undo MODULE          Restore backup for a module
  --status               Show hardening status and exit
  --config FILE          Load external configuration file
  --no-color             Disable colored output
  -h, --help             Show this help
```

**Full deployment:**

```bash
sudo ./Doorman.sh
```

**Preview changes (safe, no root required):**

```bash
./Doorman.sh --dry-run
```

**Deploy specific modules:**

```bash
sudo ./Doorman.sh --modules ssh,firewall,sysctl
```

**Check hardening status:**

```bash
sudo ./Doorman.sh --status
```

## Configuration

Doorman supports three configuration tiers. A config file loaded via `--config` has the final say, overriding both environment variables and inline defaults:

1. **Inline defaults** -- fallback values defined at the top of the script.
2. **Environment variables** -- override inline defaults, useful for CI/CD:
   ```bash
   DOORMAN_SSH_PORT=2222 DOORMAN_PASS_MIN_LEN=16 sudo -E ./Doorman.sh
   ```
3. **External config file** -- highest precedence, overrides everything else:
   ```bash
   sudo ./Doorman.sh --config /etc/doorman/production.conf
   ```

   Config files are sourced as Bash. Use the `DOORMAN_*` variable names:
   ```bash
   # /etc/doorman/production.conf
   SECURITY_EMAIL="secops@example.com"
   SSH_PORT="2200"
   PASSWORD_MIN_LENGTH="16"
   ENTERPRISE_USERS=(
       "jdoe:devops-engineers:Jane Doe"
       "asmith:developers:Alex Smith"
   )
   ```

### Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `DOORMAN_SECURITY_EMAIL` | `security@company.com` | Receives AIDE, rkhunter, and ClamAV reports |
| `DOORMAN_COMPANY_NAME` | `Company Name` | Organization name used in legal banners |
| `DOORMAN_SSH_PORT` | `2222` | SSH listen port |
| `DOORMAN_SSH_GROUPS` | `enterprise-admins,...` | Comma-separated groups allowed SSH access |
| `DOORMAN_MAX_RETRIES` | `3` | Max SSH login attempts before ban |
| `DOORMAN_BAN_TIME` | `3600` | Fail2Ban ban duration in seconds |
| `DOORMAN_FIND_TIME` | `600` | Fail2Ban observation window in seconds |
| `DOORMAN_PASS_MIN_LEN` | `14` | Minimum password length |
| `DOORMAN_PASS_MAX_AGE` | `90` | Password expiration in days |
| `DOORMAN_PASS_MIN_AGE` | `7` | Minimum days between password changes |
| `DOORMAN_PASS_WARN` | `14` | Days before expiration to warn users |
| `DOORMAN_AIDE_TIME` | `02:00` | AIDE daily check time (HH:MM) |

### User Provisioning

Define users in the `ENTERPRISE_USERS` array inside the script or config file:

```bash
ENTERPRISE_USERS=(
    "jdoe:devops-engineers:Jane Doe"
    "asmith:developers:Alex Smith"
    "mbrown:auditors:Maria Brown"
)
```

Format: `username:group:full_name`

Temporary credentials are printed to stdout only and are never written to disk. Users are forced to reset their password on first login.

## RBAC Model

```
enterprise-admins     Full sudo, password required
security-admins       Full sudo, incident response
system-admins         systemctl, journalctl
devops-engineers      systemctl, journalctl, docker, crictl
developers            systemctl status, journalctl (read-only)
qa-engineers          Test environment access
data-analysts         Data directory access
auditors              journalctl, last, ausearch, aureport (read-only)
interns               systemctl status only
```

All sudo activity is logged to `/var/log/sudo.log` with full input/output capture.

## Rollback

Every module that modifies system configuration creates a timestamped backup before applying changes. Restore with `--undo`:

```bash
sudo ./Doorman.sh --undo ssh          # Restore SSH config
sudo ./Doorman.sh --undo sudoers      # Remove sudo policies
sudo ./Doorman.sh --undo sysctl       # Reset kernel parameters
sudo ./Doorman.sh --undo firewall     # Disable firewall rules
sudo ./Doorman.sh --undo fail2ban     # Remove fail2ban config
sudo ./Doorman.sh --undo auditd       # Remove audit rules
sudo ./Doorman.sh --undo banner       # Clear login banner
```

Backups are stored in `/var/backups/doorman/` with timestamps, preserving multiple restore points.

The SSH module includes automatic rollback: if the new configuration fails syntax validation or the daemon fails to restart, the previous configuration is restored and the daemon restarted without manual intervention. A SIGINT/SIGTERM trap ensures partial writes are cleaned up if the script is interrupted.

## Architecture

```
Doorman.sh
|-- CLI Parser           --dry-run, --modules, --undo, --status, --no-color
|-- Signal Trap          Cleans up partial writes on SIGINT/SIGTERM
|-- Package Detection    Auto-detects apt / dnf / yum
|-- Module Runner        Executes selected modules in dependency order
|   |-- mod_packages()
|   |-- mod_rbac_groups()
|   |-- mod_users()
|   |-- mod_sudoers()
|   |-- mod_ssh()
|   |-- mod_firewall()
|   |-- mod_fail2ban()
|   |-- mod_auditd()
|   |-- mod_sysctl()
|   |-- mod_password_policy()
|   |-- mod_aide()
|   |-- mod_rootkit()
|   |-- mod_logging()
|   +-- mod_banner()
|-- State Tracker        /var/lib/doorman/*.applied
|-- Backup Manager       /var/backups/doorman/
+-- Report Generator     Deployment summary
```

### Design Principles

- **Idempotent**: Safe to run multiple times. Groups, users, and cron entries are checked before creation. State files track which modules have been applied.
- **Modular**: Any subset of modules can be run independently via `--modules`. Each module is self-contained with its own backup, validation, and state tracking.
- **Reversible**: `--undo` restores from timestamped backups. SSH includes automatic rollback on failure.
- **Auditable**: Every action is logged to `/var/log/doorman/`. Sudo commands are logged with full I/O. Audit rules are immutable after load (requires reboot to modify).
- **Portable**: Auto-detects package manager (apt/dnf/yum), firewall (ufw/firewalld), auth log path, and fail2ban ban action per distribution.
- **Safe**: `--dry-run` previews all changes without root. SSH config is syntax-validated before restart. Sudoers are validated with `visudo -c`. Firewalld adds SSH before switching to drop zone to prevent lockout. Interrupted execution cleans up partial state via signal trap.

### Directory Layout

| Path | Purpose |
|---|---|
| `/etc/doorman/` | Configuration directory |
| `/var/lib/doorman/` | Module state files (idempotency tracking) |
| `/var/lib/doorman/quarantine/` | ClamAV quarantined files |
| `/var/backups/doorman/` | Timestamped configuration backups |
| `/var/log/doorman/` | Deployment logs |
| `/var/log/sudo.log` | Sudo command audit log |

## Platform Support

| Distribution | Package Manager | Firewall | Fail2Ban Action |
|---|---|---|---|
| Ubuntu 20.04+ | apt | UFW | ufw |
| Debian 11+ | apt | UFW | ufw |
| RHEL 8/9 | dnf | firewalld | firewallcmd-ipset |
| CentOS Stream 8/9 | dnf | firewalld | firewallcmd-ipset |
| Fedora 38+ | dnf | firewalld | firewallcmd-ipset |

Package names, auth log paths, and firewall ban actions are automatically resolved per distribution.

## License

MIT License -- 2025 msothman
