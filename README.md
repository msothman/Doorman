## Doorman 🛡️

**Enterprise Security & RBAC Deployment Tool**

Project Doorman is a Bash-based automation framework that **hardens Linux servers** and enforces **enterprise-grade security policies** with minimal manual effort.
It provides role-based access control (RBAC), automated user and group management, SSH security, and continuous compliance monitoring through tools like **fail2ban**, **auditd**, **AIDE**, and **rkhunter**.

---

## ✨ Features

* **RBAC & User Management** – Creates secure user groups with tailored `sudo` access and provisions enterprise users with enforced password resets.
* **SSH Hardening** – Disables root login, sets custom ports, and enforces group-based access.
* **Fail2Ban** – Blocks repeated failed login attempts to prevent brute-force attacks.
* **Auditd Rules** – Monitors sensitive system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`).
* **AIDE (File Integrity Monitoring)** – Schedules daily file integrity scans with email reports.
* **Rootkit Detection** – Configures and automates `rkhunter` and `chkrootkit`.
* **Unattended Upgrades** – Keeps systems patched automatically.
* **Logging & Backups** – Centralized logs and backups in `/var/log/enterprise-security` and `/var/backups/enterprise-security`.

---

## 📂 Repository Structure

```
Doorman/
├── Doorman.sh   # Main deployment script
├── README.md                      # Documentation
```

---

## 🚀 Installation & Usage

### 1. Clone the repository

```bash
git clone https://github.com/msothman/Doorman/
cd Doorman
```

### 2. Make the script executable

```bash
chmod +x Doorman.sh
```

### 3. Customize configuration

Open the script and edit the **CONFIGURATION** section at the top to match your environment:

* Security/admin emails
* Allowed SSH groups
* Enterprise users list
* SSH port and password policy

### 4. Run the script (as root)

```bash
sudo ./Doorman.sh
```

The script will:
✅ Install required security packages
✅ Configure RBAC groups and user access
✅ Harden SSH
✅ Enable fail2ban, auditd, AIDE, and rootkit detection
✅ Set up automated compliance checks

---

## 📊 Benefits

* Cuts **manual configuration time** by up to 60%
* Reduces **unauthorized access attempts**
* Provides **continuous compliance monitoring**
* Strengthens **system reliability** with proactive security controls

---

## 📜 License

MIT License © 2025 \ msothman

---
