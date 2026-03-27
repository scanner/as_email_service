# fail2ban Integration

This document describes how to set up fail2ban to automatically ban IPs
that attack the as_email_service SMTP daemon.

## Overview

The SMTP daemon writes structured security log lines to a dedicated log
file. fail2ban watches this file and bans offending IPs at the firewall
level (iptables), blocking them before they can even begin a TLS
handshake.

Six separate jails provide granular control over ban thresholds:

| Jail                 | Event                                              | Default maxretry | Default bantime |
| -------------------- | -------------------------------------------------- | ---------------- | --------------- |
| `as-email-nouser`    | Login with nonexistent account                     | 1                | 24h             |
| `as-email-protected` | Wrong password on protected account                | 1                | 24h             |
| `as-email-passwd`    | Wrong password on regular account                  | 5                | 1h              |
| `as-email-flood`     | >10 connections in 60s from one IP                 | 1                | 24h             |
| `as-email-dnsbl`     | IP on DNS blacklist                                | 1                | 24h             |
| `as-email-conn`      | Denied reconnection, SSL/TLS error, protocol error | 5                | 1h              |

## Prerequisites

- fail2ban installed on the **Docker host** (not inside the container)
- The security log file accessible to the host via a volume mount

## Environment Variables

Add these to your `.env` file:

```bash
# Path to the security log file inside the container.
# Default: /var/log/as_email/security.log
SECURITY_LOG_FILE=/var/log/as_email/security.log

# Host directory to mount for security logs.
# Default: ./logs/as_email
HOST_LOG_DIR=/var/log/as_email

# Protected accounts get an immediate ban on wrong password (maxretry=1).
# These are common brute-force targets like admin@, root@, postmaster@.
# Comma-separated list of full email addresses.
PROTECTED_ACCOUNTS=admin@example.com,root@example.com,postmaster@example.com
```

## Docker Setup

The `smtpd` service in `docker-compose.yml` mounts the log directory:

```yaml
volumes:
  - "${HOST_LOG_DIR:-./logs/as_email}:/var/log/as_email:z"
```

The `start_smtpd.sh` script creates the log directory automatically
before starting the daemon.

After `docker compose up`, the security log will be available at
`${HOST_LOG_DIR}/security.log` on the host (default:
`./logs/as_email/security.log`).

## Installing Filters and Jails

Copy the filter and jail configuration files to fail2ban's config
directories:

```bash
# Filter files (one per event category)
sudo cp docs/fail2ban/filter.d/as-email-*.conf /etc/fail2ban/filter.d/

# Jail definitions
sudo cp docs/fail2ban/jail.d/as-email.conf /etc/fail2ban/jail.d/
```

Edit `/etc/fail2ban/jail.d/as-email.conf` and update `logpath` to match
your `HOST_LOG_DIR`:

```ini
logpath = /var/log/as_email/security.log
```

Restart fail2ban:

```bash
sudo systemctl restart fail2ban
```

## Security Event Reference

Each security log line has the format:

```
[YYYY-MM-DD HH:MM:SS] EVENT_TAG ip=<IP> key=value ...
```

| Tag                   | Meaning                               | When emitted                                            |
| --------------------- | ------------------------------------- | ------------------------------------------------------- |
| `AUTH_FAIL_NOUSER`    | Login attempt for nonexistent account | Authenticator rejects unknown username                  |
| `AUTH_FAIL_PASSWD`    | Wrong password for existing account   | Password check fails, account not in PROTECTED_ACCOUNTS |
| `AUTH_FAIL_PROTECTED` | Wrong password for protected account  | Password check fails, account is in PROTECTED_ACCOUNTS  |
| `CONN_FLOOD`          | Connection flood detected             | >10 connections in 60s from same IP                     |
| `CONN_DENIED`         | Reconnection after auth blacklist     | IP already blocked by in-app rate limiter               |
| `DNSBL_REJECT`        | IP on DNS blacklist                   | DNSBL lookup returns positive                           |
| `SSL_ERROR`           | TLS/SSL handshake failure             | Client sends bad cipher, resets during TLS              |
| `SMTP_EXCEPTION`      | Other SMTP protocol error             | Unexpected exception during SMTP session                |

## Testing

Use `fail2ban-regex` to verify that filter patterns match your log
lines:

```bash
# Test each filter against the security log
sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-nouser.conf

sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-protected.conf

sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-passwd.conf

sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-flood.conf

sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-dnsbl.conf

sudo fail2ban-regex /var/log/as_email/security.log \
    /etc/fail2ban/filter.d/as-email-conn.conf
```

Check jail status:

```bash
sudo fail2ban-client status as-email-nouser
sudo fail2ban-client status as-email-protected
```

## Tuning

### Adjusting thresholds

Edit `/etc/fail2ban/jail.d/as-email.conf` and change `maxretry`,
`bantime`, or `findtime` per jail. For example, to be more lenient
with regular wrong-password attempts during a migration:

```ini
[as-email-passwd]
maxretry = 10
findtime = 30m
```

### Repeat-offender escalation

The `nouser`, `protected`, `passwd`, `flood`, and `conn` jails use
fail2ban's ban time increment feature. When an IP is banned a second
time, the ban duration increases:

```ini
bantime.increment = true
bantime.factor    = 24     # multiplier for each subsequent ban
bantime.maxtime   = 4w     # cap at 4 weeks
```

For example, with `bantime = 24h` and `factor = 24`:

- 1st ban: 24 hours
- 2nd ban: 24 days (capped at maxtime)

To disable escalation for a jail, set `bantime.increment = false`.

### Whitelisting

To whitelist IPs (e.g. your monitoring system), add to the jail:

```ini
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8
```

## Log Rotation

The security logger uses Python's `RotatingFileHandler` with a 10 MB
limit and 3 backup files (40 MB max on disk). No external logrotate
configuration is needed.
