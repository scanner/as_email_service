# Autoconfig and Autodiscover

Mail clients can locate IMAP/SMTP settings automatically instead of asking the
user to type in server names and ports:

- **Thunderbird / Mozilla Autoconfig** — fetches
  `https://autoconfig.<domain>/mail/config-v1.1.xml?emailaddress=<email>`
  (falling back to plain HTTP if HTTPS is unavailable, then to a
  `.well-known` path on the domain itself, then to MX-based guessing).
- **Outlook / Microsoft Autodiscover** — fetches
  `https://autodiscover.<domain>/autodiscover/autodiscover.xml`, or resolves
  an `_autodiscover._tcp.<domain>` SRV record.

Here `<domain>` is the domain half of the user's email address, not the name
of this service. To support this for every domain hosted on this service
without per-domain certificates, each hosted domain gets a DNS `CNAME`
pointing its `autoconfig` and `autodiscover` names at this service's own
canonical host (the value of `settings.SITE_NAME`, e.g. `mail.example.com`):

```
autoconfig.customerdomain.com.   CNAME   mail.example.com.
autodiscover.customerdomain.com. CNAME   mail.example.com.
```

## Why a same-host HTTP→HTTPS redirect breaks this

A CNAME is invisible above the network layer: when a mail client resolves
`autoconfig.customerdomain.com` and follows the CNAME, it still connects
using the _original_ hostname for both the TLS SNI and the HTTP `Host`
header. If your reverse proxy's blanket "redirect everything on port 80 to
HTTPS on the same host" rule fires here, the client is bounced to
`https://autoconfig.customerdomain.com/...` — a hostname this service holds
no certificate for — and the TLS handshake fails.

That's fine for Autoconfig, which has a plain-HTTP fallback step in its
lookup order, but it means the plain-HTTP response has to actually answer
the request rather than bounce it back into the same broken HTTPS hostname.

## The fix: redirect these two hostnames to a host you do have a cert for

Both protocols tolerate (or explicitly expect) a **cross-host** redirect on
plain HTTP: the client follows the `Location` header to a different host —
this service's real, certificated hostname — and completes the request
there over HTTPS with a valid cert. No certificate is ever needed for
`autoconfig.<domain>` / `autodiscover.<domain>` themselves; port 80 for
those two names only ever needs to answer with a redirect.

Match on the `Host` header pattern `^(autoconfig|autodiscover)\.`, not on a
fixed list of domains — hosted domains are added dynamically (a `Server` row
per domain), so the proxy rule must work for any domain without requiring a
config change each time one is added. Preserve the full original path and
query string in the redirect, since Autoconfig passes `?emailaddress=...` as
a query parameter that the app needs downstream.

### nginx

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name ~^(autoconfig|autodiscover)\..*$;

    return 301 https://mail.example.com$request_uri;
}
```

### Caddy (Caddyfile)

Most Caddy setups use the Caddyfile rather than the JSON config, so this is
likely the more useful form:

```caddyfile
http://:80 {
    @autoconfig_autodiscover {
        header_regexp Host ^(autoconfig|autodiscover)\.
    }
    redir @autoconfig_autodiscover https://mail.example.com{uri} 301
}
```

### Caddy (JSON config)

```json
{
  "match": [
    {
      "header_regexp": {
        "Host": {
          "pattern": "^(autoconfig|autodiscover)\\."
        }
      }
    }
  ],
  "handle": [
    {
      "handler": "static_response",
      "status_code": 301,
      "headers": {
        "Location": ["https://mail.example.com{http.request.uri}"]
      }
    }
  ]
}
```

Either Caddy form only needs to be reachable on port 80 (Caddy's automatic
HTTPS does not need to know about `autoconfig.*` / `autodiscover.*` at all,
since this service never terminates TLS for those hostnames).

Replace `mail.example.com` in all examples with this deployment's
`settings.SITE_NAME` value.

## What the app still needs (not covered here)

This document only covers getting the request to this service's own,
already-certificated host. The Django side — reading the domain back out of
the `emailaddress` query param (Autoconfig) or the POST body's
`<EMailAddress>` element (Autodiscover), looking up the matching `Server`,
and rendering the config XML with that `Server`'s configured host/port
(falling back to `settings.SITE_NAME` when unset) — is tracked separately
and not yet implemented.
