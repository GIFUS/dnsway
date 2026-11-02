# DNSway Configuration Reference

This document describes the DNSway configuration file, every supported field,
rule matching, and the list and hosts file formats. It is the detailed
reference; build and run instructions are in the [main README](../README.md).

The full runnable sample is [`config.json`](config.json), with its example files
in [`lists/`](lists) and [`hosts/`](hosts).

## Configuration File

DNSway reads one JSON file. The file has no comments and is loaded once at
startup. Restart DNSway after changing it.

`config.json`, `lists/` and `hosts/` are arranged so the sample works from this
directory. Relative paths in `match_file` and `resolve_file` are resolved
against the directory containing the configuration file, not against the
current working directory.

Example:

```text
docs/
├── config.json
├── lists/
└── hosts/
```

A configuration file at `docs/config.json` therefore resolves
`lists/example.txt` to `docs/lists/example.txt`.

The top-level sections are:

| Section | Required | Purpose |
| --- | --- | --- |
| `dns` | yes | Listener, timeout, bootstrap, and upstream definitions |
| `routing` | yes | Default upstreams and selection strategy |
| `cache` | no | Cache size and TTL bounds |
| `api` | no | HTTP statistics endpoint |
| `rules` | no | Ordered request-processing rules |

## Minimal Configuration

This is the smallest useful forwarding configuration:

```json
{
  "dns": {
    "listen": "127.0.0.1:15353",
    "upstreams": {
      "cloudflare": {
        "address": "1.1.1.1:53",
        "protocol": "udp"
      }
    }
  },
  "routing": {
    "default": ["cloudflare"]
  }
}
```

It listens on localhost port 15353, forwards every query to Cloudflare over UDP,
uses the default 3-second timeout, and leaves the cache disabled.

## `dns`

The `dns` section defines where DNSway listens and which upstream resolvers it
can use.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `listen` | string | yes | none | `host:port` address used for both UDP and TCP |
| `timeout` | duration | no | `3s` | Per-query upstream timeout |
| `bootstrap` | array of strings | no | empty | Upstream IDs used to resolve hostnames in upstream addresses |
| `upstreams` | object | yes | none | Named upstream definitions; at least one is required |

### `dns.listen`

The address and port DNSway binds for both UDP and TCP. It must be a valid
`host:port` value.

```json
{
  "listen": "0.0.0.0:53"
}
```

| Value | Meaning |
| --- | --- |
| `0.0.0.0:53` | All IPv4 interfaces, standard DNS port |
| `127.0.0.1:53` | Localhost only, standard DNS port |
| `192.168.1.10:53` | A specific LAN interface |
| `[::]:53` | All IPv6 interfaces |
| `127.0.0.1:15353` | Localhost only, unprivileged test port |

Port 53 normally requires root on Linux/macOS or Administrator on Windows.
Other ports do not.

The same address is used for UDP and TCP. If either protocol cannot bind, or
another DNS service owns the port, startup fails.

### `dns.timeout`

Duration allowed for one upstream exchange. It applies to UDP, TCP, DoT, DoH,
and bootstrap lookups.

```json
{
  "timeout": "3s"
}
```

If omitted or set to `0`, DNSway uses `3s`. Negative durations are rejected.
Durations use Go syntax: `300ms`, `3s`, `45s`, `5m`, `1h`. There is no day
suffix.

When every upstream fails or times out, the client receives `SERVFAIL`.

### `dns.bootstrap`

An optional array of upstream IDs used to resolve hostnames that appear in
other upstream addresses.

```json
{
  "bootstrap": ["cloudflare", "google"]
}
```

Bootstrap is only required when an upstream address uses a hostname instead of
an IP literal. For example, this DoH upstream needs bootstrap if its hostname is
not resolvable without DNSway:

```json
{
  "address": "https://dns.example.com/dns-query",
  "protocol": "doh"
}
```

Rules for bootstrap:

- every listed ID must exist in `dns.upstreams`;
- bootstrap upstreams must use IP literals, not hostnames, so bootstrap cannot
  loop;
- an upstream with a hostname address fails validation when `bootstrap` is
  empty;
- bootstrap resolves `A` first, then `AAAA`, and caches the result;
- the cached address list uses the DNS TTL, falling back to 60 seconds when the
  TTL is missing or below 10 seconds.

Bootstrap is not used for upstreams whose addresses are already IP literals.

### `dns.upstreams`

A map of upstream IDs to resolver definitions. IDs are referenced by
`dns.bootstrap`, `routing.default`, and `rules[].servers`.

```json
{
  "upstreams": {
    "cloudflare": {
      "address": "1.1.1.1:53",
      "protocol": "udp"
    },
    "google-dot": {
      "address": "8.8.8.8:853",
      "protocol": "dot",
      "server_name": "dns.google"
    }
  }
}
```

Each upstream has these fields:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `address` | string | yes | `host:port` for UDP/TCP/DoT, or an `https://` URL for DoH |
| `protocol` | string | yes | `udp`, `tcp`, `dot`, or `doh` |
| `server_name` | string | only for DoT | TLS server name used for SNI and certificate verification |

Upstream IDs may contain arbitrary non-empty strings. Every ID referenced
elsewhere must exist. `protocol` and `routing.strategy` are case-insensitive and
are normalized to lowercase.

### Upstream Protocols

| Protocol | Address format | Default port | Behavior |
| --- | --- | --- | --- |
| `udp` | `host:port` | 53 | Standard DNS over UDP; truncated replies are retried over TCP |
| `tcp` | `host:port` | 53 | Standard DNS over TCP |
| `dot` | `host:port` | 853 | DNS over TLS; requires `server_name` |
| `doh` | `https://...` | 443 | DNS over HTTPS using POST and `application/dns-message` |

Details:

- **UDP** uses one request and one response. If the upstream sets the truncated
  bit, DNSway retries the same query over TCP.
- **TCP** uses a normal DNS-over-TCP connection.
- **DoT** uses TLS 1.2 or newer, verifies the server certificate, and uses
  `server_name` for SNI and certificate validation. A DoT upstream without
  `server_name` is rejected.
- **DoH** requires an HTTPS URL. The URL hostname is used for TLS; `server_name`
  is not used for DoH. DNSway sends the query with HTTP POST, requests
  `application/dns-message`, and attempts HTTP/2 when the library supports it.
  HTTP/3 is not implemented.
- There is no insecure TLS option. Certificate verification cannot be disabled.
- A hostname in `address` requires a working `dns.bootstrap` configuration.
- The `server_name` field is ignored for UDP, TCP, and DoH.

### Upstream Examples

```json
{
  "cloudflare": {
    "address": "1.1.1.1:53",
    "protocol": "udp"
  },
  "cloudflare-tcp": {
    "address": "1.1.1.1:53",
    "protocol": "tcp"
  },
  "cloudflare-dot": {
    "address": "1.1.1.1:853",
    "protocol": "dot",
    "server_name": "cloudflare-dns.com"
  },
  "cloudflare-doh": {
    "address": "https://cloudflare-dns.com/dns-query",
    "protocol": "doh"
  }
}
```

A hostname-based upstream can use an IP-based bootstrap upstream:

```json
{
  "dns": {
    "bootstrap": ["cloudflare"],
    "upstreams": {
      "cloudflare": {
        "address": "1.1.1.1:53",
        "protocol": "udp"
      },
      "corp-doh": {
        "address": "https://dns.corp.example/dns-query",
        "protocol": "doh"
      }
    }
  }
}
```

## `routing`

The `routing` section controls which upstreams handle queries that do not match
a rule.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `default` | array of strings | yes | none | Upstream IDs used when no rule matches |
| `strategy` | string | no | `first` | `first`, `random`, or `round_robin` |

### `routing.default`

A non-empty list of upstream IDs. It is used only when no rule matches. Even if
`rules` is present, `routing.default` is still required.

```json
{
  "default": ["cloudflare", "google"]
}
```

Every ID must exist in `dns.upstreams`. For `first`, all upstreams are raced;
the list order only breaks fallback ties. For `random` and `round_robin`, the
list is the selection pool.

### `routing.strategy`

Controls how multiple upstreams are used for one forwarded query.

| Strategy | Behavior |
| --- | --- |
| `first` | Query all selected upstreams in parallel and use the first successful response |
| `random` | Pick one upstream at random for each request |
| `round_robin` | Rotate through the selected upstreams using a global counter |

`first` races all selected upstreams. A successful response is a non-truncated
`NOERROR` answer containing a record of the requested type (`ANY`: any
non-empty answer). `NXDOMAIN`, NODATA, and DNS errors are only fallbacks.

If nothing succeeds, return `NXDOMAIN`, then NODATA, then another DNS error.
Ties use the later upstream in the list. Return `SERVFAIL` if any upstream
fails to return a valid, non-truncated response.

`random` and `round_robin` use one upstream and return `SERVFAIL` on failure.

```json
{
  "routing": {
    "default": ["cloudflare", "google"],
    "strategy": "first"
  }
}
```

## `cache`

The optional `cache` section controls DNS response caching.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `enabled` | boolean | no | `false` | Enables the in-memory cache |
| `max_size` | integer | no | `100000` | Approximate maximum number of cached responses |
| `min_ttl` | duration | no | `0s` | Lower TTL bound; `0` disables it |
| `max_ttl` | duration | no | `0s` | Upper TTL bound; `0` disables it |
| `negative_ttl` | duration | no | `30s` | Fallback TTL when a negative response has no usable SOA; `0s` disables it |

```json
{
  "cache": {
    "enabled": true,
    "max_size": 100000,
    "min_ttl": "10s",
    "max_ttl": "24h",
    "negative_ttl": "30s"
  }
}
```

Cache behavior:

- Only forwarded responses are cached; local and blocked answers bypass the
  cache.
- Key: name, type, class, EDNS presence, and the DO bit.
- `NOERROR` with `Answer`: shortest Answer TTL; TTL `0` is not cached.
- Negative (`NXDOMAIN`/NODATA): `min(SOA TTL, SOA MINIMUM)`. Without a usable
  SOA, use `negative_ttl` (`30s` default; `0s` disables it).
- `min_ttl`/`max_ttl` clamp lifetime and returned TTLs, including the fallback.
  TTLs decay while cached.
- `SERVFAIL`, `REFUSED`, and truncated responses are not cached.
- In-memory only; cleared on list/hosts reload. `max_size` is approximate
  across 16 shards.
- `min_ttl` must not exceed `max_ttl`.

## `api`

Optional HTTP API for runtime statistics.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `enabled` | boolean | no | `false` | Enables the HTTP API |
| `listen` | string | no | `127.0.0.1:8080` | HTTP listen address |
| `allowed_ips` | array | no | loopback | Allowed IPs or CIDR ranges |

```json
{
  "api": {
    "enabled": true,
    "listen": "127.0.0.1:8080",
    "allowed_ips": ["127.0.0.1/32", "::1/128"]
  }
}
```

`GET /stats` returns:

- `cache`: `enabled`, `entries`, and `max_size`;
- `queries`: `total`, `blocked`, `rules`, `default`, `cache_hits`, and
  `avg_elapsed_ms`;
- `uptime_seconds`.

`rules` counts all requests matched by any rule. `avg_elapsed_ms` is rounded to
two decimal places. An empty `allowed_ips` permits only loopback. Requests from
other IPs receive `403`; non-`GET` requests receive `405`. The API uses plain
HTTP and has no authentication; restrict `allowed_ips` and bind it to a trusted
interface.

## `rules`

`rules` is an ordered array. Each request is checked against rules from top to
bottom and the first match wins. If no rule matches, `routing.default` is used.

| Field | Type | Description |
| --- | --- | --- |
| `match` | array of strings | Exact names or `*.domain` patterns |
| `match_file` | string | File containing one pattern per line |
| `block` | boolean | Return `NXDOMAIN` |
| `resolve` | string | Return one IPv4 or IPv6 address |
| `servers` | array of strings | Forward to the listed upstream IDs |
| `resolve_file` | array of strings | Return addresses from hosts files |

Every rule must contain exactly one action: `block`, `resolve`, `servers`, or
`resolve_file`.

A rule must also have a matcher through `match` or `match_file`, except a
`resolve_file` rule, which may omit a matcher.

### Actions

| Action | Field | Result |
| --- | --- | --- |
| Block | `"block": true` | `NXDOMAIN` for every query type, without contacting an upstream |
| Static address | `"resolve": "192.0.2.10"` | Local `A` or `AAAA` answer |
| Hosts records | `"resolve_file": ["hosts/local.hosts"]` | Local `A` or `AAAA` answer from hosts files |
| Upstream routing | `"servers": ["cloudflare"]` | Forward through the normal cache and strategy path |

#### `block`

```json
{
  "match": ["*.doubleclick.net", "*.googlesyndication.com"],
  "block": true
}
```

`block` must be `true`. A rule with `"block": false` and no other action is
invalid. A blocked name returns `NXDOMAIN` for `A`, `AAAA`, and every other query
type.

#### `resolve`

```json
{
  "match": ["printer.home.arpa"],
  "resolve": "192.168.1.100"
}
```

`resolve` accepts exactly one IPv4 or IPv6 address. Hostnames and multiple
addresses are not accepted; use `resolve_file` for multiple records.

Local rules answer `A` and `AAAA` queries with an authoritative TTL of 60
seconds. Other query types matched by a local rule return `NOERROR` with no
answers.

#### `servers`

```json
{
  "match": ["*.corp.example", "corp.example"],
  "servers": ["corp-dns"]
}
```

Each listed ID must exist in `dns.upstreams`. The selected upstreams use the
cache and `routing.strategy` in the same way as `routing.default`.

#### `resolve_file`

```json
{
  "resolve_file": ["hosts/local.hosts", "hosts/custom.hosts"]
}
```

This rule has no explicit matcher and applies to any name found in the hosts
files. Multiple files are merged. If the same hostname appears more than once,
all addresses are kept.

You can combine `resolve_file` with a matcher:

```json
{
  "match": ["*.home.arpa"],
  "resolve_file": ["hosts/local.hosts"]
}
```

In this case the name must both exist in the hosts map and match the matcher.
Wildcards in `match` do not create wildcard hosts records; hosts entries are
always exact names.

### Matchers

`match` accepts:

- exact names such as `example.com`;
- leading wildcard patterns such as `*.example.com`.

`match_file` reads patterns from a file, one per line.

A rule can use both `match` and `match_file`; they are combined with OR
semantics. If either source matches, the rule matches.

Wildcard behavior:

- `*.example.com` matches `example.com` itself.
- `*.example.com` matches `www.example.com`.
- `*.example.com` matches `mail.api.example.com`.
- Only a leading `*.` is supported.
- `api.*.example.com`, `*`, and other wildcard positions are rejected.
- Matching is case-insensitive and ignores a trailing root dot.
- Wildcards are suffix matches, not public-suffix-aware. `*.ru` matches `ru`
  and every name ending in `.ru`; use it carefully.

Rule order is significant. Put specific rules above broad rules:

```json
[
  {
    "match": ["api.corp.example"],
    "servers": ["corp-dns"]
  },
  {
    "match": ["*.corp.example"],
    "servers": ["corp-dns"]
  },
  {
    "match_file": "lists/local-domains.txt",
    "servers": ["local"]
  }
]
```

Put `resolve_file` rules above broad routing rules when the same names could
match both, otherwise the hosts records will be shadowed.

## List Files

List files are used by `match_file`. They contain one exact name or `*.domain`
pattern per line.

```text
# Advertising
*.doubleclick.net
*.googlesyndication.com

# Corporate split DNS
*.corp.example
corp.example
```

Rules:

- one pattern per line;
- blank lines are ignored;
- full-line comments start with `#`;
- inline comments are not stripped; put comments on their own line;
- only exact names and leading `*.` wildcards are accepted;
- each file is limited to 32 MiB;
- a missing or invalid file fails configuration loading;
- a failed hot reload keeps the previous rules active.

## Hosts Files

Hosts files are used by `resolve_file`. Each line contains an IP address
followed by one or more hostnames.

```text
# Local servers
192.168.1.10 nas.home.arpa
192.168.1.20 media.home.arpa
192.168.1.30 api.home.arpa

# Multiple names for one IP
192.168.1.40 backend.home.arpa gateway.home.arpa

# IPv6
fd00::10 nas.home.arpa
fd00::20 media.home.arpa
```

Format:

```text
IP_ADDRESS HOSTNAME [HOSTNAME ...]
```

Rules:

- IPv4 and IPv6 addresses are supported;
- one IP may have multiple hostnames;
- the same hostname may appear multiple times; all addresses are kept;
- full-line comments start with `#`;
- a field beginning with `#` starts a trailing comment;
- hostnames are matched exactly and are normalized to lowercase without a
  trailing dot;
- wildcard hostnames are not supported;
- each file is limited to 32 MiB;
- a failed hot reload keeps the previous rules active.

## Validation

Configuration loading fails with a field-specific error when:

| Error | Cause |
| --- | --- |
| Missing `dns.listen` | No listener address |
| Invalid `dns.listen` | Bad host/port or port outside 1–65535 |
| Empty `dns.upstreams` | No upstreams |
| Unsupported protocol | `protocol` is not `udp`, `tcp`, `dot`, or `doh` |
| Invalid address | Bad host/port or invalid DoH URL |
| DoH not HTTPS | DoH address does not start with `https://` |
| Missing DoT `server_name` | `dot` upstream has no `server_name` |
| Unknown bootstrap upstream | `dns.bootstrap` references a missing ID |
| Bootstrap not IP-based | A bootstrap upstream uses a hostname |
| Hostname upstream without bootstrap | An upstream hostname cannot be resolved |
| Empty `routing.default` | No default upstreams |
| Unknown default upstream | `routing.default` references a missing ID |
| Unsupported strategy | Strategy is not `first`, `random`, or `round_robin` |
| Invalid cache size | `max_size` is negative |
| Invalid cache TTL | Negative value or `min_ttl > max_ttl` |
| Invalid API listen | `api.listen` is not a valid `host:port` |
| Invalid API IP | `api.allowed_ips` contains an invalid IP or CIDR |
| No rule action | Rule has none of `block`, `resolve`, `servers`, `resolve_file` |
| Multiple rule actions | Rule has more than one action |
| Missing matcher | Rule has no `match`/`match_file` and is not `resolve_file` |
| Invalid `resolve` | Value is not a valid IP address |
| Unknown server | `rules[].servers` references a missing upstream |
| Unreadable file | A list or hosts file cannot be read |
| Invalid pattern | Empty pattern, invalid wildcard, or non-leading `*` |

## Configuration Recipes

These recipes show configuration patterns. Some are complete configurations;
others show only the relevant section and should be merged into a full config.
The complete runnable configuration is [`config.json`](config.json).

### 1. Minimal Forwarder

```json
{
  "dns": {
    "listen": "127.0.0.1:15353",
    "upstreams": {
      "cloudflare": {
        "address": "1.1.1.1:53",
        "protocol": "udp"
      }
    }
  },
  "routing": {
    "default": ["cloudflare"]
  }
}
```

### 2. Block Advertising and Tracking Domains

Add these entries to the `rules` array:

```json
[
  {
    "match": [
      "*.doubleclick.net",
      "*.googlesyndication.com",
      "*.googleadservices.com"
    ],
    "block": true
  }
]
```

Or keep the list in a file:

```json
[
  {
    "match_file": "lists/blocked-domains.txt",
    "block": true
  }
]
```

### 3. Local Records and a Local DNS Server

```json
{
  "dns": {
    "listen": "127.0.0.1:15353",
    "upstreams": {
      "cloudflare": {
        "address": "1.1.1.1:53",
        "protocol": "udp"
      },
      "local": {
        "address": "192.168.1.1:53",
        "protocol": "udp"
      }
    }
  },
  "routing": {
    "default": ["cloudflare"]
  },
  "rules": [
    {
      "match": ["printer.home.arpa"],
      "resolve": "192.168.1.100"
    },
    {
      "resolve_file": ["hosts/local.hosts", "hosts/custom.hosts"]
    },
    {
      "match_file": "lists/local-domains.txt",
      "servers": ["local"]
    }
  ]
}
```

### 4. Split DNS

Send selected internal domains to an internal resolver and everything else to a
public resolver:

```json
{
  "dns": {
    "listen": "127.0.0.1:15353",
    "upstreams": {
      "public": {
        "address": "1.1.1.1:53",
        "protocol": "udp"
      },
      "corp": {
        "address": "10.0.0.53:53",
        "protocol": "udp"
      }
    }
  },
  "routing": {
    "default": ["public"]
  },
  "rules": [
    {
      "match": ["*.corp.example", "corp.example"],
      "servers": ["corp"]
    },
    {
      "match": ["*.home.arpa", "*.lan"],
      "servers": ["corp"]
    }
  ]
}
```

Place the most specific rules first.

### 5. Encrypted Upstreams Only

```json
{
  "dns": {
    "listen": "127.0.0.1:15353",
    "upstreams": {
      "cloudflare-dot": {
        "address": "1.1.1.1:853",
        "protocol": "dot",
        "server_name": "cloudflare-dns.com"
      },
      "google-doh": {
        "address": "https://dns.google/dns-query",
        "protocol": "doh"
      }
    }
  },
  "routing": {
    "default": ["cloudflare-dot", "google-doh"]
  }
}
```

DoH and DoT always verify certificates. There is no insecure option.

### 6. Parallel First Answer

Set `routing` to:

```json
{
  "default": ["cloudflare", "google"],
  "strategy": "first"
}
```

Both upstreams are raced. The first successful positive response wins;
`NXDOMAIN` and NODATA are only fallbacks.

### 7. Random or Round-Robin Selection

Use one upstream per request:

```json
{
  "default": ["cloudflare", "google"],
  "strategy": "round_robin"
}
```

`round_robin` rotates through the list. `random` picks a random entry. Neither
retries another upstream after a failure.

### 8. Bootstrap for a Hostname Upstream

Configure `dns` as:

```json
{
  "bootstrap": ["cloudflare"],
  "upstreams": {
    "cloudflare": {
      "address": "1.1.1.1:53",
      "protocol": "udp"
    },
    "corp-doh": {
      "address": "https://dns.corp.example/dns-query",
      "protocol": "doh"
    }
  }
}
```

Bootstrap upstreams must use IP literals. The resolved address is cached
temporarily.

### 9. Disable or Bound the Cache

Disable the cache:

```json
{
  "enabled": false
}
```

Bound how long records are cached:

```json
{
  "enabled": true,
  "max_size": 50000,
  "min_ttl": "30s",
  "max_ttl": "1h"
}
```

Both examples are values for the `cache` section.

### 10. Use Multiple Hosts Files

Add this entry to the `rules` array:

```json
[
  {
    "resolve_file": [
      "hosts/local.hosts",
      "hosts/docker.hosts",
      "hosts/custom.hosts"
    ]
  }
]
```

All files are merged. Changing any of them reloads the rules and clears the
cache.

### 11. Unprivileged Local Testing

Set the listener to:

```json
{
  "listen": "127.0.0.1:15353"
}
```

This is a value for the `dns` section. Ports above 1024 do not require elevated
privileges.

## Constraints Relevant to Configuration

- DNSway forwards queries; it is not a recursive or authoritative resolver.
- DNSSEC validation is not performed.
- Local rules answer only `A` and `AAAA`; other query types return `NOERROR`
  with no answers.
- A request must contain exactly one question; otherwise it receives `FORMERR`.
- `config.json` is not hot-reloaded. Only files referenced by `match_file` and
  `resolve_file` are watched.
- Lists and hosts files are limited to 32 MiB each.
- The cache is in memory only and is lost on restart.
- There is no access control, authentication, or rate limiting; use a firewall
  and bind to a trusted interface.
