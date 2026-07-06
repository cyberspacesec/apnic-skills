# Whois Commands

The `whois` command group queries the APNIC whois server (`whois.apnic.net:43`) and returns either parsed objects or raw text. A `reverse-dns` top-level command performs PTR lookups against the DNS.

Source: [`cmd_whois.go`](https://github.com/cyberspacesec/apnic-skills/blob/main/cmd/apnic/cmd_whois.go).

## Command Structure

```mermaid
graph TB
    W["whois"]
    W --> WIP["ip &lt;ip&gt;<br/>parsed WhoisInfo"]
    W --> WAS["asn &lt;asn&gt;<br/>parsed WhoisInfo"]
    W --> WRAW["raw &lt;query&gt;<br/>unparsed text"]

    ROOT["apnic (root)"] --> RDNS["reverse-dns &lt;ip&gt;<br/>PTR records"]
```

`whois ip` and `whois asn` parse the response into a `WhoisInfo` struct (network, CIDR, country, org, parent, created, last-updated). `whois raw` returns the unparsed text, suitable for ad-hoc queries against any whois object type.

## `apnic whois ip <ip>`

Parsed whois lookup for an IP address.

```bash
apnic whois ip 1.1.1.1
apnic --json whois ip 1.1.1.1 | jq '.cidr, .country, .org_name'
```

Human-readable output:

```
Network: APNIC-LABRADOR
CIDR:    [1.1.1.0/24]
Country: AU
Org:     APNIC-LABRADOR
Parent:  1.0.0.0/8
Created: 2011-04-12
Updated: 2024-01-15
```

## `apnic whois asn <asn>`

Parsed whois lookup for an ASN. Accepts either `13335` or `AS13335` (the `AS`/`as` prefix is stripped by `normalizeASN`).

```bash
apnic whois asn 13335
apnic whois asn AS13335
```

Human-readable output prints `Network`, `Country`, and `Org`.

## `apnic whois raw <query>`

Raw whois query: returns the unparsed text response. Pass any whois query string (an IP, an ASN, an object key, or a whois search term).

```bash
apnic whois raw "1.1.1.1"
apnic whois raw "AS13335"
apnic whois raw -i mnt-by MAINT-APNIC
```

Output is the verbatim text from the whois server with no transformation. This is the escape hatch when the structured subcommands do not expose a field you need.

## `apnic reverse-dns <ip>`

Reverse DNS (PTR) lookup for an IP address. This is a top-level command, not under `whois`, because it queries DNS rather than the whois server.

```bash
apnic reverse-dns 1.1.1.1
apnic --json reverse-dns 1.1.1.1
```

Human-readable output prints one PTR record per line, or `(no PTR records)` if none exist. With `--json`, a JSON array of strings is emitted.

## Query Flow

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as apnic whois
    participant SDK as apnic.Client
    participant WHOIS as whois.apnic.net:43

    U->>CLI: apnic whois ip 1.1.1.1
    CLI->>SDK: QueryWhoisIP(ctx, "1.1.1.1")
    SDK->>WHOIS: TCP connect :43, send "1.1.1.1\r\n"
    WHOIS-->>SDK: whois text
    SDK->>SDK: parse into WhoisInfo
    SDK-->>CLI: *WhoisInfo
    CLI-->>U: human-readable / --json
```

For `whois raw`, the parse step is skipped and the raw text is returned directly. For `reverse-dns`, the request goes to the resolver (not the whois server) and returns a `[]string` of PTR names.

## Global flags of note

| Flag | Effect on whois |
|------|-----------------|
| `--whois-server` | Override the default `whois.apnic.net:43`. |
| `--timeout` | Per-request timeout (whois queries can be slow; consider `--timeout 60s`). |
| `--stealth` / `--jitter` | Apply to HTTP only; whois is a raw TCP protocol and is not rate-jittered. Use `--rate-limit` for global throttling. |
| `--json` | Emit the parsed struct (`WhoisInfo`) or, for `raw`/`reverse-dns`, the raw text/array. |

## Output summary

| Subcommand | Human-readable | `--json` |
|------------|----------------|----------|
| `whois ip` | Labelled key/value fields | `WhoisInfo` object |
| `whois asn` | Labelled key/value fields | `WhoisInfo` object |
| `whois raw` | Raw text | Raw text (string) |
| `reverse-dns` | One PTR per line, or `(no PTR records)` | JSON array of strings |
