# GreedyBear Connector for OpenCTI

An [OpenCTI](https://github.com/OpenCTI-Platform/OpenCTI) external-import connector that pulls threat intelligence from a [GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) honeypot aggregation server.

## What it imports

For each IP or domain observed by the honeypots, the connector creates:

- **Observable** (IPv4-Addr / IPv6-Addr / Domain-Name) with labels for honeypot type(s), reputation, and attack type
- **Indicator** linked via `based-on` to the observable
- **Infrastructure** node per honeypot type (e.g. cowrie, suricata) linked via `consists-of`
- **Attack Pattern** (MITRE ATT&CK) linked to the Indicator via `indicates`
- **Autonomous System** linked via `belongs-to`
- **Country** (Location) linked via `located-at`
- **Note** with raw honeypot statistics: attack count, interaction count, login attempts, port count, recurrence probability

Without an API key only the public standard feed is used. With a key the enriched advanced feed and ASN aggregation feed are also fetched.

## Quick start

```bash
docker run -d \
  -e OPENCTI_URL=http://your-opencti:8080 \
  -e OPENCTI_TOKEN=your-token \
  -e CONNECTOR_ID=$(python3 -c "import uuid; print(uuid.uuid4())") \
  -e GREEDYBEAR_API_BASE_URL=https://your-greedybear-instance.example.com \
  -e GREEDYBEAR_OPERATOR_NAME="My Organization" \
  ghcr.io/raikyhh/greedybear-connector:latest
```

Or with `docker compose`:

```bash
cp config.yml.sample config.yml   # edit as needed
docker compose up -d
```

## Configuration

All settings can be provided as environment variables or in `config.yml`.

| Environment variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | — | OpenCTI platform URL |
| `OPENCTI_TOKEN` | — | OpenCTI API token |
| `CONNECTOR_ID` | — | Unique UUID for this connector instance |
| `CONNECTOR_NAME` | `GreedyBear` | Display name in OpenCTI |
| `CONNECTOR_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warning`, `error`) |
| `CONNECTOR_DURATION_PERIOD` | `PT6H` | Run interval (ISO 8601 duration) |
| `GREEDYBEAR_API_BASE_URL` | — | Base URL of your GreedyBear instance |
| `GREEDYBEAR_API_KEY` | *(none)* | DRF token for authenticated feeds (optional) |
| `GREEDYBEAR_TLP_LEVEL` | `green` | TLP marking: `clear`, `white`, `green`, `amber`, `amber+strict`, `red` |
| `GREEDYBEAR_OPERATOR_NAME` | `Honeypot Operator` | Organization shown as "created by" in OpenCTI |
| `GREEDYBEAR_OPERATOR_DESCRIPTION` | *(none)* | Optional description of the operator |
| `GREEDYBEAR_OPERATOR_URL` | *(none)* | Optional URL of the operator |
| `GREEDYBEAR_FEED_TYPE` | `all` | Honeypot type filter: `all`, `cowrie`, `suricata`, … |
| `GREEDYBEAR_ATTACK_TYPE` | `all` | Attack type filter: `all`, `scanner`, `payload_request` |
| `GREEDYBEAR_IOC_TYPE` | `all` | IoC type filter: `all`, `ip`, `domain` |
| `GREEDYBEAR_PRIORITIZE` | `recent` | Standard feed sort: `recent`, `persistent`, `likely_to_recur`, `most_expected_hits` |
| `GREEDYBEAR_INCLUDE_MASS_SCANNERS` | `false` | Include mass-scanner IPs |
| `GREEDYBEAR_INCLUDE_TOR_EXIT_NODES` | `true` | Include Tor exit nodes |
| `GREEDYBEAR_MAX_AGE` | `3` | Max age of entries in days (advanced feed) |
| `GREEDYBEAR_FEED_SIZE` | `5000` | Max IoCs per run |
| `GREEDYBEAR_MIN_SCORE` | *(none)* | Minimum recurrence probability filter (0.0–1.0) |

## Requirements

- OpenCTI 6.x
- A running [GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) instance
- Docker (or Python 3.12+)

## License

MIT
