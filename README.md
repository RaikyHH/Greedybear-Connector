# OpenCTI GreedyBear Connector

The GreedyBear connector imports honeypot threat intelligence from a
[GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) aggregation server into
OpenCTI. For every IP or domain observed by the honeypots it creates the matching
observable and (optionally) an indicator, enriched with the autonomous system, country,
MITRE ATT&CK technique, honeypot labels and a note with the raw honeypot statistics.

Table of Contents

- [OpenCTI GreedyBear Connector](#opencti-greedybear-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

[GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) aggregates and enriches
indicators of compromise collected from honeypot sensors. This connector pulls those
IoCs on a schedule and maps them to STIX 2.1 objects in OpenCTI.

Without an API key only the public standard feed is used. With an API key the enriched
advanced feed and the ASN aggregation feed are fetched as well (adding autonomous-system
names, captured-credential counts and sensor origins).

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.13
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version
- A running [GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) instance

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter        | config.yml      | Docker environment variable   | Default         | Mandatory | Description                                                                            |
| ---------------- | --------------- | ----------------------------- | --------------- | --------- | ------------------------------------------------------------------------------------- |
| Connector ID     | id              | `CONNECTOR_ID`                | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                              |
| Connector Type   | type            | `CONNECTOR_TYPE`              | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                          |
| Connector Name   | name            | `CONNECTOR_NAME`              | GreedyBear      | Yes       | Name of the connector.                                                                 |
| Connector Scope  | scope           | `CONNECTOR_SCOPE`             | IPv4-Addr,...   | Yes       | The scope or type of data the connector is importing.                                 |
| Log Level        | log_level       | `CONNECTOR_LOG_LEVEL`         | info            | Yes       | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.            |
| Duration Period  | duration_period | `CONNECTOR_DURATION_PERIOD`   | PT6H            | Yes       | Interval between two runs of the connector (ISO 8601 duration, e.g. `PT6H`).           |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter             | config.yml            | Docker environment variable           | Default            | Mandatory | Description                                                                                  |
| --------------------- | --------------------- | ------------------------------------- | ------------------ | --------- | ------------------------------------------------------------------------------------------- |
| API base URL          | api_base_url          | `GREEDYBEAR_API_BASE_URL`             | /                  | Yes       | Base URL of your GreedyBear instance.                                                        |
| API key               | api_key               | `GREEDYBEAR_API_KEY`                  | /                  | No        | DRF token for the authenticated feeds. Omit to use only the public standard feed.           |
| TLP level             | tlp_level             | `GREEDYBEAR_TLP_LEVEL`                | green              | No        | TLP marking for imported entities: `clear`, `white`, `green`, `amber`, `amber+strict`, `red`. |
| Operator name         | operator_name         | `GREEDYBEAR_OPERATOR_NAME`            | Honeypot Operator  | No        | Organization shown as "created by" in OpenCTI.                                               |
| Operator description  | operator_description  | `GREEDYBEAR_OPERATOR_DESCRIPTION`     | /                  | No        | Optional description of the honeypot operator.                                              |
| Operator URL          | operator_url          | `GREEDYBEAR_OPERATOR_URL`             | /                  | No        | Optional URL of the honeypot operator.                                                      |
| Feed type             | feed_type             | `GREEDYBEAR_FEED_TYPE`                | all                | No        | Honeypot feed filter: `all` or a comma-separated list of honeypot names.                    |
| Attack type           | attack_type           | `GREEDYBEAR_ATTACK_TYPE`              | all                | No        | Attack type filter: `all`, `scanner`, `payload_request`.                                     |
| IoC type              | ioc_type              | `GREEDYBEAR_IOC_TYPE`                 | all                | No        | IoC type filter: `all`, `ip`, `domain`.                                                      |
| Prioritize            | prioritize            | `GREEDYBEAR_PRIORITIZE`               | recent             | No        | Standard-feed sort (fallback only): `recent`, `persistent`, `likely_to_recur`, `most_expected_hits`. |
| Include mass scanners | include_mass_scanners | `GREEDYBEAR_INCLUDE_MASS_SCANNERS`    | false              | No        | Include IoCs flagged as mass scanners.                                                       |
| Include Tor exit nodes| include_tor_exit_nodes| `GREEDYBEAR_INCLUDE_TOR_EXIT_NODES`   | true               | No        | Include IoCs flagged as Tor exit nodes.                                                      |
| Max age               | max_age               | `GREEDYBEAR_MAX_AGE`                  | 3                  | No        | Maximum age of entries in days (advanced feed).                                             |
| Feed size             | feed_size             | `GREEDYBEAR_FEED_SIZE`                | 5000               | No        | Maximum number of IoCs to import per run.                                                    |
| Min score             | min_score             | `GREEDYBEAR_MIN_SCORE`                | /                  | No        | Minimum recurrence probability (0.0–1.0); no filter when unset.                             |
| Create indicators     | create_indicators     | `GREEDYBEAR_CREATE_INDICATORS`        | true               | No        | Create a STIX Indicator for every observable.                                               |
| Deep enrich           | deep_enrich           | `GREEDYBEAR_DEEP_ENRICH`              | false              | No        | Per-IoC enrichment (actual ports, days-seen, FireHOL labels). One extra API call per IoC.   |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.8.13`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r src/requirements.txt
```

Then, start the connector from `src` directory:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

For each IP or domain returned by GreedyBear the connector produces:

- An **Observable** (IPv4-Addr / IPv6-Addr / Domain-Name) with labels for the honeypot
  type(s), reputation and attack type.
- An **Indicator** (optional) linked via `based-on` to the observable, carrying an
  `x_opencti_score` derived from the recurrence probability and a `valid_until` window.
- An **Autonomous System** linked via `belongs-to` (with the AS name when an API key is set).
- A **Country** (Location) linked via `located-at`.
- An **Attack Pattern** (MITRE ATT&CK) linked to the indicator via `indicates`.
- A **Note** with the raw honeypot statistics (attack/interaction/login counts, recurrence,
  and — with deep enrichment — the actual destination ports, captured credentials, sensor
  origins and days-seen).

The honeypot operator is created as an Organization (the author of all objects) and
GreedyBear as a Tool used by that operator. Honeypot sensors are represented as labels,
not as separate entities.

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

## Additional information

The authenticated (advanced + ASN) feeds add AS names, captured-credential counts and
sensor origins over the public standard feed. Enabling `deep_enrich` makes one extra
enrichment call per IoC to add the actual destination ports, the days-seen persistence
count and FireHOL blocklist memberships (as `firehol:*` labels) — useful but slow for
large feeds.
