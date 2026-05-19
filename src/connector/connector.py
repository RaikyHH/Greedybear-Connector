import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from greedybear_client import GreedyBearClient
from pycti import OpenCTIConnectorHelper


class GreedyBearConnector:
    """
    OpenCTI External-Import connector for GreedyBear honeypot threat intelligence.

    Run order each cycle:
      1. Advanced feed (/api/feeds/advanced/) — enriched IoCs with ASN, country, reputation
      2. Fallback to standard feed if advanced returns nothing (e.g. no auth / old version)
      3. ASN aggregated feed (/api/feeds/asn/) — adds AS-level honeypot relationships
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        raw_key = self.config.greedybear.api_key
        self.client = GreedyBearClient(
            helper=self.helper,
            base_url=self.config.greedybear.api_base_url,
            api_key=raw_key.get_secret_value() if raw_key else None,
        )
        self.converter = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.greedybear.tlp_level,
            operator_name=self.config.greedybear.operator_name,
            operator_description=self.config.greedybear.operator_description,
            operator_url=self.config.greedybear.operator_url,
        )

    def _collect_intelligence(self) -> list:
        stix_objects = []
        cfg = self.config.greedybear

        # ---- 1. ASN feed first — builds the as_name cache for IoC processing ----
        # as_name comes from MaxMind GeoIP (geoip.as_org) stored server-side.
        # The advanced IoC feed returns only the ASN number; the AS name is only
        # available via the ASN aggregated endpoint (auth required).
        # Without an API key this returns [] immediately and the cache stays empty.
        self.helper.connector_logger.info("[GREEDYBEAR] Fetching ASN feed...")
        asn_entries = self.client.get_asn_feeds(
            max_age=cfg.max_age,
            feed_type=cfg.feed_type,
            attack_type=cfg.attack_type,
        )
        self.helper.connector_logger.info(
            "[GREEDYBEAR] ASN entries fetched", {"count": len(asn_entries)}
        )

        # Build lookup: asn (int) -> as_name (str)
        asn_name_cache: dict[int, str] = {
            int(e["asn"]): e.get("as_name", "")
            for e in asn_entries
            if e.get("asn") is not None
        }

        for entry in asn_entries:
            stix_objects.extend(self.converter.asn_entry_to_stix_objects(entry))

        # ---- 2. Advanced feed (authenticated, enriched) ----
        self.helper.connector_logger.info("[GREEDYBEAR] Fetching advanced feed...")
        iocs = self.client.get_advanced_feeds(
            max_age=cfg.max_age,
            feed_size=cfg.feed_size,
            min_score=cfg.min_score,
            ioc_type=cfg.ioc_type,
            feed_type=cfg.feed_type,
            attack_type=cfg.attack_type,
            include_mass_scanners=cfg.include_mass_scanners,
            include_tor_exit_nodes=cfg.include_tor_exit_nodes,
        )

        # ---- 3. Fallback: standard (public) feed ----
        if not iocs:
            self.helper.connector_logger.info(
                "[GREEDYBEAR] Advanced feed empty — falling back to standard feed."
            )
            iocs = self.client.get_standard_feeds(
                feed_type=cfg.feed_type,
                attack_type=cfg.attack_type,
                prioritize=cfg.prioritize,
                include_mass_scanners=cfg.include_mass_scanners,
                include_tor_exit_nodes=cfg.include_tor_exit_nodes,
            )

        self.helper.connector_logger.info(
            "[GREEDYBEAR] IoCs to process", {"count": len(iocs)}
        )

        # Deduplicate by value field; enrich asn entry with cached as_name
        seen: set[str] = set()
        for ioc in iocs:
            val = ioc.get("value") or ioc.get("ip") or ioc.get("ioc") or ""
            if val in seen:
                continue
            seen.add(val)

            # Inject as_name from cache so create_asn() gets a proper name
            asn_raw = ioc.get("asn")
            if asn_raw is not None and "as_name" not in ioc:
                try:
                    ioc["as_name"] = asn_name_cache.get(int(asn_raw), "")
                except (ValueError, TypeError):
                    pass

            stix_objects.extend(self.converter.ioc_to_stix_objects(ioc))

        # Always include the author, GreedyBear tool, their relationship, and TLP marking
        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.greedybear_tool)
            stix_objects.append(self.converter.operator_uses_greedybear)
            stix_objects.append(self.converter.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting GreedyBear connector run...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state and "last_run" in current_state:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Last run", {"last_run": current_state["last_run"]}
                )
            else:
                self.helper.connector_logger.info("[CONNECTOR] First run ever.")

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "GreedyBear feed import"
            )

            stix_objects = self._collect_intelligence()

            if stix_objects:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    "[CONNECTOR] Bundle sent",
                    {"bundles_sent": len(bundles_sent), "stix_objects": len(stix_objects)},
                )
            else:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] No STIX objects produced — nothing sent."
                )

            current_state = self.helper.get_state() or {}
            current_state["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
            self.helper.set_state(current_state)

            message = (
                f"GreedyBear connector run complete, last_run set to "
                f"{now.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Stopped.")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
