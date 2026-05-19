from typing import Optional
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class GreedyBearClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: Optional[str]
    ):
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.authenticated = bool(api_key)

        self.session = requests.Session()
        if api_key:
            # GreedyBear uses DRF token auth: "Authorization: Token <key>"
            self.session.headers.update({"Authorization": f"Token {api_key}"})

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict | list]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.get(url, params=params, timeout=60)
            self.helper.connector_logger.info("[API] GET request", {"url": url})
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Request failed", {"url": url, "error": str(err)}
            )
            return None

    def get_advanced_feeds(
        self,
        max_age: int = 3,
        feed_size: int = 5000,
        min_score: Optional[float] = None,
        ioc_type: str = "all",
        feed_type: str = "all",
        attack_type: str = "all",
        exclude_reputation: Optional[str] = None,
        include_mass_scanners: bool = False,
        include_tor_exit_nodes: bool = True,
    ) -> list[dict]:
        if not self.authenticated:
            self.helper.connector_logger.info(
                "[API] No API key — skipping advanced feed."
            )
            return []
        """
        Fetch enriched IoCs from /api/feeds/advanced/ (requires auth).

        Returns a list of IoC dicts. The JSON response is wrapped:
          {"iocs": [...], "license": "..."}

        IoC fields (from FeedsResponseSerializer):
          value, feed_type (list), scanner, payload_request,
          first_seen, last_seen, attack_count, interaction_count,
          ip_reputation, firehol_categories, asn (int), destination_port_count,
          login_attempts, recurrence_probability, expected_interactions,
          attacker_country, attacker_country_code, tags, sensors
        """
        params: dict = {
            "max_age": max_age,
            "feed_size": feed_size,
            "verbose": "false",
            "paginate": "false",
            "format_": "json",
        }
        if ioc_type != "all":
            params["ioc_type"] = ioc_type
        if feed_type != "all":
            params["feed_type"] = feed_type
        if attack_type != "all":
            params["attack_type"] = attack_type
        if min_score is not None:
            params["min_score"] = min_score

        # Build exclude_reputation list
        excluded = []
        if exclude_reputation:
            excluded.extend(
                r.strip() for r in exclude_reputation.split(";") if r.strip()
            )
        if not include_mass_scanners:
            excluded.append("mass scanner")
        if not include_tor_exit_nodes:
            excluded.append("tor exit node")
        if excluded:
            params["exclude_reputation"] = ";".join(excluded)

        result = self._get("/api/feeds/advanced/", params=params)
        if result is None:
            return []
        # Response is {"iocs": [...], "license": "..."}
        if isinstance(result, dict):
            return result.get("iocs", [])
        # Older versions might return a bare list
        if isinstance(result, list):
            return result
        return []

    def get_standard_feeds(
        self,
        feed_type: str = "all",
        attack_type: str = "all",
        prioritize: str = "recent",
        include_mass_scanners: bool = False,
        include_tor_exit_nodes: bool = True,
    ) -> list[dict]:
        """
        Fetch IoCs from the public /api/feeds/<feed_type>/<attack_type>/<prioritize>.json endpoint.
        Does NOT require authentication.

        JSON response: {"iocs": [...], "license": "..."}
        Each IoC has the same fields as the advanced feed.
        """
        params: dict = {}
        if not include_mass_scanners:
            params["include_mass_scanners"] = "false"
        if not include_tor_exit_nodes:
            params["include_tor_exit_nodes"] = "false"

        path = f"/api/feeds/{feed_type}/{attack_type}/{prioritize}.json"
        result = self._get(path, params=params or None)
        if result is None:
            return []
        if isinstance(result, dict):
            return result.get("iocs", [])
        if isinstance(result, list):
            return result
        return []

    def get_asn_feeds(
        self,
        max_age: int = 3,
        feed_type: str = "all",
        attack_type: str = "all",
    ) -> list[dict]:
        """
        Fetch aggregated ASN data from /api/feeds/asn/ (requires auth).

        Each entry contains:
          asn (int), as_name (str), ioc_count, total_attack_count,
          total_interaction_count, total_login_attempts, honeypots (list[str]),
          expected_ioc_count (float), expected_interactions (float),
          first_seen (str), last_seen (str)
        """
        if not self.authenticated:
            self.helper.connector_logger.info("[API] No API key — skipping ASN feed.")
            return []
        params: dict = {"max_age": max_age}
        if feed_type != "all":
            params["feed_type"] = feed_type
        if attack_type != "all":
            params["attack_type"] = attack_type

        result = self._get("/api/feeds/asn/", params=params)
        if result is None:
            return []
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("results", [])
        return []

    def get_enrichment(self, observable: str) -> Optional[dict]:
        """Enrich a single IP or domain. Returns the full EnrichmentSerializer response."""
        return self._get("/api/enrichment", params={"query": observable})
