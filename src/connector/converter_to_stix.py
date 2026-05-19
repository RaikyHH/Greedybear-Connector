import ipaddress
from datetime import datetime, timezone
from typing import Literal, Optional

import stix2
import validators
from pycti import (
    Identity,
    Indicator,
    Infrastructure,
    Location,
    MarkingDefinition,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Tool,
)

GREEDYBEAR_URL = "https://github.com/GreedyBear-Project/GreedyBear"

# Maps GreedyBear attack_type to (MITRE technique ID, technique name)
ATTACK_PATTERN_MAP = {
    "scanner": ("T1595", "Active Scanning"),
    "payload_request": ("T1071", "Application Layer Protocol"),
}

# Human-readable honeypot descriptions
HONEYPOT_DESCRIPTION_MAP = {
    "cowrie": "SSH/Telnet honeypot",
    "dionaea": "Multi-protocol honeypot",
    "adbhoney": "Android Debug Bridge honeypot",
    "ciscoasa": "Cisco ASA honeypot",
    "conpot": "ICS/SCADA honeypot",
    "elasticpot": "Elasticsearch honeypot",
    "glutton": "All-port honeypot",
    "heralding": "Credentials-capturing honeypot",
    "honeytrap": "TCP/UDP honeypot",
    "mailoney": "SMTP honeypot",
    "medpot": "DICOM medical honeypot",
    "rdpy": "RDP honeypot",
    "snare": "Web application honeypot",
    "tanner": "Web application honeypot backend",
}


class ConverterToStix:
    """
    Converts GreedyBear IoC data into STIX 2.1 objects for OpenCTI ingestion.

    Author identity = the honeypot operator (configurable via GREEDYBEAR_OPERATOR_NAME).
    GreedyBear is a separate Tool object used by the operator.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
        operator_name: str,
        operator_description: Optional[str] = None,
        operator_url: Optional[str] = None,
    ):
        self.helper = helper
        self.tlp_marking = self._create_tlp_marking(tlp_level.lower())

        # The honeypot operator is the author of all produced objects.
        self.author = self._create_operator(
            operator_name, operator_description, operator_url
        )

        # GreedyBear is the collection/aggregation tool used by the operator.
        self.greedybear_tool = self._create_greedybear_tool()

        # operator -[uses]-> GreedyBear
        self.operator_uses_greedybear = self.create_relationship(
            self.author.id, "uses", self.greedybear_tool.id
        )

    def _create_operator(
        self,
        name: str,
        description: Optional[str],
        url: Optional[str],
    ) -> stix2.Identity:
        ext_refs = []
        if url:
            ext_refs.append(stix2.ExternalReference(source_name=name, url=url))
        kwargs = dict(
            id=Identity.generate_id(name=name, identity_class="organization"),
            name=name,
            identity_class="organization",
            object_marking_refs=[self.tlp_marking],
        )
        if description:
            kwargs["description"] = description
        if ext_refs:
            kwargs["external_references"] = ext_refs
        return stix2.Identity(**kwargs)

    def _create_greedybear_tool(self) -> stix2.Tool:
        return stix2.Tool(
            id=Tool.generate_id("GreedyBear"),
            name="GreedyBear",
            description=(
                "GreedyBear is a honeypot data aggregation and threat intelligence platform "
                "that collects and enriches IoCs from various honeypot sensors."
            ),
            tool_types=["information-gathering"],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
            external_references=[
                stix2.ExternalReference(
                    source_name="GreedyBear",
                    url=GREEDYBEAR_URL,
                    description="GreedyBear project homepage",
                )
            ],
        )

    @staticmethod
    def _create_tlp_marking(level: str):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
        start_time: Optional[datetime] = None,
        stop_time: Optional[datetime] = None,
        description: Optional[str] = None,
    ) -> stix2.Relationship:
        kwargs = dict(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
        )
        if start_time:
            kwargs["start_time"] = start_time
        # stop_time must be strictly later than start_time (STIX 2.1 constraint)
        if stop_time and (start_time is None or stop_time > start_time):
            kwargs["stop_time"] = stop_time
        if description:
            kwargs["description"] = description
        return stix2.Relationship(**kwargs)

    # ------------------------------------------------------------------
    # Observable helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        return bool(validators.domain(value))

    def create_ip_observable(
        self,
        ip: str,
        labels: Optional[list[str]] = None,
    ) -> Optional[stix2.IPv4Address | stix2.IPv6Address]:
        custom = {"x_opencti_created_by_ref": self.author.id}
        if labels:
            custom["x_opencti_labels"] = labels

        if self._is_ipv4(ip):
            return stix2.IPv4Address(
                value=ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=custom,
            )
        if self._is_ipv6(ip):
            return stix2.IPv6Address(
                value=ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=custom,
            )
        return None

    def create_domain_observable(
        self,
        domain: str,
        labels: Optional[list[str]] = None,
    ) -> Optional[stix2.DomainName]:
        if not self._is_domain(domain):
            return None
        custom = {"x_opencti_created_by_ref": self.author.id}
        if labels:
            custom["x_opencti_labels"] = labels
        return stix2.DomainName(
            value=domain,
            object_marking_refs=[self.tlp_marking],
            custom_properties=custom,
        )

    # ------------------------------------------------------------------
    # Infrastructure (honeypot) node
    # ------------------------------------------------------------------

    def create_honeypot_infrastructure(
        self, honeypot_name: str
    ) -> stix2.Infrastructure:
        desc = HONEYPOT_DESCRIPTION_MAP.get(
            honeypot_name.lower(), f"{honeypot_name} honeypot"
        )
        return stix2.Infrastructure(
            id=Infrastructure.generate_id(honeypot_name),
            name=honeypot_name,
            description=desc,
            infrastructure_types=["honeypot"],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
        )

    # ------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------

    def create_country_location(self, country_code: str) -> Optional[stix2.Location]:
        """country_code must be ISO 3166-1 alpha-2 (2 chars)."""
        if not country_code or len(country_code) != 2:
            return None
        code = country_code.upper()
        return stix2.Location(
            id=Location.generate_id(code, "Country"),
            name=code,
            country=code,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"x_opencti_location_type": "Country"},
        )

    # ------------------------------------------------------------------
    # Autonomous System
    # ------------------------------------------------------------------

    def create_asn(self, asn_number: int, as_name: str) -> stix2.AutonomousSystem:
        return stix2.AutonomousSystem(
            number=asn_number,
            name=as_name or f"AS{asn_number}",
            object_marking_refs=[self.tlp_marking],
            custom_properties={"x_opencti_created_by_ref": self.author.id},
        )

    # ------------------------------------------------------------------
    # Attack Pattern (MITRE ATT&CK)
    # ------------------------------------------------------------------

    def create_attack_pattern(self, attack_type: str) -> Optional[stix2.AttackPattern]:
        mapping = ATTACK_PATTERN_MAP.get(attack_type)
        if not mapping:
            return None
        technique_id, technique_name = mapping
        return stix2.AttackPattern(
            name=technique_name,
            description=f"MITRE ATT&CK technique associated with '{attack_type}' activity observed in honeypots.",
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=technique_id,
                    url=f"https://attack.mitre.org/techniques/{technique_id}/",
                )
            ],
            custom_properties={"x_mitre_id": technique_id},
        )

    # ------------------------------------------------------------------
    # Note with honeypot statistics
    # ------------------------------------------------------------------

    def create_ioc_note(
        self, ioc_value: str, ioc: dict, obs_id: str
    ) -> Optional[stix2.Note]:
        attack_count = ioc.get("attack_count")
        interaction_count = ioc.get("interaction_count")
        login_attempts = ioc.get("login_attempts")
        destination_port_count = ioc.get("destination_port_count")
        recurrence = ioc.get("recurrence_probability")

        # Only create a note when there is at least some numeric data worth recording
        if all(
            v is None
            for v in (
                attack_count,
                interaction_count,
                login_attempts,
                destination_port_count,
                recurrence,
            )
        ):
            return None

        lines = [f"GreedyBear honeypot statistics for {ioc_value}:"]
        if attack_count is not None:
            lines.append(f"- Attack count: {attack_count}")
        if interaction_count is not None:
            lines.append(f"- Interaction count: {interaction_count}")
        if login_attempts is not None:
            lines.append(f"- Login attempts: {login_attempts}")
        if destination_port_count is not None:
            lines.append(f"- Destination port count: {destination_port_count}")
        if recurrence is not None:
            lines.append(f"- Recurrence probability: {recurrence:.2%}")

        content = "\n".join(lines)
        return stix2.Note(
            id=Note.generate_id(content, datetime.now(tz=timezone.utc).isoformat()),
            abstract=f"GreedyBear stats: {ioc_value}",
            content=content,
            authors=[self.author.name],
            object_refs=[obs_id],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
        )

    # ------------------------------------------------------------------
    # Full IoC conversion from advanced/standard feed entry
    # ------------------------------------------------------------------

    def ioc_to_stix_objects(self, ioc: dict, create_indicators: bool = True) -> list:
        """
        Convert a single GreedyBear IoC dict into STIX 2.1 objects + relationships.

        GreedyBear JSON response fields (from FeedsResponseSerializer):
          value (str)               — IP or domain (NOT "ip"!)
          feed_type (list[str])     — list of honeypot names that observed this IoC
          scanner (bool)
          payload_request (bool)
          first_seen (str)          — "YYYY-MM-DD"
          last_seen (str)           — "YYYY-MM-DD"
          attack_count (int)
          interaction_count (int)
          ip_reputation (str)       — e.g. "mass scanner", "known attacker", ""
          firehol_categories (list)
          asn (int | None)          — ASN number (integer, NOT "asX")
          destination_port_count (int)
          login_attempts (int)
          recurrence_probability (float 0-1)
          expected_interactions (float)
          attacker_country (str)    — full country name
          attacker_country_code (str) — ISO 3166-1 alpha-2, USE THIS for Location
          tags (list[{key, value, source}])
          sensors (list[{address, label}])
        """
        objects = []

        # "value" is the canonical field name in GreedyBear responses
        ioc_value = ioc.get("value") or ioc.get("ip") or ioc.get("ioc")
        if not ioc_value:
            return objects

        first_seen = self._parse_dt(ioc.get("first_seen"))
        last_seen = self._parse_dt(ioc.get("last_seen"))

        # -- Build labels from honeypot names, reputation, and attack type --
        honeypots = ioc.get("feed_type") or []
        if isinstance(honeypots, str):
            honeypots = [honeypots]
        honeypots = [h for h in honeypots if h and h != "all"]

        labels: list[str] = list(honeypots)
        reputation = ioc.get("ip_reputation") or ""
        if reputation:
            labels.append(reputation)
        attack_type = self._derive_attack_type(ioc)
        if attack_type:
            labels.append(attack_type)

        # Create the observable (IP or domain)
        if self._is_ipv4(ioc_value) or self._is_ipv6(ioc_value):
            obs = self.create_ip_observable(ioc_value, labels or None)
        elif self._is_domain(ioc_value):
            obs = self.create_domain_observable(ioc_value, labels or None)
        else:
            self.helper.connector_logger.warning(
                "[CONVERTER] Skipping value that is neither IP nor domain",
                {"value": ioc_value},
            )
            return objects

        if obs is None:
            return objects
        objects.append(obs)

        # -- Country: use attacker_country_code (alpha-2), NOT attacker_country (full name) --
        country_code = ioc.get("attacker_country_code") or ioc.get("attacker_country")
        if country_code and len(country_code) == 2:
            country = self.create_country_location(country_code)
            if country:
                objects.append(country)
                objects.append(
                    self.create_relationship(obs.id, "located-at", country.id)
                )

        # -- ASN: field is "asn" (integer) --
        asn_raw = ioc.get("asn")
        if asn_raw is None:
            asn_raw = ioc.get("autonomous_system")
        if asn_raw is not None:
            try:
                asn_number = int(str(asn_raw).replace("AS", "").strip())
                asn_obj = self.create_asn(asn_number, ioc.get("as_name", ""))
                objects.append(asn_obj)
                objects.append(
                    self.create_relationship(obs.id, "belongs-to", asn_obj.id)
                )
            except (ValueError, TypeError):
                pass

        # -- Honeypot infrastructure: Infrastructure -[consists-of]-> Observable --
        # (NOT obs -[communicates-with]-> Infrastructure — that direction is invalid in OpenCTI)
        hp_objects: list[stix2.Infrastructure] = []
        for hp_name in honeypots:
            hp_obj = self.create_honeypot_infrastructure(hp_name)
            objects.append(hp_obj)
            hp_objects.append(hp_obj)
            objects.append(
                self.create_relationship(
                    hp_obj.id,
                    "consists-of",
                    obs.id,
                    start_time=first_seen,
                    stop_time=last_seen,
                )
            )

        # -- Indicator (optional, controlled by create_indicators flag) --
        if create_indicators:
            indicator_pattern = (
                f"[ipv4-addr:value = '{ioc_value}']"
                if self._is_ipv4(ioc_value)
                else (
                    f"[ipv6-addr:value = '{ioc_value}']"
                    if self._is_ipv6(ioc_value)
                    else f"[domain-name:value = '{ioc_value}']"
                )
            )
            indicator = stix2.Indicator(
                id=Indicator.generate_id(indicator_pattern),
                name=ioc_value,
                pattern=indicator_pattern,
                pattern_type="stix",
                valid_from=first_seen or datetime.now(tz=timezone.utc),
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                    "x_opencti_labels": labels if labels else None,
                },
            )
            objects.append(indicator)
            objects.append(self.create_relationship(indicator.id, "based-on", obs.id))
            # indicates -> each honeypot infrastructure
            for hp_obj in hp_objects:
                objects.append(
                    self.create_relationship(indicator.id, "indicates", hp_obj.id)
                )
            # indicates -> attack pattern (if known)
            if attack_type:
                ap = self.create_attack_pattern(attack_type)
                if ap:
                    objects.append(ap)
                    objects.append(
                        self.create_relationship(indicator.id, "indicates", ap.id)
                    )
        elif attack_type:
            # No indicator requested but attack pattern still useful as context
            ap = self.create_attack_pattern(attack_type)
            if ap:
                objects.append(ap)

        # -- Note with raw honeypot statistics --
        note = self.create_ioc_note(ioc_value, ioc, obs.id)
        if note:
            objects.append(note)

        return objects

    @staticmethod
    def _derive_attack_type(ioc: dict) -> Optional[str]:
        """
        GreedyBear returns boolean flags `scanner` and `payload_request`.
        Map them back to attack_type strings for MITRE mapping.
        """
        if ioc.get("scanner"):
            return "scanner"
        if ioc.get("payload_request"):
            return "payload_request"
        # Fallback: explicit attack_type string from advanced feed query param
        return ioc.get("attack_type") or None

    # ------------------------------------------------------------------
    # ASN feed conversion
    # ------------------------------------------------------------------

    def asn_entry_to_stix_objects(self, entry: dict) -> list:
        """
        Convert a GreedyBear ASN aggregated feed entry into STIX objects.

        Fields (from asn_aggregated_queryset):
          asn (int), as_name (str), ioc_count, total_attack_count,
          total_interaction_count, total_login_attempts,
          honeypots (list[str]), expected_ioc_count, expected_interactions,
          first_seen (datetime str), last_seen (datetime str)
        """
        objects = []

        asn_raw = entry.get("asn")
        if asn_raw is None:
            return objects
        try:
            asn_number = int(asn_raw)
        except (ValueError, TypeError):
            return objects

        # Field is "as_name" in GreedyBear's ASN feed (NOT "asn_name")
        as_name = entry.get("as_name") or ""
        asn_obj = self.create_asn(asn_number, as_name)
        objects.append(asn_obj)

        first_seen = self._parse_dt(entry.get("first_seen"))
        last_seen = self._parse_dt(entry.get("last_seen"))

        honeypots = entry.get("honeypots", [])
        if isinstance(honeypots, str):
            honeypots = [honeypots]
        for hp_name in honeypots:
            if not hp_name:
                continue
            hp_obj = self.create_honeypot_infrastructure(hp_name)
            objects.append(hp_obj)
            # Infrastructure -[consists-of]-> AutonomousSystem is not valid either.
            # Use: AutonomousSystem -[belongs-to]-> Infrastructure is also not valid.
            # Valid option for ASN<->Infrastructure: no direct relationship in OpenCTI schema.
            # Instead record that the ASN was seen at these honeypots via a Note-style
            # relationship — we skip the invalid rel and let the shared Infrastructure node
            # provide the implicit link when IoC objects also point to the same hp_obj.

        return objects

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_dt(value) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(str(value), fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
        return None
