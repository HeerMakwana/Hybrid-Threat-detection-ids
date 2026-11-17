from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DECODER = ROOT / "wazuh" / "decoders" / "multi_domain_ids_decoder.xml"
RULES = ROOT / "wazuh" / "rules" / "multi_domain_ids_rules.xml"
AGENT = ROOT / "wazuh" / "agent" / "multi_domain_ids.conf"


def validate() -> None:
    decoder_root = ET.parse(DECODER).getroot()
    rules_root = ET.parse(RULES).getroot()
    agent_root = ET.parse(AGENT).getroot()

    if decoder_root.tag != "decoder" or decoder_root.findtext("plugin_decoder") != "JSON_Decoder":
        raise ValueError("The decoder must configure Wazuh's JSON_Decoder plugin")

    ids = [rule.get("id") for rule in rules_root.findall(".//rule")]
    if any(rule_id is None for rule_id in ids) or len(ids) != len(set(ids)):
        raise ValueError("Wazuh rule IDs must be present and unique")
    if not rules_root.findall(".//decoded_as"):
        raise ValueError("At least one Wazuh rule must reference the JSON decoder")

    localfile = agent_root if agent_root.tag == "localfile" else agent_root.find("localfile")
    if localfile is None or localfile.findtext("log_format") != "json":
        raise ValueError("The agent configuration must collect JSON-formatted logs")
    if not localfile.findtext("location"):
        raise ValueError("The agent configuration must specify the alert log path")


if __name__ == "__main__":
    validate()
    print("XML well-formed and required integration elements are present.")
    print("This does not replace validation with Wazuh manager --test-config or logtest.")
