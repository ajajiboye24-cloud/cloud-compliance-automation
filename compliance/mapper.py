import yaml


def load_control_mappings(file_path="compliance/control_mapping.yaml"):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)


def enrich_finding(finding, mappings):
    control_id = finding.get("control_id")

    mapping = mappings.get(control_id, {})

    enriched_finding = {
        **finding,
        "category": mapping.get("category", "Unmapped"),
        "control_objective": mapping.get("control_objective", "No control objective mapped."),
        "framework_mappings": mapping.get("framework_mappings", {})
    }

    return enriched_finding