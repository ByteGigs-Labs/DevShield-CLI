import json
from pathlib import Path

from devshield.core.models import ScanResult

target = Path(__file__).resolve().parent.parent / "docs" / "schema" / "scan-result.schema.json"
target.parent.mkdir(parents=True, exist_ok=True)
schema = ScanResult.model_json_schema()
schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
schema["$id"] = (
    "https://github.com/ByteGigs-Labs/DevShield-CLI/blob/main/docs/schema/scan-result.schema.json"
)
target.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
