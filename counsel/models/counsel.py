import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Self

from pydantic import AnyHttpUrl, BaseModel

from counsel.models.syft import SyftModel


class Severity(str, Enum):
    UNKNOWN = "unknown"
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def threshold(cls, severity: Self) -> List[Self]:
        severities = list(iter(cls))
        return severities[severities.index(severity) : :]


class ContainerStatus(str, Enum):
    RESTARTING = "restarting"
    RUNNING = "running"
    PAUSED = "paused"
    EXITED = "exited"


class Image(BaseModel):
    id: str
    labels: Dict[str, Any]
    tags: List[str]
    short_id: str


class Container(BaseModel):
    id: str
    name: str
    image: Image
    labels: Dict[str, Any]
    status: ContainerStatus
    short_id: str


class BOM(SyftModel):
    pass


class Artifact(BaseModel):
    name: str
    version: str
    type: str


class Vulnerability(BaseModel):
    id: str
    source: AnyHttpUrl
    artifact: Artifact
    namespace: str
    severity: Severity
    description: str | None


class VulnerabilitiesSummary(BaseModel):
    image_id: str
    tags: List[str]
    issuing_date: datetime = datetime.now()
    vulnerabilities: List[Vulnerability]

    @classmethod
    def parse_grype_dict(
        cls, grype_dict: dict[str, Any], issuing_date: datetime | None = None
    ) -> "VulnerabilitiesSummary":
        if issuing_date is None:
            issuing_date = datetime.now()

        summary = {
            "image_id": grype_dict["source"]["target"]["imageID"],
            "tags": grype_dict["source"]["target"]["tags"],
            "vulnerabilities": [],
            "issuing": issuing_date,
        }

        # Extract CVEs
        for m in grype_dict["matches"]:
            artifact = {
                "name": m["artifact"]["name"],
                "version": m["artifact"]["version"],
                "type": m["artifact"]["version"],
            }

            summary["vulnerabilities"].append(
                {
                    "id": m["vulnerability"]["id"],
                    "source": m["vulnerability"]["dataSource"],
                    "artifact": artifact,
                    "namespace": m["vulnerability"]["namespace"],
                    "severity": m["vulnerability"]["severity"].lower(),
                    "description": m["vulnerability"].get("description"),
                }
            )

        return cls.parse_obj(summary)

    @classmethod
    def parse_grype_json(cls, grype_str: str) -> "VulnerabilitiesSummary":
        return cls.parse_grype_dict(json.loads(grype_str))
