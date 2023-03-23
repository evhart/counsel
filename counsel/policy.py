import importlib
import logging
from datetime import datetime, timedelta
from typing import List

import apprise
from jinja2 import Template
from pydantic import AnyHttpUrl, BaseModel, FilePath

from counsel.models.counsel import Severity, VulnerabilitiesSummary

logger = logging.getLogger(__name__)


# TODO Consider passing issuing policy (so actions can alter the policy, e.g., cleanup).
class Action(BaseModel):
    def __call__(self, vulnerability_summary: VulnerabilitiesSummary) -> None:
        self.run(vulnerability_summary)

    def run(self, vulnerability_summary: VulnerabilitiesSummary) -> None:
        logger.info(f"Running action for {vulnerability_summary.image_id}")
        logger.info(
            f'  - Vulnerabilities found for "{vulnerability_summary.image_id}": {len(vulnerability_summary.vulnerabilities)}'  # noqa: E501
        )
        logger.info("  - High/Critical Vulnerabilities:")
        for v in vulnerability_summary.vulnerabilities:
            if v.severity.value in ["high", "critical"]:
                logger.info(
                    f"      - { v.id} - {v.artifact.name}/{v.artifact.version} ({v.severity.value}) - {v.source}"  # noqa: E501
                )


class SlackNotification(Action):
    slack_webhook_url: AnyHttpUrl
    template_path: FilePath = importlib.resources.files(  # type: ignore
        "counsel.assets.templates"
    ).joinpath("slack.md.j2")

    def run(self, vulnerability_summary: VulnerabilitiesSummary) -> None:
        logger.info(f"Running slack action for: {vulnerability_summary.image_id}")
        logger.info(f"Reading Jinja2 template from file: {self.template_path}")

        with open(self.template_path) as f:
            template = Template(f.read())

        msg = self.render_template(vulnerability_summary, template)
        apobj = apprise.Apprise(f"{self.slack_webhook_url}?footer=no")

        logger.info(f"Notifying: {self.slack_webhook_url}")

        apobj.notify(body=msg)

    @classmethod
    def render_template(
        cls, vulnerability_summary: VulnerabilitiesSummary, template: Template
    ) -> str:
        logger.info("Rendering Jinja2 template")
        return template.render(
            vulnerabilities=vulnerability_summary.vulnerabilities,
            tags=vulnerability_summary.tags,
            image_id=vulnerability_summary.image_id,
        )


# TODO Implement ways to keep the old/pending issuing_date
# (so running policies are kept between image updates).
# TODO Remove from history if images has diapeared
# (e.g. if image as not be  proceesed for a while.).
class Policy(BaseModel):
    """A policy is applied based as soon as the constrains are met."""

    name: str
    severities: List[Severity] = Severity.threshold(Severity.HIGH)
    action: Action = Action()
    delay: timedelta | None = None  # timedelta(days=14)
    description: str | None = None

    execution_history: List[str] = []

    def check_policy(self, vulnerabilities_summary: VulnerabilitiesSummary) -> bool:
        logger.info(f"Checking policy for: {vulnerabilities_summary.image_id}")
        # sourcery skip: use-any, use-next
        # Check agains history:
        history_pass = False
        if vulnerabilities_summary.image_id in self.execution_history:
            logger.info("  - History check: FAIL")
            return False
        else:
            logger.info("  - History check: PASS")
            history_pass = True

        # Validate delta:
        delay_pass = False
        if self.delay and datetime.now() < (
            vulnerabilities_summary.issuing_date + self.delay
        ):
            logger.info("  - Delay check: FAIL")
            return False
        else:
            logger.info("  - Delay check: PASS")
            delay_pass = True

        # Validate severity:πP
        severity_pass = False
        for v in vulnerabilities_summary.vulnerabilities:
            if v.severity in self.severities:
                logger.info("  - Severity check: PASS")
                severity_pass = True
                break
        if not severity_pass:
            logger.info("  - Severity check: FAIL")

        return history_pass and delay_pass and severity_pass

    def check_policies(
        self, vulnerabilities_summaries: List[VulnerabilitiesSummary]
    ) -> List[bool]:
        return [self.check_policy(v) for v in vulnerabilities_summaries]

    def apply_policy(
        self, vulnerabilities_summary: VulnerabilitiesSummary, force: bool = False
    ) -> bool:
        logger.info(
            f"Attempting to apply policy for: {vulnerabilities_summary.image_id}"
        )
        if self.check_policy(vulnerabilities_summary) or force:
            self.action(vulnerabilities_summary)

            if vulnerabilities_summary.image_id not in self.execution_history:
                self.execution_history.append(vulnerabilities_summary.image_id)

            return True

        return False

    def apply_policies(
        self,
        vulnerabilities_summaries: List[VulnerabilitiesSummary],
        force: bool = False,
    ) -> List[bool]:
        return [self.apply_policy(v, force=force) for v in vulnerabilities_summaries]
