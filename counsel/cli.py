import logging
from datetime import timedelta

import typer
import urllib3
from rich.logging import RichHandler

import counsel
from counsel.counsel import Counsel
from counsel.models.counsel import Severity
from counsel.policy import Policy, SlackNotification

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, tracebacks_suppress=[typer, urllib3])],
)
logging.getLogger("docker").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("apprise").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logger.setLevel(level="INFO")

app = typer.Typer()


@app.command()
def callback(
    scan_schedule: str = typer.Option(
        "", envvar="COUNSEL_SCAN_SHEDULE", help="Schedule when to run Counsel."
    ),
    initial_scan: bool = typer.Option(
        False,
        "--initial-scan",
        envvar="COUNSEL_INITIAL_SCAN",
        help="Run an initial scan before starting the scheduler.",
    ),
    alert_threshold: Severity = typer.Option(
        default="high",
        case_sensitive=False,
        envvar="COUNSEL_THRESHOLD",
        help="Minimum vulnerability threshold for raising an alert.",
    ),
    remind_delay: int = typer.Option(
        default=10,
        envvar="COUNSEL_REMIND_DELAY",
        help="When a notification/action reminder should be sent (in days).",
    ),
    kill_delay: int = typer.Option(
        default=14,
        envvar="COUNSEL_KILL_DELAY",
        help="When the final notification/action should be sent (in days).",
    ),
    slack_webhook_url: str = typer.Option(
        default="",
        envvar="COUNSEL_SLACK_URL",
        help="Slack webhook URL for alert notifications.",
    ),
    slack_msg_template: str = typer.Option(
        default="",
        envvar="COUNSEL_SLACK_MSG_TEMPLATE_PATH",
        help="Slack Jinja2 template for alert notifications.",
    ),
) -> None:
    """🕵️‍♀️ Counsel - A tool for monitoring the vulnerabilities of docker containers."""  # noqa E501

    logger.info(f"Running Counsel version: {counsel.__version__}")
    logger.info("Parameters:")
    if scan_schedule:
        logger.info(f"  - COUNSEL_SCAN_SHEDULE: {scan_schedule}")
    logger.info(f"  - COUNSEL_THRESHOLD: {alert_threshold.value}")
    logger.info(f"  - COUNSEL_REMIND_DELAY: {remind_delay}")

    if slack_webhook_url:
        logger.info(f"  - COUNSEL_SLACK_URL: {slack_webhook_url}")

    if slack_msg_template:
        logger.info(f"  - COUNSEL_SLACK_MSG_TEMPLATE_PATH: {slack_webhook_url}")

    # logger.info(logging.Logger.manager.loggerDict)

    cs = Counsel()
    if scan_schedule != "":
        cs.scan_all_schedule = scan_schedule

    # TODO: Allow parameter for policies, probably using a configuration file
    severity_threshold = Severity.threshold(alert_threshold)
    cs.policies.append(Policy(name="warn", severities=severity_threshold))
    cs.policies.append(
        Policy(
            name="remind",
            severities=severity_threshold,
            delay=timedelta(days=remind_delay),
        )
    )
    cs.policies.append(
        Policy(
            name="kill",
            severities=severity_threshold,
            delay=timedelta(days=kill_delay),
        )
    )

    if slack_webhook_url != "":
        slack = SlackNotification(slack_webhook_url=slack_webhook_url)
        if slack_msg_template != "":
            slack.template_path = slack_msg_template

        cs.policies.append(
            Policy(name="warn/slack", severities=severity_threshold, action=slack)
        )
        cs.policies.append(
            Policy(
                name="remind/slack",
                severities=severity_threshold,
                delay=timedelta(days=remind_delay),
                action=slack,
            )
        )
        cs.policies.append(
            Policy(
                name="kill/slack",
                severities=severity_threshold,
                delay=timedelta(days=kill_delay),
                action=slack,
            )
        )

    logger.info("Policies")
    for pol in cs.policies:
        logger.info(
            f"  - {pol.name} at {str(pol.delay or 'Now')}: {str(pol.description or '')} ({pol.action.__class__.__name__})"  # noqa: E501
        )

    if scan_schedule != "":
        cs.run_schedule(initial_scan=initial_scan)
    else:
        cs.scan_all(apply_policies=True)


if __name__ == "__main__":
    app()
