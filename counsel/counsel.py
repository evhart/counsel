import logging
import os
import sched
import tempfile
import time
from datetime import datetime
from subprocess import run
from typing import List, Tuple

import cachetools
import docker
from cachetools import Cache, TTLCache, cachedmethod
from croniter import croniter
from pydantic import BaseModel, FilePath, PrivateAttr
from rich import print

from counsel.models.counsel import BOM, Container, Image, VulnerabilitiesSummary
from counsel.policy import Policy

logger = logging.getLogger(__name__)


class Counsel(BaseModel):
    syft_path: FilePath = "syft"
    grype_path: FilePath = "grype"

    scan_all_schedule: str | None = None
    policies: List[Policy] = []
    # cache: Optional[FilePath] = None

    _docker_client: docker.models.configs.ConfigCollection = PrivateAttr(
        default_factory=docker.from_env
    )
    _methods_cache: Cache = PrivateAttr()  # type: ignore

    def __init__(self, **data) -> None:  # type: ignore
        super().__init__(**data)
        self._methods_cache = TTLCache(maxsize=32, ttl=60)

    def scan(
        self,
        image_id: str,
        apply_policies: bool = False,
        force_policies: bool = False,
    ) -> VulnerabilitiesSummary:
        v = self.vulnerabilities(image_id)
        if apply_policies:
            self.apply_policies(v.image_id, force_policies=force_policies)

        return v

    def scan_all(
        self, apply_policies: bool = False, force_policies: bool = False
    ) -> List[VulnerabilitiesSummary]:
        return [
            self.scan(
                i.id,
                apply_policies=apply_policies,
                force_policies=force_policies,
            )
            for i in self.images()
        ]

    def check_policies(
        self,
        image_id: str,
    ) -> Tuple[VulnerabilitiesSummary, List[Tuple[Policy, bool]]]:
        v = self.scan(image_id, apply_policies=False, force_policies=False)
        p = [p.check_policy(v) for p in self.policies]

        return v, list(zip(self.policies, p))

    def check_policies_all(
        self,
    ) -> List[Tuple[VulnerabilitiesSummary, List[Tuple[Policy, bool]]]]:
        return [
            self.check_policies(
                i,
            )
            for i in self.images()
        ]

    def apply_policies(
        self, image_id: str, force_policies: bool = False
    ) -> Tuple[VulnerabilitiesSummary, List[Tuple[Policy, bool]]]:
        v = self.scan(image_id=image_id, apply_policies=False, force_policies=False)
        p = [p.apply_policy(v, force=force_policies) for p in self.policies]

        return v, list(zip(self.policies, p))

    def apply_policies_all(
        self, force_policies: bool = False
    ) -> List[Tuple[VulnerabilitiesSummary, List[Tuple[Policy, bool]]]]:
        return [
            self.apply_policies(i, force_policies=force_policies) for i in self.images()
        ]

    def _containers(self) -> Tuple[List[Container], List[Image]]:
        client = self._docker_client

        # Get running containers (by default only show running containers):
        images = {}
        countainers_list = []

        for container in client.containers.list():
            image = container.image

            i = Image(
                id=image.id,
                labels=image.labels,
                tags=image.tags,
                short_id=image.short_id,
            )

            c = Container(
                id=container.id,
                name=container.name,
                image=i,
                labels=container.labels,
                status=container.status,
                short_id=container.short_id,
            )

            images[i.id] = i
            countainers_list.append(c)

        return countainers_list, list(images.values())

    def containers(self) -> List[Container]:
        return self._containers()[0]

    def images(self) -> List[Image]:
        return self._containers()[1]

    @cachedmethod(
        lambda self: self._methods_cache, key=cachetools.keys.methodkey  # type: ignore
    )  # noaq E501
    def bom(self, image_id: str) -> BOM:
        data = run(
            [self.syft_path, "--quiet", "-o", "json", image_id],
            capture_output=True,
        )
        # data = json.loads(data.stdout)
        return BOM.parse_raw(data.stdout)

    @cachedmethod(
        lambda self: self._methods_cache, key=cachetools.keys.methodkey  # type: ignore
    )  # noaq E501
    def vulnerabilities(self, image_id: str) -> VulnerabilitiesSummary:
        # Analyse vulnerabilities using Grype:
        # Create temporary file for analysis:
        v = VulnerabilitiesSummary(image_id=image_id, tags=[], vulnerabilities=[])
        bom = self.bom(image_id)

        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as tmp:
                tmp.write(bom.json(by_alias=True))

            data = run(
                [self.grype_path, "--quiet", "-o", "json", path],
                capture_output=True,
            )

            v = VulnerabilitiesSummary.parse_grype_json(data.stdout)  # type: ignore

        finally:
            os.remove(path)

        return v

    def run_schedule(
        self, initial_scan: bool = False, apply_policies: bool = True
    ) -> None:
        cron_itr = croniter(self.scan_all_schedule)  # type: ignore
        scheduler = sched.scheduler(timefunc=time.time)

        print(f"Cron schedule is: '{self.scan_all_schedule}'")

        if initial_scan:
            print("Runnint initial scan before scheduling (initial_scan=True).")
            self.scan_all(apply_policies=apply_policies)
        try:
            while True:
                t = cron_itr.get_next(datetime)
                print(f"The next scan is scheduled at: {t}.")
                scheduler.enterabs(
                    t.timestamp(),
                    1,
                    self.scan_all,
                    kwargs={"apply_policies": apply_policies},
                )
                scheduler.run()
        except KeyboardInterrupt:
            print("Stopping scheduler")
        finally:
            for e in scheduler.queue:
                scheduler.cancel(e)
