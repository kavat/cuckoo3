# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

from cuckoo.common.config import cfg
from cuckoo.common import virustotalk

from ..abtracts import Processor
from ..signatures.signature import Scores, IOC

class VirustotalK(Processor):

    CATEGORY = ["file", "url"]
    KEY = "virustotalk"

    def init(self):
        self.min_suspicious = cfg(
            "virustotal", "min_suspicious", subpkg="processing"
        )
        self.min_malicious = cfg(
            "virustotal", "min_malicious", subpkg="processing"
        )

    def _handle_file_target(self):
        try:
            return virustotalk.fileinfo_request(
                self.ctx.result.get("target").sha256
            )
        except Exception as e:
            self.ctx.log.warning(
                "Error while making Virustotal request", error=e
            )

        return None

    def _handle_url_target(self):
        try:
            return virustotalk.urlinfo_request(
                self.ctx.result.get("target").url
            )
        except Exception as e:
            self.ctx.log.warning(
                "Error while making Virustotal request", error=e
            )

        return None

    def start(self):
        info = None
        if self.ctx.analysis.category == "file":
            info = self._handle_file_target()
        elif self.ctx.analysis.category == "url":
            info = self._handle_url_target()

        if not info:
            return {}

        if 'error' in info and info['error'] == 'ko':
            self.ctx.log.error(
                "Error on Virustotal request", error=info['msg']
            )
            self.ctx.log.error(
                "Hits returned", hits=info
            )
            return {}
        
        if 'stats' not in info:
            self.ctx.log.error(
                "Error on Virustotal response", error="missed 'stats'"
            )
            self.ctx.log.error(
                "Hits returned", hits=info
            )
            return {}

        if 'avs' not in info:
            self.ctx.log.error(
                "Error on Virustotal response", error="missed 'avs'"
            )
            self.ctx.log.error(
                "Hits returned", hits=info
            )
            return {}

        malicious_count = info["stats"]["malicious"]

        score = 0
        if malicious_count >= self.min_malicious:
            score = Scores.KNOWN_BAD
        elif malicious_count >= self.min_suspicious:
            # Suspicious. Decide what scores to use Cuckoo-wide and document.
            score = Scores.SUSPICIOUS

        if score:
            iocs = [
                IOC(antivirus=avname)
                for avname, avinfo in info["avs"].items()
                if avinfo["category"] == "malicious"
            ]

            self.ctx.signature_tracker.add_signature(
                name="virustotal",
                score=score,
                short_description="Virustotal sources report this target as "
                                  "malicious",
                description=f"{malicious_count} Virustotal antivirus engines "
                            f"detect this target as malicious",
                iocs=iocs
            )

        return info
