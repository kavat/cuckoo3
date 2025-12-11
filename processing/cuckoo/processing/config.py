# Copyright (C) 2019-2023 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

from cuckoo.common import config

from .signatures.signature import Levels


class ScoringLevel(config.String):
    def constraints(self, value):
        super().constraints(value)

        try:
            Levels.to_score(value)
        except KeyError:
            raise config.ConstraintViolationError(
                f"Invalid score level {value}. "
                f"Possible levels: {list(Levels.LEVEL_SCORE.keys())}"
            )


exclude_autoload = []
typeloaders = {
    "identification.yaml": {
        "tags": config.Dict(
            config.List(config.String),
            allow_empty=True,
            default_val={
                "office": ["microsoft_word", "microsoft_excel", "microsoft_powerpoint"],
                "dotnet": ["microsoft_dotnet"],
                "powershell": ["powershell"],
                "pdfreader": ["acrobat_reader"],
                "flash": ["flash"],
                "java": ["oracle_java"],
                "ruby": ["ruby"],
                "perl": ["perl"],
                "python": ["python"],
                "mediaplayer": ["mediaplayer"],
                "quicktime": ["quicktime"],
                "ace": ["ace"],
                "arc": ["arc"],
                "unarchive": ["unarchive"],
            },
        ),
        "log_unidentified": config.Boolean(default_val=False),
        "selection": {
            "extension_priority": config.List(
                config.String,
                allow_empty=True,
                default_val=[
                    "exe",
                    "msi",
                    "docm",
                    "dotm",
                    "doc",
                    "xlam",
                    "xlsm",
                    "xlsb",
                    "xls",
                    "ppsm",
                    "pptm",
                    "ppt",
                    "ps1",
                    "vbs",
                    "bat",
                    "hta",
                    "jar",
                    "iqy",
                    "slk",
                    "wsf",
                    "lnk",
                    "url",
                    "pdf",
                    "dll",
                ],
            )
        },
    },
    "anubi.yaml": {
      "enabled": config.Boolean(default_val=True),
      "local_rules": config.Boolean(default_val=False)
    },
    "virustotal.yaml": {
        "enabled": config.Boolean(default_val=True),
        "key": config.String(
            allow_empty=True,
            default_val="",
            sensitive=True,
        ),
        "url_noapikey": config.String(
            default_val="https://www.virustotal.com/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={}"
        ),
        "user_agents": config.List(
            config.String,
            default_val=[
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (X11; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.85',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.85'
            ]
        ),
        "cookies": config.Dict(
            config.String,
            default_val={
                '_ga_BLNDV9X2JR': 'GS1.1.1717576452.39.1.1717576854.0.0.0',
                '_ga': 'GA1.2.1169951016.1704279517',
                '_ga_1R8YHMJVFG': 'GS1.1.1714652776.3.0.1714652784.0.0.0',
                '__gsas': 'ID=79a4a8fd03f29f9b:T=1712063204:RT=1712063204:S=ALNI_Maz-ZYDcSc1EgL1DpHgz3-ivVxxrg',
                'new-privacy-policy-accepted': '1',
                'ssm_au_c': 'k9UToAOr0Mqb8mnL8w3ck83XEpOB9aA+oY5alc21plKQgAAAAFiKHoOIczxzLLmP3fNNH8tb/FJZ1FoeD2BJoVHptZaM=',
                'ssm_au_d': '1',
                '_gid': 'GA1.2.1975526599.1717570596',
                '_gat': '1'
            }
        ),
        "request_headers": config.Dict(
            config.String,
            default_val={
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.virustotal.com/',
                'content-type': 'application/json',
                'X-Tool': 'vt-ui-main',
                'x-app-version': 'v1x28x5',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Connection': 'keep-alive'
            }
        ),
        "min_suspicious": config.Int(default_val=3, min_value=1),
        "min_malicious": config.Int(default_val=5, min_value=1),
    },
    "irma.yaml": {
        "enabled": config.Boolean(default_val=False),
        "min_suspicious": config.Int(default_val=3, min_value=1),
        "min_malicious": config.Int(default_val=5, min_value=1),
        "timeout": config.Int(default_val=60, min_value=0),
        "scan": config.Boolean(default_val=False),
        "force": config.Boolean(default_val=False),
        "url": config.HTTPUrl(),
        "probes": config.String(),
        "submitter": config.String(),
        "rescan_time": config.Int(default_val=15, min_value=1),
    },
    "mhr.yaml": {
        "enabled": config.Boolean(default_val=False),
        "timeout": config.Int(default_val=60, min_value=0),
        "url": config.HTTPUrl(),
        "user": config.String(allow_empty=True),
        "password": config.String(allow_empty=True),
        "min_suspicious": config.Int(default_val=10, min_value=1),
        "min_malicious": config.Int(default_val=30, min_value=1),
    },
    "misp.yaml": {
        "processing": {
            "enabled": config.Boolean(default_val=False),
            "url": config.HTTPUrl(),
            "verify_tls": config.Boolean(default_val=True),
            "key": config.String(sensitive=True),
            "timeout": config.Int(default_val=5, min_value=0),
            "pre": {
                "event_limit": config.Int(default_val=1, min_value=1),
                "query_ids_flag": config.Int(default_val=1, min_value=0, max_value=1),
                "publish_timestamp": config.String(default_val="365d"),
                "file": {"hashes": config.List(config.String, default_val=["sha256"])},
            },
            "post": {
                "query_limits": config.Dict(
                    config.Int, default_val={"dst_ip": 10, "domain": 10, "url": 10}
                ),
                "event_limits": config.Dict(
                    config.Int, default_val={"dst_ip": 1, "domain": 1, "url": 1}
                ),
                "query_ids_flags": config.Dict(
                    config.Int, default_val={"dst_ip": 1, "domain": 1, "url": 1}
                ),
                "publish_timestamps": config.Dict(
                    config.String,
                    default_val={"dst_ip": "365d", "domain": "365d", "url": "365d"},
                ),
            },
        },
        "reporting": {
            "enabled": config.Boolean(default_val=False),
            "url": config.HTTPUrl(),
            "verify_tls": config.Boolean(default_val=True),
            "key": config.String(sensitive=True),
            "timeout": config.Int(default_val=5, min_value=0),
            "min_score": config.Int(default_val=7, min_value=1, max_value=10),
            "web_baseurl": config.HTTPUrl(allow_empty=True),
            "event": {
                "distribution": config.Int(allow_empty=True),
                "sharing_group": config.Int(allow_empty=True),
                "threat_level": config.Int(allow_empty=True, min_value=0, max_value=4),
                "analysis": config.Int(allow_empty=True, min_value=0, max_value=2),
                "galaxy_mitre_attack": config.Boolean(default_val=True),
                "publish": config.Boolean(default_val=False),
                "tags": config.List(
                    config.String, default_val=["Cuckoo 3"], allow_empty=True
                ),
                "attributes": {
                    "ip_addresses": {
                        "include": config.Boolean(default_val=True),
                        "ids": config.Boolean(default_val=False),
                    },
                    "domains": {
                        "include": config.Boolean(default_val=True),
                        "ids": config.Boolean(default_val=False),
                    },
                    "urls": {
                        "include": config.Boolean(default_val=True),
                        "ids": config.Boolean(default_val=False),
                    },
                    "mutexes": {
                        "include": config.Boolean(default_val=True),
                        "ids": config.Boolean(default_val=False),
                    },
                    "sample_hashes": {
                        "include": config.Boolean(default_val=True),
                        "ids": config.Boolean(default_val=False),
                        "upload_sample": config.Boolean(default_val=False),
                    },
                },
            },
        },
    },
    "ai.yaml": {
        "processing": {
            "enabled": config.Boolean(default_val=False),
            "gemini_api_key": config.String(default_val=""),
            "gemini_api_model": config.String(default_val="gemini-2.5-flash")
        }
    },
    "intelmq.yaml": {
        "processing": {
            "enabled": config.Boolean(default_val=False),
            "hosts": config.List(config.HTTPUrl, ["http://127.0.0.1:9200"]),
            "index_name": config.String(),
            "query_limit": config.Int(default_val=10, min_value=1),
            "event_limit": config.Int(default_val=1, min_value=1, max_value=10000),
            "link_url": config.HTTPUrl(required=False),
        },
        "reporting": {
            "enabled": config.Boolean(default_val=False),
            "api_url": config.HTTPUrl(),
            "verify_tls": config.Boolean(default_val=True),
            "min_score": config.Int(default_val=7, min_value=1, max_value=10),
            "web_baseurl": config.HTTPUrl(allow_empty=True),
            "feed_accuracy": config.Int(allow_empty=True, min_value=0, max_value=100),
            "event_description": config.String(
                default_val="Cuckoo 3 behavioral analysis", allow_empty=True
            ),
        },
    },
    "elasticsearch.yaml": {
        "enabled": config.Boolean(default_val=False),
        "indices": {
            "names": {
                "analyses": config.String(default_val="analyses"),
                "tasks": config.String(default_val="tasks"),
                "events": config.String(default_val="events"),
            },
        },
        "timeout": config.Int(default_val=300),
        "max_result_window": config.Int(default_val=10000),
        "hosts": config.List(config.HTTPUrl, ["http://127.0.0.1:9200"]),
        "user": config.String(allow_empty=True),
        "password": config.String(allow_empty=True),
        "ca_certs": config.String(default_val="/etc/ssl/certs/ca-certificates.crt"),
    },
    "suricata.yaml": {
        "enabled": config.Boolean(default_val=False),
        "unix_sock_path": config.UnixSocketPath(
            default_val="/var/run/suricata/suricata-command.socket",
            must_exist=True,
            readable=True,
            writable=True,
        ),
        "process_timeout": config.Int(default_val=60),
        "evelog_filename": config.String(default_val="eve.json"),
        "classification_config": config.FilePath(
            default_val="/etc/suricata/classification.config",
            must_exist=True,
            readable=True,
        ),
        "classtype_scores": config.Dict(
            element_class=ScoringLevel,
            default_val={
                "command-and-control": "known bad",
                "exploit-kit": "known bad",
                "domain-c2": "malicious",
                "trojan-activity": "malicious",
                "targeted-activity": "likely malicious",
                "shellcode-detect": "likely malicious",
                "coin-mining": "likely malicious",
                "external-ip-check": "suspicious",
                "non-standard-protocol": "informational",
            },
        ),
        "ignore_sigids": config.List(config.Int, allow_empty=True),
    },
    "post.yaml": {
        "signatures": {
            "max_iocs": config.Int(default_val=100, min_value=1),
            "max_ioc_bytes": config.Int(default_val=1024 * 20, min_value=150),
        },
        "processes": {"max_processes": config.Int(default_val=100, min_value=1)},
    },
}
