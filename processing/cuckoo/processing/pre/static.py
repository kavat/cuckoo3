# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.
import os.path

from cuckoo.common.config import cfg
from cuckoo.common.storage import Paths, Binaries
from cuckoo.common.external_interactions import anubi_analyze_single_file

from ..abtracts import Processor
from ..static.pe import PEFile
from ..static.strings_analysis import StringsDetonation
from ..static.office import OfficeDocument
from ..static.pdf import PDFFile
from ..errors import StaticAnalysisError

class StringsAnalysis(Processor):

    CATEGORY = ["file"]
    KEY = "strings"

    def start(self):
        target = self.ctx.result.get("target")

        file_path, _ = Binaries.path(Paths.binaries(), target.sha256)
        if os.path.getsize(file_path) < 1:
            return {}

        return StringsDetonation(file_path)


class AnubiAnalysis(Processor):

    CATEGORY = ["file"]
    KEY = "anubi"

    @classmethod
    def enabled(cls):
        return cfg("anubi", "enabled", subpkg="processing")

    def start(self):
        target = self.ctx.result.get("target")

        file_path, _ = Binaries.path(Paths.binaries(), target.sha256)
        if os.path.getsize(file_path) < 1:
            return {}

        return anubi_analyze_single_file(file_path, target.orig_filename)

class FileInfoGather(Processor):

    CATEGORY = ["file"]
    KEY = "static"

    _EXTENSION_HANDLER = {
        (".exe", ".dll"): (PEFile, "pe"),
        # Word
        (".doc", ".docm", ".wbk", ".dotm", ".dotx", ".docb", ".docx",
        # Hangul word processor
          ".hwp",
        # Powerpoint
          ".ppt", ".pptm", ".pptx", ".potm", ".ppam", ".ppsm", ".potx",
          ".ppsx", ".sldx", ".sldm",
        # Excel
          "xls", "xlsm", "xlsx", "xlm", "xlt", "xltx", "xltm",
          "xlsb", "xla", "xlam", "xll", "xlw",): (OfficeDocument, "office"),
        # PDF
        (".pdf"): (PDFFile, "pdf")
    }

    def start(self):
        target = self.ctx.result.get("target")

        file_path, _ = Binaries.path(Paths.binaries(), target.sha256)
        if os.path.getsize(file_path) < 1:
            return {}

        data = {}
        subkey = None

        for ext, handler_subkey in self._EXTENSION_HANDLER.items():

            if not target.filename.lower().endswith(ext):
                continue

            handler, subkey = handler_subkey
            try:
                data = handler(file_path).to_dict()
            except StaticAnalysisError as e:
                self.ctx.log.warning(
                    "Failed to run static analysis handler",
                    handler=handler, error=e
                )
            except Exception as e:
                err = "Unexpected error while running static analysis handler"
                self.ctx.log.exception(err, handler=handler, error=e)
                self.ctx.errtracker.add_error(
                    f"{err}. Handler: {handler}. Error: {e}"
                )

            break

        if data:
            return {
                subkey:data
            }

        return {}
