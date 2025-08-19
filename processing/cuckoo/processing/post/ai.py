# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

import json
import google.generativeai as genai

from cuckoo.common.config import cfg
from cuckoo.common.storage import AnalysisPaths

from ..abtracts import Processor
from ..errors import DisablePluginError

class AIError(Exception):
    pass

class AIInfoGather(Processor):
    CATEGORY = ["file", "url"]
    KEY = "ai"

    @classmethod
    def enabled(cls):
        return cfg("ai.yaml", "processing", "enabled", subpkg="processing")

    @classmethod
    def init_once(cls):
        cls.gemini_api_key = cfg("ai.yaml", "processing", "gemini_api_key", subpkg="processing")
        cls.gemini_api_model = cfg("ai.yaml", "processing", "gemini_api_model", subpkg="processing")

    def init(self):
        try:
            genai.configure(api_key=self.gemini_api_key)
        except AIError as e:
            raise DisablePluginError(f"Failed to configura AI plugin. Error: {e}")

    def _get_content_for_report(self):

        content = ""

        with open(AnalysisPaths._path(self.ctx.analysis.id, "pre.json")) as f:
            d = json.load(f)

            if 'static' in d and 'pe' in d['static']:
                content = f"{content}\n### START GENERIC PARAGRAPH ###"
                content = f"{content}\nDESCRIPTION=Initial paragraph used to identify operative system used and SHA512 of file"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online SHA512 hash"
                content = f"{content}\nHEADER=OS platform;SHA512 file hash"
                content = f"{content}\nROW=windows;{d['target']['sha512']}"
                content = f"{content}\n### END GENERIC PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static'] and 'peid_signatures' in d['static']['pe']:
                count_signatures = 1
                content = f"{content}\n### START PEID SIGNATURES PARAGRAPH ###"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online the signature"
                content = f"{content}\nDESCRIPTION=PEID SIGNATURES are specific patterns or sequences of bytes within a file that indicate the presence of a particular packer or compiler"
                content = f"{content}\nHEADER="
                for signature in d['static']['pe']['peid_signatures']:
                    content = f"{content}\nROW=signature_{count_signatures};{signature}"
                    count_signatures = count_signatures + 1
                content = f"{content}\n### END PEID SIGNATURES PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static'] and 'pe_imports' in d['static']['pe']:
                content = f"{content}\n### START PE IMPORTS PARAGRAPH ###"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online if DLL/functions imported are used for malicious activities"
                content = f"{content}\nDESCRIPTION=PE IMPORTS refers to the process where a program (the executable file) uses functions or data defined in other program files (typically dynamic-link libraries, or DLLs)"
                content = f"{content}\nHEADER=imported dll name;imported function name;imported function address"
                for pe_import in d['static']['pe']['pe_imports']:
                    for import_f in pe_import['imports']:
                        content = f"{content}\nROW={pe_import['dll']};{import_f['name']};{import_f['address']}"
                content = f"{content}\n### END PE IMPORTS PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static'] and 'pe_exports' in d['static']['pe']:
                content = f"{content}\n### START PE EXPORTS PARAGRAPH ###"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online if functions exported are used for malicious activities"
                content = f"{content}\nDESCRIPTION=PE EXPORTS refers to a list of functions and variables that are made available for use by other programs"
                content = f"{content}\nHEADER=exported function name;exported function address"
                for pe_export in d['static']['pe']['pe_exports']:
                    content = f"{content}\nROW={pe_export['name']};{pe_export['address']}"
                content = f"{content}\n### END PE EXPORTS PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static'] and 'pe_sections' in d['static']['pe']:
                content = f"{content}\n### START PE SECTIONS PARAGRAPH ###"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online the structure of the sections, consider dangerous entropy greater or equal to 7 as value"
                content = f"{content}\nDESCRIPTION=PE SECTIONS are distinct blocks of memory that hold specific types of data, such as code, data, or resources"
                content = f"{content}\nHEADER=section name;section writeble or not;section address;section size;section data size;section entropy"
                for pe_section in d['static']['pe']['pe_sections']:
                    content = f"{content}\nROW={pe_section['name']};{pe_section['writeble']};{pe_section['virtual_address']};{pe_section['virtual_size']};{pe_section['size_of_data']};{pe_section['entropy']}"
                content = f"{content}\n### END PE SECTIONS PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static'] and 'pe_resources' in d['static']['pe']:
                content = f"{content}\n### START PE RESOURCES PARAGRAPH ###"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online if resources can be used for malicious scopes"
                content = f"{content}\nDESCRIPTION=PE RESOURCES are non-executable data such as images, icons, strings, dialog templates, and other data essential for the program's operation"
                content = f"{content}\nHEADER=resource name;resource offset;resource size;resource filetype"
                for pe_resource in d['static']['pe']['pe_resources']:
                    content = f"{content}\nROW={pe_resource['name']};{pe_resource['offset']};{pe_resource['size']};{pe_resource['filetype']}"
                content = f"{content}\n### END PE RESOURCES PARAGRAPH ###"

        return content

    def start(self):
        content = self._get_content_for_report()

        if content == "":
            self.ctx.log.warning("Failed to retrieve content for AI report")
            return {} 

        try:
            prompt_model = (
                "You are a cybersecurity specialist expert in malware analysis.\n"
                "You will receive in attachment a text formatted as following:\n"
                "- Text contains multiple paragraphs\n"
                "- Each paragraph begins with ### START XXXXXXXX PARAGRAPH ###\n"
                "- Each paragraph ends with ### END XXXXXXXX PARAGRAPH ###\n"
                "- Each paragraph contains a line starting with HOWTOUSE occurrence and aims to teach you which are the controls that I ask you to perform\n"
                "- Each paragraph contains a line starting with DESCRIPTION occurrence explaining the meaning of the paragraph\n"
                "- Each paragraph contains a line starting with HEADER occurrence. If it is blank, you has not consider the lines below as a CSV content. Otherwise, you has to consider the lines below a CSV content separated by ; where each value field will correspond to the respective field in HEADER line.\n"
                "- Each paragraph contains one or more line starting with ROW occurrence that represent the values to be analysed\n"
                "Perform the analysis as explained before adding the scope of the software analysed if you are able to retrieve its name from SHA512 hash. At the end of the analysis, please returns a report in output following next requirements:\n"
                "- output contains first italian version and after english one\n"
                "- versions has to be separated by ___|||___ characters\n"
                "- you have not to include the preamble where you summarize what I asked you to do, return only the analysis"
            )
            
            model = genai.GenerativeModel(self.gemini_api_model)
            response = model.generate_content(prompt_model + "\n\n" + content)
            return {
                "gemini_report": {
                    "it": response.text.split('___|||___')[0],
                    "en": response.text.split('___|||___')[1]
                }
            }
        except AIError as e:
            self.ctx.log.warning("Failed to retrieve AI report", error=e)
            return {}
