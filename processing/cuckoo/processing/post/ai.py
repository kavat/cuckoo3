# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

import json
import google.generativeai as genai

from cuckoo.common.config import cfg
from cuckoo.common.storage import AnalysisPaths

from ..abtracts import Processor
from ..errors import DisablePluginError

import os
import re
import sys
from typing import Dict, Tuple, List

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

VALID_EXTS = {".yar", ".yara"}

def list_yara_files(directory: str) -> List[str]:
    files = []
    for entry in os.listdir(directory):
        p = os.path.join(directory, entry)
        if os.path.isfile(p) and os.path.splitext(entry)[1].lower() in VALID_EXTS:
            files.append(p)
    return sorted(files)

def extract_rules_from_text(text: str) -> Dict[str, str]:
    """
    Estrae tutte le regole dal testo (nome -> testo intero della regola, includendo 'rule ... { ... }').
    Usa ricerca della parola 'rule' e conteggio parentesi graffe per catturare blocchi nidificati.
    """
    rules = {}
    # trova le occorrenze di 'rule <name>'
    for m in re.finditer(r'\brule\s+([A-Za-z0-9_]+)\b', text, flags=re.IGNORECASE):
        name = m.group(1)
        # trova la prima '{' dopo la match
        start_idx = m.end()
        brace_pos = text.find('{', start_idx)
        if brace_pos == -1:
            continue
        idx = brace_pos
        depth = 0
        end_idx = None
        # scorri avanti per bilanciare le graffe
        while idx < len(text):
            ch = text[idx]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_idx = idx
                    break
            idx += 1
        if end_idx:
            rule_text = text[m.start(): end_idx+1]
            # Se il nome è già presente, aggiungiamo un suffisso numerico per evitare perdita
            if name in rules:
                # crea nome con suffisso
                i = 1
                new_name = f"{name}__dup{i}"
                while new_name in rules:
                    i += 1
                    new_name = f"{name}__dup{i}"
                rules[new_name] = rule_text
            else:
                rules[name] = rule_text
    return rules

class YaraRuleStore:
    def __init__(self, directory: str):
        self.directory = directory
        self.files = list_yara_files(directory)
        self.rules_map: Dict[str, Tuple[str, str]] = {}
        # rules_map[name] = (file_path, rule_text)
        self.compiled_rules = None
        self._load()

    def _load(self):
        # leggi file e estrai regole
        per_file_rules = {}  # file -> dict(name->text)
        for f in self.files:
            try:
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    txt = fh.read()
                extracted = extract_rules_from_text(txt)
                per_file_rules[f] = extracted
                for name, text in extracted.items():
                    self.rules_map[name] = (f, text)
            except Exception as e:
                print(f"[!] Errore leggendo {f}: {e}", file=sys.stderr)

        # prova a compilare tutte le regole (opzionale ma utile per validazione)
        if YARA_AVAILABLE and per_file_rules:
            # prepare file mapping per yara.compile: namespace->path
            file_mapping = {}
            for idx, f in enumerate(self.files):
                ns = f"ns{idx}"
                file_mapping[ns] = f
            try:
                # nota: yara.compile con filepaths mappa namespace->file
                self.compiled_rules = yara.compile(filepaths=file_mapping)
            except yara.SyntaxError as e:
                print(f"[!] Errore di sintassi durante la compilazione delle regole YARA: {e}", file=sys.stderr)
                # non interrompere: le regole testate manualmente rimangono nella mappa
            except Exception as e:
                print(f"[!] Errore inatteso compilando le regole: {e}", file=sys.stderr)
        elif not YARA_AVAILABLE:
            print("[i] Modulo yara-python non installato: salto compilazione (solo estrazione testo).", file=sys.stderr)

    def get_rule_body(self, rule_name: str) -> str:
        """
        Ritorna il testo della regola (intero blocco 'rule ... { ... }') per rule_name.
        Lancia KeyError se la regola non viene trovata.
        """
        if rule_name in self.rules_map:
            _, text = self.rules_map[rule_name]
            return text
        # tentativo di case-insensitive match
        lower = {k.lower(): k for k in self.rules_map.keys()}
        if rule_name.lower() in lower:
            real = lower[rule_name.lower()]
            _, text = self.rules_map[real]
            return text
        raise KeyError(f"Regola '{rule_name}' non trovata fra le regole caricate.")

    def list_rules(self) -> List[str]:
        return sorted(self.rules_map.keys())

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

    def _get_content_for_report_yara(self, yara_rules_path):

        content = ""

        with open(AnalysisPaths._path(self.ctx.analysis.id, "pre.json")) as f:
            d = json.load(f)

            if 'anubi' in d:

                store = YaraRuleStore(yara_rules_path)

                if d['anubi']['yara_scan']:

                    first = 0

                    for rule in d['anubi']['yara_scan']:
                        try:
                            body = store.get_rule_body(rule['rule'])
                            if first == 0:
                                first = 1
                                content = f"{d['target']['filename']}###{d['target']['sha512']}\n"
                            content = f"{content}--- RULE BODY START ---\n{body}\n--- RULE BODY END ---"
                        except KeyError as e:
                            self.ctx.log.warning(f"Error on _get_content_for_report_yara for rule {rule['rule']}:", error=e)

        return content


    def _get_content_for_report_general(self):

        content = ""

        with open(AnalysisPaths._path(self.ctx.analysis.id, "pre.json")) as f:
            d = json.load(f)

            if 'static' in d and 'elf' in d['static'] and 'elf_analysis' in d['static']['elf']:

                content = f"{content}\n### START ELF GENERIC PARAGRAPH ###"
                content = f"{content}\nDESCRIPTION=Initial paragraph used to identify operative system used and SHA512 hash of file"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online SHA512 hash"
                content = f"{content}\nHEADER=OS platform;SHA512 file hash"
                content = f"{content}\nROW=linux;{d['target']['sha512']}"
                content = f"{content}\n### END ELF GENERIC PARAGRAPH ###"

                if 'program_header' in d['static']['elf']['elf_analysis']:
                    content = f"{content}\n### START ELF PROGRAM HEADERS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=An executable or shared object file's program header table is an array of structures, each describing a segment or other information the system needs to prepare the program for execution"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online if headers identified can be used for malicious activities"
                    content = f"{content}\nHEADER=header type;header offset;header virtual address;header physical address;header size; header flags"
                    for header in d['static']['elf']['elf_analysis']['program_header']:
                        content = f"{content}\nROW={header['Type']};{header['Offset']};{header['Virtual Address']};{header['Physical Address']};{header['File Size']};{header['Flags']}"
                    content = f"{content}\n### END ELF HEADERS PARAGRAPH ###"

                if 'shared_libraries' in d['static']['elf']['elf_analysis']:
                    content = f"{content}\n### START ELF SHARED LIBRARIES PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=Shared libraries are libraries that are loaded by programs when they start"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online if shared library imported can be used for malicious activities"
                    content = f"{content}\nHEADER="
                    for shared_library in d['static']['elf']['elf_analysis']['shared_libraries']:
                        content = f"{content}\nROW={shared_library}"
                    content = f"{content}\n### END ELF SHARED LIBRARIES PARAGRAPH ###" 

                if 'sections' in d['static']['elf']['elf_analysis']:
                    content = f"{content}\n### START ELF SECTIONS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=ELF SECTIONS are distinct blocks of memory that hold specific types of data, such as code, data, or resources"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online the structure of the sections"
                    content = f"{content}\nHEADER=section name;section flags;section address;section size;section entropy"
                    for elf_section in d['static']['elf']['elf_analysis']['sections']:
                        content = f"{content}\nROW={elf_section['Name']};{elf_section['Flags']};{elf_section['Address']};{elf_section['Size']};{elf_section['Entropy']}"
                    content = f"{content}\n### END ELF SECTIONS PARAGRAPH ###"                

                if 'dynamic_symbols' in d['static']['elf']['elf_analysis']:
                    content = f"{content}\n### START ELF DYNAMIC SYMBOLS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=ELF files contain various components like machine instructions, symbols, and data, organized in a way that both the operating system and runtime linker can interpret"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check if symbols can be used for malicious scope"
                    content = f"{content}\nHEADER=symbol name;symbol binding"
                    for elf_symbol in d['static']['elf']['elf_analysis']['dynamic_symbols']: 
                        if 'Name' in elf_symbol:
                            content = f"{content}\nROW={elf_symbol['Name']};{elf_symbol['Symbol Binding']}"
                    content = f"{content}\n### END ELF DYNAMIC SYMBOLS PARAGRAPH ###"

                if 'functions' in d['static']['elf']['elf_analysis']:
                    content = f"{content}\n### START ELF FUNCTIONS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=Symbols are a symbolic reference to some type of data or code such as a global variable or function"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check if functions can be used for malicious scope"
                    content = f"{content}\nHEADER=function name;function offset"
                    for elf_function in d['static']['elf']['elf_analysis']['functions']:
                        content = f"{content}\nROW={elf_function['Function']};{elf_function['Offset Value']}"
                    content = f"{content}\n### END ELF FUNCTIONS PARAGRAPH ###"

            if 'static' in d and 'pe' in d['static']:

                content = f"{content}\n### START GENERIC PARAGRAPH ###"
                content = f"{content}\nDESCRIPTION=Initial paragraph used to identify operative system used and SHA512 hash of file"
                content = f"{content}\nHOWTOUSE=Use this paragraph to check online SHA512 hash"
                content = f"{content}\nHEADER=OS platform;SHA512 file hash"
                content = f"{content}\nROW=windows;{d['target']['sha512']}"
                content = f"{content}\n### END GENERIC PARAGRAPH ###"

                if 'peid_signatures' in d['static']['pe']:
                    content = f"{content}\n### START PEID SIGNATURES PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=PEID SIGNATURES are specific patterns or sequences of bytes within a file that indicate the presence of a particular packer or compiler"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online the signature"
                    content = f"{content}\nHEADER="
                    for signature in d['static']['pe']['peid_signatures']:
                        content = f"{content}\nROW={signature}"
                    content = f"{content}\n### END PEID SIGNATURES PARAGRAPH ###"

                if 'pe_imports' in d['static']['pe']:
                    content = f"{content}\n### START PE IMPORTS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=PE IMPORTS refers to the process where a program (the executable file) uses functions or data defined in other program files (typically dynamic-link libraries, or DLLs)"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online if DLL/functions imported are used for malicious activities"
                    content = f"{content}\nHEADER=imported dll name;imported function name;imported function address"
                    for pe_import in d['static']['pe']['pe_imports']:
                        for import_f in pe_import['imports']:
                            content = f"{content}\nROW={pe_import['dll']};{import_f['name']};{import_f['address']}"
                    content = f"{content}\n### END PE IMPORTS PARAGRAPH ###"

                if 'pe_exports' in d['static']['pe']:
                    content = f"{content}\n### START PE EXPORTS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=PE EXPORTS refers to a list of functions and variables that are made available for use by other programs"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online if functions exported are used for malicious activities"
                    content = f"{content}\nHEADER=exported function name;exported function address"
                    for pe_export in d['static']['pe']['pe_exports']:
                        content = f"{content}\nROW={pe_export['name']};{pe_export['address']}"
                    content = f"{content}\n### END PE EXPORTS PARAGRAPH ###"

                if 'pe_sections' in d['static']['pe']:
                    content = f"{content}\n### START PE SECTIONS PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=PE SECTIONS are distinct blocks of memory that hold specific types of data, such as code, data, or resources"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online the structure of the sections, consider dangerous entropy greater or equal to 7 as value"
                    content = f"{content}\nHEADER=section name;section writeble or not;section address;section size;section data size;section entropy"
                    for pe_section in d['static']['pe']['pe_sections']:
                        content = f"{content}\nROW={pe_section['name']};{pe_section['writeble']};{pe_section['virtual_address']};{pe_section['virtual_size']};{pe_section['size_of_data']};{pe_section['entropy']}"
                    content = f"{content}\n### END PE SECTIONS PARAGRAPH ###"

                if 'pe_resources' in d['static']['pe']:
                    content = f"{content}\n### START PE RESOURCES PARAGRAPH ###"
                    content = f"{content}\nDESCRIPTION=PE RESOURCES are non-executable data such as images, icons, strings, dialog templates, and other data essential for the program's operation"
                    content = f"{content}\nHOWTOUSE=Use this paragraph to check online if resources can be used for malicious scopes"
                    content = f"{content}\nHEADER=resource name;resource offset;resource size;resource filetype"
                    for pe_resource in d['static']['pe']['pe_resources']:
                        content = f"{content}\nROW={pe_resource['name']};{pe_resource['offset']};{pe_resource['size']};{pe_resource['filetype']}"
                    content = f"{content}\n### END PE RESOURCES PARAGRAPH ###"

        return content

    def start(self):
        content = self._get_content_for_report_general()

        if content == "":
            self.ctx.log.warning("Failed to retrieve content for AI report general")
        else:
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
                    "Perform the analysis as explained before adding the scope of the software analysed if you are able to retrieve its name from SHA512 hash, ensure avoiding false positives performing more controls and checks. At the end of the analysis, please returns a report in output following next requirements:\n"
                    "- output contains first italian version and after english one\n"
                    "- versions has to be separated by ___|||___ characters\n"
                    "- you have not to include the preamble where you summarize what I asked you to do, return only the analysis"
                )
              
                model = genai.GenerativeModel(self.gemini_api_model)
                response = model.generate_content(prompt_model + "\n\n" + content)

                print_response = 0
                it_version = "Non disponibile"
                en_version = "Not available"

                try:
                    it_version = response.text.split('___|||___')[0]
                except Exception as e1:
                    self.ctx.log.warning("Error during AI general response split italian version:", error=e1)
                    print_response = 1
                try:
                    en_version = response.text.split('___|||___')[1]
                except Exception as e2:
                    self.ctx.log.warning("Error during AI general response split english version:", error=e2)
                    print_response = 1

                if print_response == 1:
                    self.ctx.log.warning("Response from Gemini AI general: {}".format(response.text))

            except AIError as e:
                self.ctx.log.warning("Failed to retrieve AI report general", error=e)

            except Exception as e_gen:
                self.ctx.log.warning("Failed to retrieve AI report general, generic exception", error=e_gen)

        content = self._get_content_for_report_yara("/opt/anubi/conf/anubi-signatures/yara/")

        if content == "":
            self.ctx.log.warning("Failed to retrieve content for AI report yara")
        else:

            try:
                prompt_model = (
                    "You are a cybersecurity specialist expert in malware analysis.\n"
                    "You will receive in attachment a text formatted as following:\n"
                    "- Text contains multiple yara rules triggered as paragraph\n"
                    "- First line contains software name and its sha256 hash separated by three #\n"
                    "- Every other paragraph begins with ### RULE BODY START ###\n"
                    "- Every other paragraph ends with ### RULE BODY END ###\n"
                    "- Every other paragraph contains between delimitators lines explained above the body of the rule\n"
                    "Ensure avoiding false positives performing more controls and checks. At the end of the analysis, please returns a report in output following next requirements:\n"
                    "- output contains first italian version and after english one\n"
                    "- versions has to be separated by ___|||___ characters\n"
                    "- summarize in a table with the focal points\n"
                    "- you have not to include the preamble where you summarize what I asked you to do, return only the analysis"
                )

                model = genai.GenerativeModel(self.gemini_api_model)
                response = model.generate_content(prompt_model + "\n\n" + content)

                print_response = 0
                it_y_version = "Non disponibile"
                en_y_version = "Not available"

                try:
                    it_y_version = response.text.split('___|||___')[0]
                except Exception as e1:
                    self.ctx.log.warning("Error during AI yara response split italian version:", error=e1)
                    print_response = 1
                try:
                    en_y_version = response.text.split('___|||___')[1]
                except Exception as e2:
                    self.ctx.log.warning("Error during AI yara response split english version:", error=e2)
                    print_response = 1

                if print_response == 1:
                    self.ctx.log.warning("Response from Gemini AI yara: {}".format(response.text))

            except AIError as e:
                self.ctx.log.warning("Failed to retrieve AI report yara", error=e)

            except Exception as e_gen:
                self.ctx.log.warning("Failed to retrieve AI report yara, generic exception", error=e_gen)

        return {
            "gemini_report": {
                "it": it_version,
                "en": en_version,
                "it_y": it_y_version,
                "en_y": en_y_version
            }
        }
