#DetermineTarget
import subprocess
import re
import sys
import json
import tempfile
import shutil
import os
import traceback

from ..errors import StaticAnalysisError
from cuckoo.common.storage import File

from ..abtracts import Processor
from ..static.pe import PEFile
from ..static.strings_analysis import StringsDetonation
from ..static.office import OfficeDocument
from ..static.pdf import PDFFile
from ..static.elf import ElfFile

from cuckoo.common.external_interactions import anubi_analyze_single_file
from cuckoo.common.config import cfg

from pathlib import Path

CHAR_BEFORE_AFTER = 20


class SevenZipFile(Processor):

  _TYPE_HANDLER = {
    ("application/x-pie-executable", "application/x-sharedlib"): (ElfFile, "elf"),
    ("application/x-dosexec"): (PEFile, "pe")
  }

  def strings_file_in_SevenZip(self, target, file_path):
    return StringsDetonation(file_path, self.log_handler, self.errtracker_handler)

  def anubi_file_in_SevenZip(self, orig_filename, file_path):
    return anubi_analyze_single_file(file_path, orig_filename)

  def process_file_in_SevenZip(self, target, file_path):

    data = {}
    subkey = None

    for media_type, handler_subkey in self._TYPE_HANDLER.items():

      if target["media_type"] not in media_type:
        continue

      handler, subkey = handler_subkey
      self.log_handler.info(f"[SevenZip analysis] [{file_path}] handling {handler} for {subkey}")
      try:
        data = handler(file_path, self.log_handler, self.errtracker_handler).to_dict()
      except StaticAnalysisError as e:
        self.log_handler.warning(
          "Failed to run static analysis handler",
          handler=handler, error=e
        )
      except Exception as e:
        err = "Unexpected error while running static analysis handler"
        self.log_handler.exception(err, handler=handler, error=e)
        self.errtracker_handler.add_error(f"{err}. Handler: {handler}. Error: {e}, Stacktrace: {traceback.format_exc()}")

      break

    if data:
      return {
        subkey:data
      }

    return {}

  def in_SevenZip_file_details(self, filepath):
    self.log_handler.info(f"[SevenZip analysis] [{filepath}] recovering file metadata")
    file_helper = File(filepath)
    return file_helper.to_dict()

  def prendi_tutti_contesti(self, testo, sottostringa, n):
    risultati = []
    start = 0
    while True:
      idx = testo.find(sottostringa, start)
      if idx == -1:
        break
      inizio = max(0, idx - n)
      fine = min(len(testo), idx + len(sottostringa) + n)
      risultati.append(testo[inizio:fine])
      start = idx + 1 # continua a cercare dopo l'occorrenza trovata
    return risultati

  def run_cmd(self, cmd_list):
    result = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode(errors='ignore'), result.stderr.decode(errors='ignore')

  def extract_SevenZip_streams(self, SevenZip_path):
    # Usa 7z per elencare i flussi nel file SevenZip
    return self.run_cmd(['7z', 'l', SevenZip_path])

  def get_SevenZip_content(self, SevenZip_path, ritorno, extract, delete):
    if extract:
      tempdir = tempfile.mkdtemp()
      ritorno = {'origin': tempdir, 'filenames': []}

      self.run_cmd(['7z', 'x', SevenZip_path, f"-o{tempdir}"])

      for root, dirs, files in os.walk(tempdir, topdown=True):
        new_dirs = []
        for d in dirs:
          full_path = Path(root) / d
          try:
            _ = list(os.scandir(full_path))  # Tenta accesso per verificare permessi
            new_dirs.append(d)
          except PermissionError:
            pass
            #print(f"Permission denied: {full_path}")
          except FileNotFoundError:
            pass
        dirs[:] = new_dirs  # Modifica dirs in-place per evitare discesa

        for file in files:
          file_path = f"{Path(root) / file}"
          file_name = file_path.replace(f"{tempdir}/", "")
          details = self.in_SevenZip_file_details(file_path)
          if os.path.islink(file_path):
            self.log_handler.info(f"[SevenZip analysis] skipped {file_path} because link")
          else:
            ritorno['filenames'].append({
              'name': file_name,
              'path': file_path,
              'details': details,
              'analysis': self.process_file_in_SevenZip(details, file_path),
              'strings': self.strings_file_in_SevenZip(details, file_path),
              'anubi': self.anubi_file_in_SevenZip(file_name, file_path)
            })

    if delete:
      shutil.rmtree(tempdir, ignore_errors=True)
    return ritorno

  def parse_streams_listing(self):
    output, stderr = self.extract_SevenZip_streams(self._filepath)
    lines = output.splitlines()
    suspicious = []
    for line in lines:
      for pattern in cfg("cuckoo.yaml", "suspicious_strings"):
        if pattern in line.lower():
          suspicious.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return suspicious or [{'info': 'No suspicious flow has been found'}]

  def search_suspicious_content(self, SevenZip_path):
    # Estrai stringhe dal binario SevenZip
    output, stderr = self.run_cmd(['strings', SevenZip_path])
    lines = output.splitlines()
    findings = []
    for line in lines:
      for pattern in cfg("cuckoo.yaml", "suspicious_strings"):
        if pattern in line.lower():
          findings.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return findings or [{'info': 'No suspicious string has been found'}]

  def __init__(self, filepath, log_handler, errtracker_handler):
    self._filepath = filepath
    self.log_handler = log_handler
    self.errtracker_handler = errtracker_handler

  def to_dict(self):

    return {
      "content": self.get_SevenZip_content(self._filepath, {}, True, True),
      "streams": self.parse_streams_listing(),
      "suspicious_strings": self.search_suspicious_content(self._filepath)
      #"certificate_chain": self.get_certificates_chain(),
    }
