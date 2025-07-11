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
from ..static.strings_analysis import StringsDetonation

from pathlib import Path

SUSPICIOUS_STRINGS = [
  'powershell', 'cmd.exe', 'regsvr32', 'rundll32',
  'mshta', 'certutil', 'base64', 'wget', 'curl',
  'vbs', 'jscript', 'wscript', 'cscript', "wscript",
  "Invoke-", "DownloadString", "CreateObject", "WinExec", "ShellExecute",
  "net user", "net localgroup", "schtasks", "bypass", "obfuscate"
]
CHAR_BEFORE_AFTER = 20


class TarStaticAnalysisError(StaticAnalysisError):
  pass

class TarFile(Processor):

  _TYPE_HANDLER = {
    ("application/x-pie-executable", "application/x-sharedlib"): (ElfFile, "elf")
  }

  def strings_file_in_tar(self, target, file_path):
    return StringsDetonation(file_path)

  def anubi_file_in_tar(self, orig_filename, file_path):
    return anubi_analyze_single_file(file_path, orig_filename)

  def process_file_in_tar(self, target, file_path):

    data = {}
    subkey = None

    for media_type, handler_subkey in self._TYPE_HANDLER.items():

      if target["media_type"] not in media_type:
        continue

      handler, subkey = handler_subkey
      print(f"Gestisco {handler} e {subkey}")
      try:
        data = handler(file_path).to_dict()
      except StaticAnalysisError as e:
        self.ctx.log.warning(
          "Failed to run static analysis handler",
          handler=handler, error=e
        )
      except Exception as e:
        print(traceback.format_exc())
        err = "Unexpected error while running static analysis handler"
        self.ctx.log.exception(err, handler=handler, error=e)
        self.ctx.errtracker.add_error(f"{err}. Handler: {handler}. Error: {e}, Stacktrace: {traceback.format_exc()}")

      break

    if data:
      return {
        subkey:data
      }

    return {}

  def in_tar_file_details(self, filepath):
    print(f"filepath: {filepath}")
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

  def extract_tar_streams(self, tar_path):
    # Usa 7z per elencare i flussi nel file tar 
    return self.run_cmd(['tar', 'tvf', tar_path])

  def get_tar_content(self, tar_path, ritorno, extract, delete):
    if extract:
      tempdir = tempfile.mkdtemp()
      ritorno = {'origin': tempdir, 'filenames': []}
      self.run_cmd(['tar', 'zxvf', tar_path, "-C", tempdir])

      for root, dirs, files in os.walk(tempdir, topdown=True):
        new_dirs = []
        for d in dirs:
          full_path = Path(root) / d
          try:
            _ = list(os.scandir(full_path))  # Tenta accesso per verificare permessi
            new_dirs.append(d)
          except PermissionError:
            print(f"Permission denied: {full_path}")
          except FileNotFoundError:
            pass
        dirs[:] = new_dirs  # Modifica dirs in-place per evitare discesa

        for file in files:
          file_path = f"{Path(root) / file}"
          file_name = file_path.replace(f"{tempdir}/", "")
          details = self.in_tar_file_details(file_path)
          ritorno['filenames'].append({
            'name': file_name,
            'path': file_path,
            'details': details,
            'analysis': self.process_file_in_tar(details, file_path),
            'strings': self.strings_file_in_tar(details, file_path),
            'anubi': self.anubi_file_in_tar(file_name, file_path)
          })

    if delete:
      shutil.rmtree(tempdir, ignore_errors=True)
    return ritorno

  def parse_streams_listing(self):
    output, stderr = self.extract_tar_streams(self._filepath)
    lines = output.splitlines()
    suspicious = []
    for line in lines:
      for pattern in SUSPICIOUS_STRINGS:
        if pattern in line.lower():
          suspicious.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return suspicious or [{'info': 'No suspicious flow has been found'}]

  def search_suspicious_content(self, tar_path):
    # Estrai stringhe dal binario tar 
    output, stderr = self.run_cmd(['strings', tar_path])
    lines = output.splitlines()
    findings = []
    for line in lines:
      for pattern in SUSPICIOUS_STRINGS:
        if pattern in line.lower():
          findings.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return findings or [{'info': 'No suspicious string has been found'}]

  def __init__(self, filepath):
    self._filepath = filepath

  def to_dict(self):
    return {
      "content": self.get_tar_content(self._filepath, {}, True, True),
      "streams": self.parse_streams_listing(),
      "suspicious_strings": self.search_suspicious_content(self._filepath)
      #"certificate_chain": self.get_certificates_chain(),
    }
