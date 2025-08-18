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

CHAR_BEFORE_AFTER = 20


class MSIStaticAnalysisError(StaticAnalysisError):
  pass

class MSIFile(Processor):

  _TYPE_HANDLER = {
    ("application/x-dosexec"): (PEFile, "pe")
  }

  def strings_file_in_msi(self, target, file_path):
    return StringsDetonation(file_path, self.log_handler, self.errtracker_handler)

  def anubi_file_in_msi(self, orig_filename, file_path):
    return anubi_analyze_single_file(file_path, orig_filename)

  def process_file_in_msi(self, target, file_path):

    data = {}
    subkey = None

    for media_type, handler_subkey in self._TYPE_HANDLER.items():

      if target["media_type"] != media_type:
        continue

      handler, subkey = handler_subkey
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

  def in_msi_file_details(self, filepath):
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

  def extract_msi_streams(self, msi_path):
    # Usa 7z per elencare i flussi nel file MSI
    return self.run_cmd(['7z', 'l', msi_path])

  def get_msi_content(self, msi_path, ritorno, extract, delete):
    if extract:
      tempdir = tempfile.mkdtemp()
      ritorno = {'origin': tempdir, 'filenames': []}
      self.run_cmd(['7z', 'e', '-y', msi_path, f"-o{tempdir}"])
    for dirpath, dirnames, filenames in os.walk(tempdir):
      for dirname in dirnames:
        ritorno = self.get_msi_content("f{ritorno['origin']}/{dirname}", ritorno, False, False)
      for filename in filenames:
        file_path = f"{ritorno['origin']}/{filename}"
        file_name = file_path.replace(f"{ritorno['origin']}/", "")
        details = self.in_msi_file_details(file_path)
        ritorno['filenames'].append({
          'name': file_name, 
          'path': file_path, 
          'details': details, 
          'analysis': self.process_file_in_msi(details, file_path),
          'strings': self.strings_file_in_msi(details, file_path),
          'anubi': self.anubi_file_in_msi(file_name, file_path)
        })
    if delete:
      shutil.rmtree(tempdir, ignore_errors=True)
    return ritorno

  def parse_streams_listing(self):
    output, stderr = self.extract_msi_streams(self._filepath)
    lines = output.splitlines()
    suspicious = []
    for line in lines:
      for pattern in cfg("cuckoo.yaml", "suspicious_strings"):
        if pattern in line.lower():
          suspicious.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return suspicious or [{'info': 'No suspicious flow has been found'}]

  def search_suspicious_content(self, msi_path):
    # Estrai stringhe dal binario MSI
    output, stderr = self.run_cmd(['strings', msi_path])
    lines = output.splitlines()
    findings = []
    for line in lines:
      for pattern in cfg("cuckoo.yaml", "suspicious_strings"):
        if pattern in line.lower():
          findings.append({'sospetto': True, 'pattern': pattern, 'occurrences': self.prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)})
    return findings or [{'info': 'No suspicious string has been found'}]

  def extract_custom_actions_msiinfo(self, msi_path):
    try:
      output, stderr = self.run_cmd(['msiinfo', msi_path, 'export', 'CustomAction'])
      lines = output.splitlines()
      results = []
      for line in lines[1:]:  # salta intestazione
        if any(s in line.lower() for s in cfg("cuckoo.yaml", "suspicious_strings")):
          results.append({'stringa': line.strip(), 'sospetto': True})
      return results or [{'info': 'No suspicious CustomAction has been found'}]
    except Exception as e:
      err = "Unexpected error during msiinfo run"
      self,log_handler.exception(err, handler=handler, error=e)
      self.errtracker_handler.add_error(
        f"{err}. Handler: {handler}. Error: {e}"
      )
      return [{'error': f"{err}. Handler: {handler}. Error: {e}"}]

  def get_certificates_chain(self):
    output, err = self.run_cmd(['/bin/bash', '/opt/cuckoo3/scripts/get_certificate_chain.sh', self._filepath])
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_certificates_chain output: {output}")
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_certificates_chain err: {err}")
    lines = output.splitlines()
    return '<br>'.join(lines)

  def get_certificates_signatures(self):
    output, err = self.run_cmd(['/bin/bash', '/opt/cuckoo3/scripts/check_signature.sh', self._filepath])
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_certificates_signatures output: {output}")
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_certificates_signatures err: {err}")
    lines = output.splitlines()
    return '<br>'.join(lines)

  def get_msi_summary_information(self):
    output, err = self.run_cmd(['/bin/bash', '/opt/cuckoo3/scripts/get_msi_information.sh', self._filepath])
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_msi_summary_information output: {output}")
    self.log_handler.info(f"[MSI analysis] [{self._filepath}] get_msi_summary_information err: {err}")
    lines = output.splitlines()
    return '<br>'.join(lines)

  def __init__(self, filepath, log_handler, errtracker_handler):
    self._filepath = filepath
    self.log_handler = log_handler
    self.errtracker_handler = errtracker_handler

  def to_dict(self):
    return {
      "content": self.get_msi_content(self._filepath, {}, True, True),
      "streams": self.parse_streams_listing(),
      #"suspicious_strings": self.search_suspicious_content(self._filepath),
      "custom_actions": self.extract_custom_actions_msiinfo(self._filepath),
      "certificates": self.get_certificates_signatures(),
      #"certificate_chain": self.get_certificates_chain(),
      "summary_information": self.get_msi_summary_information()
    }
