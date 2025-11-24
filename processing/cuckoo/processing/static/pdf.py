# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

import logging
import re
import zlib
import pandas as pd
import pdfquery

from cuckoo.common.log import set_logger_level
from ..errors import StaticAnalysisError

class PDFStaticAnalysisError(StaticAnalysisError):
    pass

class PDFFile:

    def __init__(self, filepath, log_handler, errtracker_handler):
        self._filepath = filepath
        self.log_handler = log_handler
        self.errtracker_handler = errtracker_handler

    def uncompress_flatdecode(self):
        ritorno = ""
        pdf = open(self._filepath, "rb").read()
        #stream = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)
        stream = re.compile(rb'(?<=FlateDecode).*?stream\s*(.*?)\s*endstream', re.S)

        for s in stream.findall(pdf):
            s = s.strip(b'\r\n')
            try:
                ritorno = "{}{}\n".format(ritorno, zlib.decompress(s).decode())
            except:
                pass

        return ritorno

    def general_content(self):
        pdf_xml_path = '/tmp/appoggio.xml'
        pdf = pdfquery.PDFQuery(self._filepath)
        pdf.load()

        #convert the pdf to XML
        pdf.tree.write(pdf_xml_path, pretty_print = True)
        pdf_xml = open(pdf_xml_path)
        return pdf_xml.readlines()

    def to_dict(self):

        general_content = self.general_content()
        decoded_content = self.uncompress_flatdecode()

        return {
            "pdf_general_content": general_content,
            "pdf_decoded_content": decoded_content
        }
