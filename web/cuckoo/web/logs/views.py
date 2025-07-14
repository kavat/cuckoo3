import os

from urllib.parse import urlparse

from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.http import (
    HttpResponseBadRequest, HttpResponseServerError, HttpResponseNotAllowed,
    HttpResponseNotFound, HttpResponse
)
from django.shortcuts import render, redirect
from django.views import View
import re

from cuckoo.common import submit, analyses
from cuckoo.common.config import cfg
from cuckoo.common.result import (
    retriever, Results, ResultDoesNotExistError, InvalidResultDataError
)
from cuckoo.common.storage import AnalysisPaths
from cuckoo.common.vmcloak_vm import GetLiveVM

class Logs(View):

    def get(self, request):
        return render(request, template_name="logs/index.html.jinja2")

class LogsData(View):

    def get(self, request):
        file_log = '/home/cuckoo/.cuckoocwd/log/cuckoo.log'
        if os.path.isfile(file_log):
            with open(file_log) as f:
                return HttpResponse(f.read())
        else:
            return HttpResponse(f"{file_log} not found")
