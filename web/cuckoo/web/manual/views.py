from urllib.parse import urlparse

from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.http import (
    HttpResponseBadRequest, HttpResponseServerError, HttpResponseNotAllowed,
    HttpResponseNotFound
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


class Manual(View):

    def get(self, request):
        return render(request, template_name="manual/index.html.jinja2")


