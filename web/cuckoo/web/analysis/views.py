# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

from django.http import HttpResponseServerError, HttpResponseNotFound
from django.shortcuts import render

from cuckoo.common.analyses import States
from cuckoo.common.storage import TaskPaths
from cuckoo.common.result import (
    retriever, Results, ResultDoesNotExistError, InvalidResultDataError
)
from ipaddress import ip_network, ip_address
from ipware import get_client_ip
from cuckoo.common.config import cfg

import json
import pypandoc


def index(request, analysis_id):
    skip_post = False
    try:
        result = retriever.get_analysis(
            analysis_id, include=[Results.ANALYSIS, Results.TASK, Results.PRE, Results.POST]
        )
        analysis = result.analysis
        with open(TaskPaths.report(f"{analysis_id}_1")) as f:
            task_report = json.load(f)
    except FileNotFoundError:
        skip_post = True
    except ResultDoesNotExistError:
        return HttpResponseNotFound()
    except InvalidResultDataError as e:
        return HttpResponseServerError(str(e))

    if analysis.state == States.FATAL_ERROR:
        return render(
            request, template_name="analysis/error.html.jinja2",
            context={
                "analysis": analysis.to_dict(),
                "analysis_id": analysis_id
            }
        )

    try:
        pre = result.pre
        #post = task_report
    except ResultDoesNotExistError:
        return HttpResponseNotFound()
    except InvalidResultDataError as e:
        return HttpResponseServerError(str(e))

    if skip_post != True:
        try:
            post = task_report
        except ResultDoesNotExistError:
            return HttpResponseNotFound()
        except InvalidResultDataError as e:
            return HttpResponseServerError(str(e))
    else:
        post = {}

    allowed_subnets = cfg(
        "web.yaml", "web", "downloads", "allowed_subnets", subpkg="web"
    )
    isAllowed = False
    if allowed_subnets:
        ip, isPrivate = get_client_ip(request, request_header_order=['X-Real-IP'])
        if ip:
            for network in allowed_subnets.split(","):
                network = ip_network(network)
                if ip_address(ip) in network:
                    isAllowed = True

    pre_postanalysis = pre.to_dict()
    if 'static' in pre_postanalysis and 'elf' in pre_postanalysis['static'] and 'elf_analysis' in pre_postanalysis['static']['elf']:
      for tag in ['sections','program_header']:
        for k,v in enumerate(pre_postanalysis['static']['elf']['elf_analysis'][tag]):
          suspected = 'X' in v['Flags'] and 'W' in v['Flags']
          pre_postanalysis['static']['elf']['elf_analysis'][tag][k]['Suspected'] = str(suspected)
      for tag in ['dynamic_symbols','functions']:
        for k,v in enumerate(pre_postanalysis['static']['elf']['elf_analysis'][tag]):
          func_name = ""
          if 'Name' in v and tag == 'dynamic_symbols':
            func_name = v['Name']
          if 'Function' in v and tag == 'functions':
            func_name = v['Function']
          suspected = func_name.split('@')[0] in cfg("cuckoo.yaml", "suspicious_functions")
          pre_postanalysis['static']['elf']['elf_analysis'][tag][k]['Suspected'] = str(suspected)

    if skip_post != True and 'ai' in post and 'gemini_report' in post['ai']:
      gemini_report_it = pypandoc.convert_text(post['ai']['gemini_report']['it'], 'html', format='md').replace(" * ","<br>")
      gemini_report_en = pypandoc.convert_text(post['ai']['gemini_report']['en'], 'html', format='md').replace(" * ","<br>")
      post['ai']['gemini_report']['it'] = gemini_report_it
      post['ai']['gemini_report']['en'] = gemini_report_en

    return render(
      request, template_name="analysis/index.html.jinja2",
      context={
        "analysis": analysis.to_dict(),
        "pre": pre_postanalysis,
        "post": post,
        "analysis_id": analysis_id,
        "filedownload_allowed": isAllowed
      }
    )


def static(request, analysis_id):
    try:
        result = retriever.get_analysis(
            analysis_id, include=[Results.ANALYSIS, Results.PRE]
        )
        analysis = result.analysis
        pre = result.pre
    except ResultDoesNotExistError:
        return HttpResponseNotFound()
    except InvalidResultDataError as e:
        return HttpResponseServerError(str(e))

    return render(
        request, template_name="analysis/static.html.jinja2",
        context={
            "analysis": analysis.to_dict(),
            "pre": pre.to_dict(),
            "analysis_id": analysis_id
        }
    )
