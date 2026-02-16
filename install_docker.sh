#!/bin/bash

/opt/venv/bin/pip3 install -U wheel
/opt/venv/bin/pip3 install -U requests
/opt/venv/bin/pip3 install -U python_nmap
/opt/venv/bin/pip3 install -U mysql-connector-python
/opt/venv/bin/pip3 install -U pandas
/opt/venv/bin/pip3 install -U pdfquery
/opt/venv/bin/pip3 install -U netifaces
/opt/venv/bin/pip3 install -U pyelftools
/opt/venv/bin/pip3 install -U pyexecjs
/opt/venv/bin/pip3 install -U pyenchant
/opt/venv/bin/pip3 install -U google-generativeai
/opt/venv/bin/pip3 install -U google-genai
/opt/venv/bin/pip3 install -U pyexecjs
/opt/venv/bin/pip3 install -U pypandoc
# TMP solution until new versions of sflock etc are released to PyPI
/opt/venv/bin/pip3 install -U git+https://github.com/kavat/peepdf
/opt/venv/bin/pip3 install -U git+https://github.com/kavat/sflock
/opt/venv/bin/pip3 install -U git+https://github.com/kavat/roach
/opt/venv/bin/pip3 install -U git+https://github.com/kavat/httpreplay

declare -a pkglist=("./common" "./processing" "./machineries" "./web" "./node" "./core")

for pkg in ${pkglist[@]}
do
  if ! [[ -d "$pkg" ]]; then
    echo "Missing package: $pkg"
    exit 1
  fi

  /opt/venv/bin/pip3 install -e "$pkg"
  if [ $? -ne 0 ]; then
      echo "Install of $pkg failed"
      exit 1
  fi
done
