#!/bin/bash
PATH_PYTHON3=$(find / -name "python3" 2>/dev/null | grep venv | xargs dirname)
su - cuckoo -c "${PATH_PYTHON3}/cuckoocleanup deleteid $1"
