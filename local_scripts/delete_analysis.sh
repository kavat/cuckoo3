#!/bin/bash
PATH_PYTHON3=$(find / -name "python3" | grep venv | xargs dirname)
su - cuckoo -c "${PATH_PYTHON3}/cuckoocleanup deleteid $1"
