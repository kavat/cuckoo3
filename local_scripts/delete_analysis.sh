#!/bin/bash
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoocleanup deleteid $1"
