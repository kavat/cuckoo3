# Cuckoo 3 documentation

Cuckoo 3 is a Python 3 open source automated malware analysis system.

Initial born from [CERT-EE project](https://github.com/cert-ee/cuckoo3) and forked by me in order to improve new features and controls, this Sandbox aims to help people and companies to be reactive and ready against cyber threats.

## Generic control applied

### Static (both Linux and Windows)

Static controls are applied without run file and they are:
- File header
- String analysis
- [Anubi](https://github.com/kavat/anubi) with:
  - Hash analysis
  - Yara analysis 
- MISP intelligence (if enabled)
- Virustotal (if enabled)

### Dynamic (only Windows)

Dynamic controls and run are applied launching an internal vm that executes file in order to monitor its behaviour (network, file system writes/reads, registry usage, etc).

## Specific control for file types

File types below are supported:
- Windows PE files (static and dynamic analysis):
  - Sections
  - Signatures
  - Imports
  - Exports
- Linux Shared Objects (static analysis):
  - packer(file, unpack),
  - Sections(file),
  - Headers
  - Shared libraries
  - Dynamic symbols
  - Functions
  - Variable data
  - Anti-debug APIs
- Microsoft Office and PDF documents (static and dynamic analysis)  
- MSI/tar/7-zip files (static and dynamic analysis): all previous listed checks are applied
