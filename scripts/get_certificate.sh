#!/bin/bash
FILE="$1"
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "▒ File not found in argument"
  exit 1
fi
TMPDIR=/tmp/$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
SIGNATURE="$TMPDIR/signature.der"
CERT_PEM="$TMPDIR/cert.pem"
SPLITTED_CERT_PEM="$TMPDIR/individual-"
mkdir "$TMPDIR"
#echo "▒ Signature recovery..."
osslsigncode extract-signature -in "$FILE" -out "$SIGNATURE" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
  /opt/cuckoo3/venv/bin/python3 /opt/cuckoo3/scripts/export_certificates.py "$FILE" "$SIGNATURE"
  if [[ $? -ne 0 ]]; then
    echo "▒ No signature found"
    rm -rf "$TMPDIR"
    exit 1
  fi
fi
#echo "▒ Certificate conversion..."
openssl pkcs7 -in "$SIGNATURE" -inform DER -print_certs -out "$CERT_PEM" 2>/dev/null
if [[ $? -ne 0 ]]; then
  /opt/cuckoo3/venv/bin/python3 /opt/cuckoo3/scripts/export_certificates.py "$FILE" "$SIGNATURE"
  if [[ $? -ne 0 ]]; then
    echo "▒ Certificate conversion failed"
    rm -rf "$TMPDIR"
    exit 1
  else
    openssl pkcs7 -in "$SIGNATURE" -inform DER -print_certs -out "$CERT_PEM" 2>/dev/null
  fi
fi
csplit -z -f "$SPLITTED_CERT_PEM" "$CERT_PEM" '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1
for individual in $(ls "$SPLITTED_CERT_PEM"*); do
  check=$(grep 'BEGIN CERTIFICATE' $individual)
  if [ "${check}" != "" ]; then
    cat $individual | grep -v "^\(subject\|issuer\)" | grep "[a-zA-Z]" > ${individual}_parsed
    mv ${individual}_parsed ${individual}
  else
    rm ${individual}
  fi
done
for individual in $(ls "$SPLITTED_CERT_PEM"*); do
  openssl x509 -in "$individual" -noout -subject -issuer -sha1 -fingerprint -dates 2>&1
  echo ""
done
rm -rf "$TMPDIR"
