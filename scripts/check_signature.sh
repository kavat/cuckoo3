#!/bin/bash
FILE="$1"
PATH_PYTHON3=$(find / -name "python3" | grep venv | xargs dirname)
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "ż File not found in argument"
  exit 1
fi
TMPDIR=/tmp/$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
SIGNATURE="$TMPDIR/signature.der"
CERT_PEM="$TMPDIR/cert.pem"
ORDERED_CERT_PEM="$TMPDIR/ordered_cert.pem"
SPLITTED_CERT_PEM="$TMPDIR/individual-"

mkdir "$TMPDIR"

#echo "Signature recovery..."
osslsigncode extract-signature -in "$FILE" -out "$SIGNATURE" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
  $PATH_PYTHON3/python3 /opt/cuckoo3/scripts/export_certificates.py "$FILE" "$SIGNATURE"
  if [[ $? -ne 0 ]]; then
    echo "No signature found"
    rm -rf "$TMPDIR"
    exit 1
  fi
fi

#echo "Certificate conversion..."
openssl pkcs7 -in "$SIGNATURE" -inform DER -print_certs -out "$CERT_PEM" 2>/dev/null
if [[ $? -ne 0 ]]; then
  $PATH_PYTHON3/python3 /opt/cuckoo3/scripts/export_certificates.py "$FILE" "$SIGNATURE"
  if [[ $? -ne 0 ]]; then
    echo "Certificate conversion failed"
    rm -rf "$TMPDIR"
    exit 1
  else
    openssl pkcs7 -in "$SIGNATURE" -inform DER -print_certs -out "$CERT_PEM" 2>/dev/null
  fi
fi

#echo ""
#echo "Certificate data:"
#openssl x509 -in "$CERT_PEM" -noout -subject -issuer -sha1 -fingerprint -dates 2>&1
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

#echo "Certificate trust chain verification:"
openssl verify -verbose -no_check_time -CAfile /etc/ssl/certs/ca-certificates.crt "$CERT_PEM" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
  $PATH_PYTHON3/python3 /opt/cuckoo3/scripts/invert_chain_order.py "$CERT_PEM" "$ORDERED_CERT_PEM"
  if [[ $? -eq 0 ]]; then
    openssl verify -verbose -no_check_time -CAfile /etc/ssl/certs/ca-certificates.crt "$ORDERED_CERT_PEM" > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echo "Untrusted"
      echo ""
      echo "Certificate content"
      cat "$CERT_PEM"
    else
      echo "Trusted"
    fi
  else
    echo "Untrusted"
    echo ""
    echo "Certificate content"
    cat "$CERT_PEM"
  fi
else
  echo "Trusted"
fi
rm -rf "$TMPDIR"
