import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Carica i certificati PEM estratti
with open(sys.argv[1], "rb") as f:
  pem_data = f.read()

# Parse dei certificati
certs = []
for cert_pem in pem_data.split(b"-----END CERTIFICATE-----"):
  cert_pem = cert_pem.strip()
  if cert_pem:
    cert_pem += b"\n-----END CERTIFICATE-----\n"
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    certs.append((cert, cert_pem))

# Mappa per trovare la catena
cert_map = {cert.subject.rfc4514_string(): (cert, pem) for cert, pem in certs}

# Trova il leaf (quello che non è issuer di nessuno)
issuers = set(c.issuer.rfc4514_string() for c, _ in certs)
subjects = set(c.subject.rfc4514_string() for c, _ in certs)

leaf_subjects = subjects - issuers
if not leaf_subjects:
  print("No leaf certificate")
  sys.exit(1)

leaf_subject = leaf_subjects.pop()
leaf_cert, leaf_pem = cert_map[leaf_subject]

# Costruisci la catena intermedi → leaf
ordered_pems = []
current_cert = leaf_cert

# Cammina all’indietro lungo la chain per ottenere la catena
while current_cert.issuer != current_cert.subject:
  issuer_dn = current_cert.issuer.rfc4514_string()
  if issuer_dn not in cert_map:
    break # root non presente
  issuer_cert, issuer_pem = cert_map[issuer_dn]
  ordered_pems.insert(0, issuer_pem) # prepend intermediate
  current_cert = issuer_cert

# Infine aggiungi il leaf (ultimo)
ordered_pems.append(leaf_pem)

# Scrivi l'output finale: intermedi prima, leaf per ultimo
with open(sys.argv[2], "wb") as f:
  for pem in ordered_pems:
    f.write(pem + b"\n")
  sys.exit(0)
