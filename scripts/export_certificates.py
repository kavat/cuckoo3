import pefile
import sys

nome_file = sys.argv[1]
signature_file = sys.argv[2]
pe = pefile.PE(nome_file, fast_load=False)

# Entry 4 è IMAGE_DIRECTORY_ENTRY_SECURITY
security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

virtual_address = security_dir.VirtualAddress
size = security_dir.Size

#print(f"Sicurezza trovata a VA={virtual_address}, size={size}")

if virtual_address != 0 and size != 0:
  # WIN_CERTIFICATE header è lungo 8 byte, va saltato
  with open(nome_file, "rb") as f:
    f.seek(virtual_address + 8)
    data = f.read(size - 8)
    with open(signature_file, "wb") as out:
      out.write(data)
  sys.exit(0)
else:
  print("Sign not found")
sys.exit(1)
