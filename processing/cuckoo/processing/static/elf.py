from elftools.elf.elffile import ELFFile
from ..abtracts import Processor
#from capstone import *
import subprocess
import math
#import angr
import struct
import json

class ElfFile(Processor):

    def str_break(self, string):

        """Breaks a string into chunks of 20 characters for readability."""

        spaced_string = []
        for _ in range(0, len(string), 20):
            spaced_string.append(string[_:_+20])

        return ' '.join(spaced_string)

    def extract_var_data(self, filename, ENDIAN):

        """Extracts variable data from an ELF file, including address, size, and inferred values."""

        if ENDIAN == "little":
            prefix = "<"
        if ENDIAN == "big":
            prefix= ">"

        def get_var_addr(filename):
            """Retrieves variable addresses and sizes using readelf."""

            command = f"readelf -s {filename} | grep 'OBJECT'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if stdout:
                output = stdout.decode()
            output = output.splitlines()
            var_data =[]

            for _ in output:
                _ = _.split(' ')
                while '' in _ :
                    _.remove('')
                if not _[-1].startswith('_') and _[-1]!='completed.0':
                    var_data.append(_)
            return var_data

        def analyze_var(bytes_data, size, ENDIAN):
            """
                Analyses most significant byte to infer signed or unsigned values
                if most_sig_byte == 0b10000000, it is most probably signed

                NOTE :  It does not explicitly say if the data is signed or not, but is accurate and consistent with results. Doesnt work with large numbers
                        and some unsigned values using 'b10000000' in place of its most significant byte, and idk how to fix it :/
            """

            most_sig_byte = bytes_data[-1] if ENDIAN == 'little' else bytes_data[0]
            signed_guess = most_sig_byte & 0x80 != 0 #checks if the bytes_data is potentially negative

            if signed_guess:
                signed_value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=True)
                unsigned_value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False)

                if signed_value <= 0:
                    value = signed_value
                else:
                    value = unsigned_value  # Treat as unsigned
            else:
                value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False)

            return value

        with open(filename, 'rb') as f:
            elf = ELFFile(f)

            data_list = []
            for section in elf.iter_sections():
                sh_addr = section['sh_addr']
                sh_size = section['sh_size']

                for n in get_var_addr(filename):
                    address = int(n[1], 16)
                    size = int(n[2])
                    name = n[-1]
                    dump = {}
                # Check if address falls in this section
                    if sh_addr <= address < sh_addr + sh_size:
                        offset = address - sh_addr
                        data = section.data()[offset:offset+size]

                        dump['Variable Name'] = name
                        dump['Address'] = hex(address)
                        dump['Size'] = size
                        dump['Hex Dump'] = self.str_break(data.hex())
                        dump['ASCII Dump'] = self.str_break(data.decode(errors='ignore'))
                        try:
                          dump['Decimal'] = self.str_break(str(int(data.hex(), 16)))
                        except:
                          dump['Decimal'] = ""

                        bytes_data = bytes.fromhex(data.hex())

                        if size == 8:
                            try:
                                value = struct.unpack(prefix + 'd', bytes_data)[0] # Double
                                if str(value) != 'nan':
                                    dump['Double'] = value
                                value = analyze_var(bytes_data, size, ENDIAN) #int64
                                #value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False )
                                dump['int_64'] = value
                            except:
                                pass

                        if size == 4:
                            try:
                                value = struct.unpack(prefix + 'f', bytes_data)[0]  # Float
                                if str(value) != 'nan':
                                    dump['Float'] = value
                                value = analyze_var(bytes_data, size,  ENDIAN)  #int32
                                #value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False )
                                dump['int32'] = value
                            except:
                                pass

                        data_list.append(dump)

            return data_list

    def calculate_entropy(self, data):

        byte_frequencies = [0] * 256
        total_bytes = len(data)

        for byte in data:
            byte_frequencies[byte] += 1

        entropy = 0
        for count in byte_frequencies:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return f"{entropy:.4f}"

    def analyze_elf_sections(self, file_path):
        section_entropy = dict()
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            for section in elf.iter_sections():
                section_name = section.name
                section_data = section.data()
                section_entropy[section_name] = self.calculate_entropy(section_data)
            section_entropy.pop('') if '' in section_entropy.keys() else None
            return section_entropy

    def decompile(self, file):
        proj = angr.Project(file, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        main = proj.kb.functions['main']
        dec = proj.analyses.Decompiler(main, cfg=cfg.model)
        print('[*] Generated C - Lang Pseudocode')

        return dec.codegen.text

    def read_string(self, memory, addr):
        """Read and decode null-terminated strings"""
        s = b""
        while True:
            b = memory.load(addr, 1)
            if b == b"\x00":
                break
            s += b
            addr += 1
        return s.decode()

    def disassem_vars(self, file):

        """Get Variable data from binary"""

        proj = angr.Project(file, auto_load_libs=False)
        var_str = []
        for section in proj.loader.main_object.sections:
            if "data" in section.name or "rodata" in section.name or "bss" in section.name:
                if section.name == ".rodata":

                    # strings
                    # document this part of the code
                    # fr man, i was away for few days nd i forgot how this shit works, awesome....

                    addr = section.vaddr
                    while addr < section.vaddr + section.memsize:
                        try:
                            s = read_string(proj.loader.memory, addr)
                            var_str.append(f"/* Address: {hex(addr)} (.rodata)-> String: {s} */")
                            addr += len(s) + 1
                        except:
                            addr += 1

                elif section.name == ".data":

                    # integers
                    # document this part too :(

                    addr = section.vaddr
                    while addr < section.vaddr + section.memsize:
                        val = proj.loader.memory.load(addr, 4)
                        int_val = struct.unpack("<I", val)[0]
                        var_str.append(f"/* Address: {hex(addr)} (.data)-> Value: {int_val} */")
                        addr += 4
        print('[*] Grabbed Assembly Instructions')
        return '\n'.join(var_str)

    def detect_pyinstaller(self, filename):
            with open(filename, 'rb') as f:
                data = f.read()
            # PyInstaller markers
            markers = [
                b'pyiboot01_bootstrap',
                b'pyimod',
                b'PYZ-00',
                b'_MEIPASS'
            ]

            for marker in markers:
                if marker in data:
                    return f"Detected PyInstaller marker: {marker.decode('utf-8', 'ignore')}"
                else:
                    return False

    def detect_packer(self, filename, use_unpacked):
            result = subprocess.run(['strings', filename], capture_output=True, text=True)
            strings = result.stdout.split(" ")

            # List of common packer markers
            packers = {
                "UPX": ["UPX", "UPX!", "UPX0", "UPX1", "UPX2"],
                "MPRESS": ["MPRESS1", "MPRESS2"],
                "ASPack": ["ASPack"],
                "Themida": ["Themida"],
                "PECompact": ["PEC2"],
                "FSG": ["FSG!"],
                "MEW": ["MEW"],
                "EXEcryptor": ["EXEcryptor"]
            }

            found = []
            for packer, hex in packers.items():
                if any(item in strings for item in hex):
                    found.append(packer)

            def calculate_entropy(data):
                # Initialize a list to count byte frequencies (256 possible byte values)
                byte_frequencies = [0] * 256
                total_bytes = len(data)

                for byte in data:
                    byte_frequencies[byte] += 1

                # Shannon entropy calc:
                entropy = 0
                for count in byte_frequencies:
                    if count > 0:
                        probability = count / total_bytes
                        entropy -= probability * math.log2(probability)

                return entropy

            #if use_unpacked == "y":
            #    note = "Working with Unpacked file"
            #else :
            #    note = "Working with packed file"
            note = ""

            with open(filename, 'rb') as file:
                data = file.read()
            fileentropy = calculate_entropy(data)

            if len(found) > 0:
                print(f"{filename} is packed with {', '.join(found)}, Entropy: {fileentropy:.4f}")
                pa_ = f"{filename} is packed with {', '.join(found)}"

                if 'UPX' in found and use_unpacked :
                    #TODO : Fix error handling for UPX files with manipulated hex data
                    try:
                        subprocess.run(["upx", "-d", filename], check=True, stdout=subprocess.DEVNULL)
                        print("[*] Unpacked UPX file successfully")

                    except:
                        print("[*] Cound not Unpack UPX file")

            elif self.detect_pyinstaller(filename):
                pa_ = self.detect_pyinstaller(filename)

            else :
                if fileentropy > 6:
                    pa_ = "High Entropy detected: Possible encryption or packed sections detected."
                else:
                    pa_ = f"Not packed with any packer"

            return {"Packer" : pa_, "Entropy" : fileentropy, "Note" : note}

    #def disassemble_elf(filename):
    #    '''
    #    usage : disassemble_elf(filename)
    #    '''
    #    opc_list = []
    #    with open(filename, "rb") as f:
    #        elf = ELFFile(f)
    #        arch = CS_ARCH_X86
    #        mode = CS_MODE_64
    #        # disassm sections to find the .text section
    #        for section in elf.iter_sections():
    #            if section.name == ".text":
    #                code = section.data()
    #                addr = section['sh_addr']
    #
    #                opc_list.append('Entry Point:'+ hex(elf.header['e_entry']))
    #
    #
    #                md = Cs(arch, mode)
    #                md.detail = True
    #
    #                ###
    #                for insn in md.disasm(code, addr):
    #                    opc_list.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    #                break
    #        else:
    #            opc_list.append("No .text section found.")
    #
    #    return '\n'.join(opc_list)

    def detect_antidebug_apis(self, file_path):
        suspicious_symbols = [
                {'ptrace': 'Used to prevent debugger attachment'},
                {'getppid': 'Checks if parent process is a debugger'},
                {'syscall':'Direct syscall usage to evade detection'},
                {'prctl': 'Disables ptrace for self'},
                {'sigaction': 'Modifies signal handling to disrupt debuggers'},
                {'fork': 'Creates processes to hide from debuggers'},
                {'execve': 'Re-spawns itself to avoid debugging'}
        ]

        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            symbols = []
            # Scan symbol tables
            for section in elf.iter_sections():
                if section.header['sh_type'] == 'SHT_SYMTAB':
                    symtab = section
                    for sym in symtab.iter_symbols():
                        if sym.name:
                            symbols.append(sym.name)

            # Match symbols
            matches = []
            for _ in suspicious_symbols:
                sym = list(_.keys())[0]
                for i in symbols:
                    if sym in i:
                        matches.append(_)

            return {list(item.keys())[0]: list(item.values())[0] for item in matches}

    def header(self, file):
        data = subprocess.run(["readelf", "-h", file, "-W"], text=True, capture_output=True).stdout
        header_data = dict()
        for _ in data.splitlines():
           key, value = _.split(":")
           key = key.strip()
           value = value.strip()
           if value.isdigit():
               value = int(value)
           header_data[key] = value
        header_data.pop("ELF Header")

        filedata = subprocess.run(["file", file], text=True, capture_output=True).stdout
        filedata = filedata.split(",")
        if ' not stripped\n' in filedata:
            header_data["Stripped File"] = False
        else:
            header_data["Stripped File"] = True

        print("[*] Parsed Header Data")

        return header_data

    def sections(self, file):
        data = subprocess.run(["readelf", "-S", file, "-W"], text=True, capture_output=True).stdout
        if data.strip() != "There are no sections in this file." :
            section_list, parsed_list, section_data = [[] for _ in range(3)]
            data_keys = ["Name", "Type", "Address", "Offset", "Size", "Entry Size", "Flags", "Link", "Info", "Alignment"]
            for _ in data.splitlines():
                if _.startswith("  ["):
                    section_list.append(_)
            section_list = section_list[2:]
            for _i in section_list:
                _i = _i.split(" ")
                while '' in _i:
                    _i.remove('')
                if _i[0] == "[" :
                    _i = _i[2:]
                else :
                    _i = _i[1:]
                if len(_i) < 10:
                    _i.insert(6, "Unknown")
                if len(_i)>10 and _i[7] in "WAXMSILOGTCxoEDlp":
                    _i[6] = _i[6] + _i[7]
                    _i.pop(7)
                parsed_list.append(_i)
            for _j in parsed_list:
                _j = dict(zip(data_keys, _j))
                section_data.append(_j)

            output = []
            entropy_data = self.analyze_elf_sections(file)
            for item in section_data:
                key = item['Name']
                if key in entropy_data:
                    item['Entropy'] = entropy_data[key]
                output.append(item)
        elif data.strip() == "There are no sections in this file." :
            output = "No Section data found in the file, file is possibly manipulated or packed"
        else :
            output = "An Unknown Error Occured"

        print("[*] Parsed Section Data")

        return output

        #TODO :permissions of each sections in complete words instead of WAX format

    def program_headers(self, file):
        data = subprocess.run(["readelf","-l", file, "-W"], text=True, capture_output=True).stdout
        data = data.splitlines()
        start = data.index("Program Headers:")
        if " Section to Segment mapping:" not in data :
            data = data[start:]
        else:
            end = data.index(" Section to Segment mapping:")
            data = data[start+2:end-1]
        header_keys = ['Type', 'Offset', 'Virtual Address', 'Physical Address', 'File Size', 'Memory Size', 'Flags', 'Alignment']
        program_headers = []
        for _ in data:
            if 'Requesting' not in _:
                _ = _.split(' ')
                while '' in _:
                    _.remove('')
                if len(_)>7 and _[7] in "WAXMSILOGTCxoEDlp":
                    _[6] = _[6] + _[7]
                    _.pop(7)
                _ = dict(zip(header_keys, _))
                program_headers.append(_)

        print("[*] Parsed Program Headers")

        return program_headers

    def shared_libraries(self, file):
        data = subprocess.run(["readelf","-d", file, "-W"], text=True, capture_output=True).stdout

        if data.strip()!="There is no dynamic section in this file.":

            data = data.splitlines()
            shared_libraries = []
            for _ in data:
                if "NEEDED" in _:
                    _ = _.split(' ')
                    while '' in _ :
                        _.remove('')
                    shared_libraries.append(_[-1])
        else:
            shared_libraries = ["Could'nt retrive Shared Libraries"]
        return shared_libraries

    def dyn_syms(self, file):
        data = subprocess.run(["readelf","--dyn-syms", file, "-W"], text=True, capture_output=True).stdout
        if len(data)!=0:
            data = data.splitlines()[3:]
            table_keys = ["Offset Value", "Size", "Type", "Symbol Binding", "Visibility", "Section Index" , "Name"]
            dyn_sym_table = []
            for _ in data:
                _ = _.split(' ')
                while '' in _ :
                    _.remove('')
                _.pop(0)
                _ = dict(zip(table_keys, _))
                dyn_sym_table.append(_)
        else:
            dyn_sym_table = ["Couldn't retrive the Dynamic Symbols table "]

        print("[*] Parsed Dynamic Symbols table")

        return dyn_sym_table

    def functions(self, file):
        command = f"objdump -d {file} | grep '<.*>:'"
        map = ["Offset Value", "Function"]
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        function_table = []
        if stdout:
            output = stdout.decode()
            output = output.splitlines()

            for _ in output:
                _ = _.split(' ')
                _[-1]= _[-1][1:-2]
                _ = dict(zip(map, _))
                function_table.append(_)

        if stderr:
            raise ValueError

        print("[*] Parsed Functions")

        return function_table

    def variable_data(self, file):
        header_dict = self.header(file)
        if "little" in header_dict['Data']:
            endian = "little"
        else :
            endian = "big"
        vars = self.extract_var_data(file, endian)
        if len(vars) == 0:
            vars = ['No Varibles are defined in the .data section']

        print("[*] Parsed Variable Data")
        return vars

    def antidebug_apis(self, file):
        apis = self.detect_antidebug_apis(file)
        if len(apis) == 0:
            apis = ['No Suspicious Apis Detected']
        print("[*] Analysed APIs")
        return apis

    def packer(self, file, arg):

        print("[*] Analysing Packer data")
        return self.detect_packer(file, arg)

    def data(self, file, unpack):
        table = ['headers', 'packer_info', 'sections', 'program_header', 'shared_libraries', 'dynamic_symbols', 'functions', 'variable_data', 'suspicious_api'] #, '<h2>Disassembling</h2>']

        vars = [self.header(file),
            self.packer(file, unpack),
            self.sections(file),
            self.program_headers(file),
            self.shared_libraries(file),
            self.dyn_syms(file),
            self.functions(file),
            self.variable_data(file),
            self.antidebug_apis(file)#,
            #disassemble_elf(file)
            ]
        data = dict(zip(table, vars))

        return data

    def static_analysis(self, file_path, unpack):
        """
        Perform static analysis on the given file and generate an HTML report.

        Args:
            file_path (str): Path to the file to be analyzed.
            save_json (bool): Whether to save the analysis result as JSON.
            unpack (bool): Whether to attempt unpacking UPX.
        """
        analysis_result = self.data(file_path, unpack)
        #analysis_json = json.dumps(analysis_result, indent=4)
        return analysis_result

    def __init__(self, filepath):
        self._filepath = filepath

    def to_dict(self):
        return {"elf_analysis": self.static_analysis(self._filepath, True)}
  
#print(ElfFile("/tmp/pnscan").to_dict())
