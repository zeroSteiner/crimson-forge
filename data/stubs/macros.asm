{% set ___macro_strings = [] %}

{% macro load_string(value, register) -%}
  {% do ___macro_strings.append(value) -%}
  ; {{ register }} = &'{{ value }}'
  call _macro_string{{ ___macro_strings | length }}
  {% for source_line in raw_string(value) %}
  {{ source_line.code }}
  {% endfor %}
_macro_string{{ ___macro_strings | length }}:
  pop {{ register }}
{%- endmacro %}

{% macro _amd64_memcpy(dest, src, n) %}
  mov rcx, {{ n }}
  {% if dest != 'rsi' %}mov rsi, {{ src }}{% endif %}
  {% if dest != 'rdi' %}mov rdi, {{ dest }}{% endif %}
  mov rax, rdi
  rep movsb
{% endmacro %}

{% macro _amd64_memset(dest, val, n) %}
  mov rcx, {{ n }}
{% if val != 'rax' %}
  mov rax, {{ val }}
{% endif %}
{% if dest != 'rdi' %}
  mov rdi, {{ dest }}
{% endif %}
  push rdi
  rep stosb
  pop rax
{% endmacro %}

{% macro _x86_memcpy(dest, src, n) %}
  mov ecx, {{ n }}
  {% if dest != 'esi' %}mov esi, {{ src }}{% endif %}
  {% if dest != 'edi' %}mov edi, {{ dest }}{% endif %}
  mov eax, edi
  rep movsb
{% endmacro %}

{% macro _x86_memset(dest, val, n) %}
  mov ecx, {{ n }}
{% if val != 'eax' %}
  mov eax, {{ val }}
{% endif %}
{% if dest != 'edi' %}
  mov edi, {{ dest }}
{% endif %}
  push edi
  rep stosb
  pop eax
{% endmacro %}

{% macro memcpy(dest, src, n) -%}
  ; memcpy({{ dest }}, {{ src }}, {{ n }})
{% if arch == 'x86' %}{{ _x86_memcpy(dest, src, n) }}{% endif %}
{% if arch == 'amd64' %}{{ _amd64_memcpy(dest, str, n) }}{% endif %}
{%- endmacro %}

{% macro memset(dest, val, n) -%}
  ; memset({{ dest }}, {{ val }}, {{ n }})
{{ assert(val < 256, 'value is a single byte') -}}
{% if arch == 'x86' %}{{ _x86_memset(dest, val, n) }}{% endif %}
{% if arch == 'amd64' %}{{ _amd64_memset(dest, val, n) }}{% endif %}
{%- endmacro %}