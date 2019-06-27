{% set ___macro_strings = [] %}

{% macro load_string(value, register=None) -%}
  {% do ___macro_strings.append(value) -%}
  ; {{ register }} = &'{{ value }}'
  call _macro_string{{ ___macro_strings | length }}
  {% for source_line in raw_string(value) %}
  {{ source_line.code }}
  {% endfor %}
_macro_string{{ ___macro_strings | length }}:
{% if register is not none %}  pop {{ register }}{% endif %}
{%- endmacro %}

{% macro _amd64_memcpy(dest, src, n) %}
  mov rcx, {% if n is number %}{{ '0x%0x' % n }}{% else %}{{ n }}{% endif %}

  {% if dest != 'rsi' %}mov rsi, {{ src }}{% endif %}
  {% if dest != 'rdi' %}mov rdi, {{ dest }}{% endif %}
  mov rax, rdi
  rep movsb
{% endmacro %}

{% macro _amd64_memset(dest, val, n) %}
  mov rcx, {% if n is number %}{{ '0x%0x' % n }}{% else %}{{ n }}{% endif %}

{% if val == 0 %}
  xor rax, rax
{% elif val != 'rax' %}
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
  mov ecx, {% if n is number %}{{ '0x%0x' % n }}{% else %}{{ n }}{% endif %}

  {% if dest != 'esi' %}mov esi, {{ src }}{% endif %}
  {% if dest != 'edi' %}mov edi, {{ dest }}{% endif %}
  mov eax, edi
  rep movsb
{% endmacro %}

{% macro _x86_memset(dest, val, n) %}
  mov ecx, {% if n is number %}{{ '0x%0x' % n }}{% else %}{{ n }}{% endif %}

{% if val == 0 %}
  xor eax, eax
{% elif val != 'eax' %}
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