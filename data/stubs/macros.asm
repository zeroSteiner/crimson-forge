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