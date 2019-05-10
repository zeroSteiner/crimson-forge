{% set ___macro_strings = 0 %}

{% macro load_string(value, register) -%}
  {% set _macro_strings = ___macro_strings + 1 -%}
  ; {{ register }} = &'{{ value }}'
  call _macro_string{{ ___macro_strings }}
  {% for source_line in raw_string(value) %}
  {{ source_line.code }}
  {% endfor %}
_macro_string{{ ___macro_strings }}:
  pop {{ register }}
{%- endmacro %}