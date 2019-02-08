:mod:`source`
=============

.. module:: crimson_forge.source
   :synopsis:

This module contains functions and classes for dealing with assembly at the
source code level.

Functions
---------

.. autofunction:: label_maker

.. autofunction:: remove_comments

Classes
-------

.. autoclass:: Reference

.. autoclass:: ReferenceType
   :members: ADDRESS, BLOCK, BLOCK_ADDRESS, INSTRUCTION
   :special-members:

.. autoclass:: SourceCode

.. autoclass:: SourceLine

.. autoclass:: SourceLineComment

.. autoclass:: SourceLineLabel
