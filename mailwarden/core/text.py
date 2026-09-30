"""Text normalisation shared by the gate and the redactor.

Defeats common obfuscation before any pattern matching: compatibility forms
(full-width digits, ligatures), zero-width and bidi-control characters,
terminal control sequences, and Cyrillic/Greek look-alike letters.
"""

from __future__ import annotations

import re
import unicodedata

_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠎​-‏"
    "‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CONFUSABLES = str.maketrans(
    "АВЕКМНОРСТХУаеорсухіјѕΑΒΕΖΗΙΚΜΝΟΡΤΥΧοριν",
    "ABEKMHOPCTXYaeopcyxijsABEZHIKMNOPTYXopiv",
)


def clean(text: str) -> str:
    """NFKC, drop invisible/bidi characters and terminal control codes."""
    text = unicodedata.normalize("NFKC", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = _INVISIBLE.sub("", text)
    return _CONTROL.sub(" ", text)


def fold(text: str) -> str:
    """clean() plus look-alike letter folding, for pattern matching only."""
    return clean(text).translate(_CONFUSABLES)
