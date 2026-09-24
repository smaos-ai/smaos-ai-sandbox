import re
from typing import Any, Dict, List, Tuple

class HCLParser:
    """Zero-dependency recursive-descent parser for HCL governance syntax."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        while self.pos < len(self.text):
            self._skip_whitespace()
            if self.pos >= len(self.text):
                break
            
            block_type = self._read_identifier()
            self._skip_whitespace()
            
            block_name = ""
            if self.pos < len(self.text) and self.text[self.pos] == '"':
                block_name = self._read_string()
                self._skip_whitespace()
                
            if self.pos < len(self.text) and self.text[self.pos] == "{":
                self.pos += 1
                body = self._parse_block_body()
                if block_type not in result:
                    result[block_type] = {} if block_name else body
                if block_name:
                    result[block_type][block_name] = body
            else:
                raise ValueError(f"Expected '{{' at position {self.pos}")
        return result

    def _skip_whitespace(self):
        while self.pos < len(self.text):
            if self.text[self.pos] in " \t\r\n":
                self.pos += 1
            elif self.text[self.pos] == "#" or (self.text[self.pos:self.pos+2] == "//"):
                while self.pos < len(self.text) and self.text[self.pos] != "\n":
                    self.pos += 1
            else:
                break

    def _read_identifier(self) -> str:
        start = self.pos
        while self.pos < len(self.text) and (self.text[self.pos].isalnum() or self.text[self.pos] in "_-"):
            self.pos += 1
        return self.text[start:self.pos]

    def _read_string(self) -> str:
        self.pos += 1 # skip opening quote
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] != '"':
            if self.text[self.pos] == "\\":
                self.pos += 2
            else:
                self.pos += 1
        val = self.text[start:self.pos]
        self.pos += 1 # skip closing quote
        return val

    def _parse_block_body(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        while self.pos < len(self.text):
            self._skip_whitespace()
            if self.pos >= len(self.text) or self.text[self.pos] == "}":
                if self.pos < len(self.text):
                    self.pos += 1
                break
                
            key = self._read_identifier()
            self._skip_whitespace()
            if self.pos < len(self.text) and self.text[self.pos] == "=":
                self.pos += 1
                self._skip_whitespace()
                val = self._parse_value()
                body[key] = val
            elif self.pos < len(self.text) and self.text[self.pos] == "{":
                self.pos += 1
                sub_body = self._parse_block_body()
                body[key] = sub_body
            else:
                raise ValueError(f"Expected '=' or '{{' for key {key} at {self.pos}")
        return body

    def _parse_value(self) -> Any:
        self._skip_whitespace()
        if self.pos >= len(self.text):
            return None
        c = self.text[self.pos]
        if c == '"':
            return self._read_string()
        if c == "[":
            self.pos += 1
            items = []
            while self.pos < len(self.text):
                self._skip_whitespace()
                if self.pos < len(self.text) and self.text[self.pos] == "]":
                    self.pos += 1
                    break
                items.append(self._parse_value())
                self._skip_whitespace()
                if self.pos < len(self.text) and self.text[self.pos] == ",":
                    self.pos += 1
            return items
        
        # Numbers or Booleans
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in " ,\r\n}#]":
            self.pos += 1
        raw = self.text[start:self.pos]
        if raw.lower() == "true":
            return True
        if raw.lower() == "false":
            return False
        try:
            if "." in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            return raw
