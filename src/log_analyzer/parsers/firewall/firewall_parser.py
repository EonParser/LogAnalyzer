"""Firewall parsers module for registering and accessing all firewall log parsers"""

import logging
from typing import Dict, List, Type, Optional

from ..base import BaseParser, ParserFactory, LogEntry
from ..firewall_base import FirewallLogParser
from .iptables import IPTablesLogParser
from .pfsense import PFSenseLogParser
from .ciscoasa import CiscoASALogParser
from .windows import WindowsFirewallLogParser


class FirewallParserFactory:
    """Factory class for creating and managing firewall parsers"""
    
    def __init__(self):
        """Initialize the firewall parser factory"""
        self._parsers: Dict[str, Type[FirewallLogParser]] = {}
        self.logger = logging.getLogger(__name__)
        
        # Register default parsers
        self.register_default_parsers()
    
    def register_parser(self, name: str, parser_class: Type[FirewallLogParser]) -> None:
        """Register a new firewall parser

        Args:
            name: Name of the parser
            parser_class: Parser class to register
        """
        self._parsers[name] = parser_class
    
    def get_parser(self, name: str) -> FirewallLogParser:
        """Get a parser instance by name

        Args:
            name: Name of the parser to get

        Returns:
            FirewallLogParser instance

        Raises:
            ValueError: If parser with given name is not registered
        """
        if name not in self._parsers:
            available = ", ".join(self._parsers.keys())
            raise ValueError(f"Firewall parser '{name}' not found. Available parsers: {available}")
        
        return self._parsers[name]()
    
    def get_all_parsers(self) -> List[FirewallLogParser]:
        """Get instances of all registered parsers

        Returns:
            List of FirewallLogParser instances
        """
        return [parser_class() for parser_class in self._parsers.values()]
    
    def get_parser_for_line(self, line: str) -> Optional[FirewallLogParser]:
        """Find appropriate parser for a log line

        Args:
            line: Log line to parse

        Returns:
            Appropriate FirewallLogParser instance or None if no suitable parser found
        """
        for name, parser_class in self._parsers.items():
            parser = parser_class()
            if parser.supports_format(line):
                return parser
        
        return None
    
    def register_default_parsers(self) -> None:
        """Register all built-in firewall parsers"""
        self.register_parser("iptables", IPTablesLogParser)
        self.register_parser("pfsense", PFSenseLogParser)
        self.register_parser("cisco_asa", CiscoASALogParser)
        self.register_parser("windows_firewall", WindowsFirewallLogParser)


class CombinedFirewallParser(FirewallLogParser):
    """Parser that tries all firewall parsers to find one that works"""
    
    def __init__(self):
        """Initialize combined firewall parser"""
        super().__init__()
        self.name = "firewall"
        self.description = "Combined Firewall Log Parser"
        self.logger = logging.getLogger(__name__)
        
        # Create factory and get all parsers
        self.factory = FirewallParserFactory()
        self.parsers = self.factory.get_all_parsers()
    
    def supports_format(self, line: str) -> bool:
        """Check if any firewall parser supports this format"""
        return any(parser.supports_format(line) for parser in self.parsers)
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Try all parsers until one succeeds"""
        for parser in self.parsers:
            if parser.supports_format(line):
                try:
                    self.logger.debug(f"Using {parser.name} parser for line: {line[:50]}...")
                    return parser.parse_line(line)
                except Exception as e:
                    self.logger.warning(f"Parser {parser.name} failed: {str(e)}")
                    continue
        
        # Log a warning if no parser could handle the line
        self.logger.warning(f"No parser could parse line: {line[:50]}...")
        return None


def register_with_parser_factory(factory: ParserFactory) -> None:
    """Register all firewall parsers with the main parser factory

    Args:
        factory: ParserFactory instance to register parsers with
    """
    # Register the combined parser as the main 'firewall' parser
    factory.register_parser("firewall", CombinedFirewallParser)
    
    # Also register individual parsers for direct access
    factory.register_parser("iptables", IPTablesLogParser)
    factory.register_parser("pfsense", PFSenseLogParser)
    factory.register_parser("cisco_asa", CiscoASALogParser)
    factory.register_parser("windows_firewall", WindowsFirewallLogParser)