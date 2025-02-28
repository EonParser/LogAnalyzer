"""Firewall parsers module for registering and accessing all firewall log parsers"""

from typing import Dict, List, Type

from ..base import BaseParser, ParserFactory
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
    
    def get_parser_for_line(self, line: str) -> FirewallLogParser:
        """Find appropriate parser for a log line

        Args:
            line: Log line to parse

        Returns:
            Appropriate FirewallLogParser instance

        Raises:
            ValueError: If no suitable parser is found
        """
        for name, parser_class in self._parsers.items():
            parser = parser_class()
            if parser.supports_format(line):
                return parser
        
        raise ValueError(f"No suitable firewall parser found for: {line[:50]}...")
    
    def register_default_parsers(self) -> None:
        """Register all built-in firewall parsers"""
        self.register_parser("iptables", IPTablesLogParser)
        self.register_parser("pfsense", PFSenseLogParser)
        self.register_parser("cisco_asa", CiscoASALogParser)
        self.register_parser("windows_firewall", WindowsFirewallLogParser)


def register_with_parser_factory(factory: ParserFactory) -> None:
    """Register all firewall parsers with the main parser factory

    Args:
        factory: ParserFactory instance to register parsers with
    """
    factory.register_parser("firewall", FirewallLogParser)
    factory.register_parser("iptables", IPTablesLogParser)
    factory.register_parser("pfsense", PFSenseLogParser)
    factory.register_parser("cisco_asa", CiscoASALogParser)
    factory.register_parser("windows_firewall", WindowsFirewallLogParser)