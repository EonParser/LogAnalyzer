from typing import Dict, List, Any, Set
import re

class FieldDetector:
    """Detects and extracts fields from log entries"""
    
    def __init__(self):
        """Initialize field detector"""
        self.common_fields = {
            "timestamp": ["timestamp", "time", "date", "@timestamp"],
            "ip": ["ip", "ip_address", "client_ip", "source_ip", "destination_ip", "src", "dst", "remotehost"],
            "port": ["port", "src_port", "dst_port", "source_port", "destination_port"],
            "status": ["status", "status_code", "response_code"],
            "method": ["method", "http_method", "request_method"],
            "user": ["user", "username", "user_id", "userid"],
            "level": ["level", "severity", "loglevel"],
            "path": ["path", "url", "uri", "request_uri", "endpoint"],
            "action": ["action", "operation"]
        }
        
        # Field types
        self.field_types = {
            "timestamp": "datetime",
            "ip": "string",
            "port": "number",
            "status": "number",
            "method": "string",
            "user": "string",
            "level": "string",
            "path": "string",
            "action": "string"
        }

    def detect_fields(self, entries: List[Any]) -> Dict[str, Dict[str, Any]]:
        """Detect fields from a list of log entries
        
        Args:
            entries: List of log entries
            
        Returns:
            Dictionary mapping field name to field information
        """
        if not entries:
            return {}
            
        detected_fields = {}
        field_values = {}
        
        # Detect fields from the entries
        for entry in entries[:100]:  # Sample from first 100 entries
            if hasattr(entry, "parsed_data") and entry.parsed_data:
                # Flatten nested structure
                fields = self._flatten_dict(entry.parsed_data)
                
                for field_name, value in fields.items():
                    # Skip null values
                    if value is None:
                        continue
                        
                    # Initialize field if not seen before
                    if field_name not in field_values:
                        field_values[field_name] = set()
                    
                    # Add value to the set (only if serializable)
                    try:
                        # Convert to string for consistent handling
                        str_value = str(value)
                        if len(str_value) < 100:  # Skip very long values
                            field_values[field_name].add(str_value)
                    except:
                        pass
        
        # Create field information
        for field_name, values in field_values.items():
            # Skip fields with too many unique values
            if len(values) > 50 and len(values) > len(entries) * 0.5:
                continue
                
            # Determine field type
            field_type = self._determine_field_type(field_name, values)
            
            # Find standard name if possible
            standard_name = self._get_standard_field_name(field_name)
            
            detected_fields[field_name] = {
                "name": field_name,
                "standard_name": standard_name,
                "type": field_type,
                "unique_values": list(values)[:50],  # Limit to first 50 values
                "value_count": len(values)
            }
            
        return detected_fields
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
        """Flatten a nested dictionary
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for nested dictionaries
            
        Returns:
            Flattened dictionary
        """
        items = {}
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            
            if isinstance(v, dict):
                # If the nested dictionary is small, we also include it directly
                if len(v) <= 5:  
                    items[new_key] = v
                # Recursively flatten nested dictionaries
                items.update(self._flatten_dict(v, new_key))
            else:
                items[new_key] = v
        return items
    
    def _determine_field_type(self, field_name: str, values: Set[str]) -> str:
        """Determine the type of a field
        
        Args:
            field_name: Field name
            values: Set of values for the field
            
        Returns:
            Field type
        """
        # Check if field matches a known type
        for std_name, names in self.common_fields.items():
            for name in names:
                if name.lower() in field_name.lower():
                    return self.field_types.get(std_name, "string")
        
        # Try to infer type from values
        if not values:
            return "string"
            
        # Check if all values are numeric
        numeric_count = sum(1 for v in values if v.isdigit())
        if numeric_count == len(values):
            return "number"
            
        # Check if values look like IP addresses
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ip_count = sum(1 for v in values if re.match(ip_pattern, v))
        if ip_count > 0 and ip_count == len(values):
            return "ip"
            
        # Default to string
        return "string"
    
    def _get_standard_field_name(self, field_name: str) -> str:
        """Get standard field name if possible
        
        Args:
            field_name: Original field name
            
        Returns:
            Standard field name or original name
        """
        field_lower = field_name.lower()
        
        for std_name, names in self.common_fields.items():
            # Exact match
            if field_lower in names:
                return std_name
                
            # Partial match
            for name in names:
                if name in field_lower:
                    return std_name
        
        return field_name