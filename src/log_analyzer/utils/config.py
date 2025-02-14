import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .constants import DEFAULT_CONFIG, ENV_VARS
from .helpers import merge_dicts


class Config:
    """Configuration management for log analyzer"""

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """Initialize configuration.

        Args:
            config_path: Optional path to configuration file
        """
        self._config = deepcopy(DEFAULT_CONFIG)

        # Load configuration from file if provided
        if config_path:
            self.load_file(config_path)

        # Apply environment variables
        self.load_environment()

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key (dot notation supported)
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

            if value is None:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """Set configuration value.

        Args:
            key: Configuration key (dot notation supported)
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def load_file(self, config_path: Union[str, Path]) -> None:
        """Load configuration from file.

        Args:
            config_path: Path to configuration file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid
        """
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path) as f:
            try:
                file_config = json.load(f)
                self._config = merge_dicts(self._config, file_config)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid configuration file: {e}") from e

    def load_environment(self) -> None:
        """Load configuration from environment variables"""
        for env_var, (config_key, type_func) in ENV_VARS.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    typed_value = type_func(value)
                    self.set(config_key, typed_value)
                except (ValueError, TypeError):
                    # Log warning but continue
                    import logging

                    logging.warning(f"Invalid environment variable {env_var}: {value}")

    def update(self, config: Dict[str, Any]) -> None:
        """Update configuration with dictionary.

        Args:
            config: Configuration dictionary to merge
        """
        self._config = merge_dicts(self._config, config)

    def reset(self) -> None:
        """Reset configuration to defaults"""
        self._config = deepcopy(DEFAULT_CONFIG)

    def as_dict(self) -> Dict[str, Any]:
        """Get complete configuration as dictionary.

        Returns:
            Configuration dictionary
        """
        return deepcopy(self._config)

    def validate(self) -> bool:
        """Validate configuration.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate required fields
        required_fields = [
            "parsing.chunk_size",
            "processing.max_workers",
            "processing.queue_size",
        ]

        for field in required_fields:
            if self.get(field) is None:
                raise ValueError(f"Missing required configuration: {field}")

        # Validate numeric fields
        numeric_fields = [
            ("parsing.chunk_size", 1, None),
            ("parsing.max_line_length", 1, None),
            ("processing.max_workers", 1, None),
            ("processing.queue_size", 1, None),
            ("processing.batch_size", 1, None),
            ("processing.timeout", 0, None),
            ("output.max_errors", 0, None),
        ]

        for field, min_val, max_val in numeric_fields:
            value = self.get(field)
            if value is not None:
                if not isinstance(value, (int, float)):
                    raise ValueError(f"Invalid type for {field}: expected number")
                if min_val is not None and value < min_val:
                    raise ValueError(f"Invalid value for {field}: must be >= {min_val}")
                if max_val is not None and value > max_val:
                    raise ValueError(f"Invalid value for {field}: must be <= {max_val}")

        # Validate boolean fields
        boolean_fields = [
            "parsing.ignore_blank_lines",
            "parsing.ignore_comments",
            "analysis.calculate_metrics",
            "analysis.track_unique_values",
            "output.include_raw_data",
            "output.pretty_print",
        ]

        for field in boolean_fields:
            value = self.get(field)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"Invalid type for {field}: expected boolean")

        return True

    def __getitem__(self, key: str) -> Any:
        """Get configuration value using dictionary access.

        Args:
            key: Configuration key

        Returns:
            Configuration value

        Raises:
            KeyError: If key not found
        """
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        """Set configuration value using dictionary access.

        Args:
            key: Configuration key
            value: Value to set
        """
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Check if configuration key exists.

        Args:
            key: Configuration key

        Returns:
            True if key exists
        """
        return self.get(key) is not None

    def __repr__(self) -> str:
        """Get string representation of configuration.

        Returns:
            String representation
        """
        return f"Config({self._config})"

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary.

        Args:
            config: Configuration dictionary

        Returns:
            New Config instance
        """
        instance = cls()
        instance.update(config)
        return instance

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables.

        Returns:
            New Config instance
        """
        instance = cls()
        instance.load_environment()
        return instance

    def to_file(self, config_path: Union[str, Path]) -> None:
        """Save configuration to file.

        Args:
            config_path: Path to save configuration

        Raises:
            IOError: If file cannot be written
        """
        path = Path(config_path)

        try:
            with open(path, "w") as f:
                json.dump(self._config, f, indent=2, sort_keys=True)
        except IOError as e:
            raise IOError(f"Failed to write configuration file: {e}") from e

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get configuration section.

        Args:
            section: Section name

        Returns:
            Section configuration

        Raises:
            KeyError: If section not found
        """
        if section not in self._config:
            raise KeyError(f"Configuration section not found: {section}")
        return deepcopy(self._config[section])

    def set_section(self, section: str, config: Dict[str, Any]) -> None:
        """Set configuration section.

        Args:
            section: Section name
            config: Section configuration
        """
        self._config[section] = deepcopy(config)

    def get_nested(self, *keys: str, default: Any = None) -> Any:
        """Get nested configuration value.

        Args:
            *keys: Sequence of nested keys
            default: Default value if not found

        Returns:
            Configuration value
        """
        value = self._config

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default

            if value is None:
                return default

        return value

    def set_nested(self, *keys_and_value: Any) -> None:
        """Set nested configuration value.

        Args:
            *keys_and_value: Sequence of keys followed by value

        Raises:
            ValueError: If no value provided
        """
        if len(keys_and_value) < 2:
            raise ValueError("Must provide keys and value")

        keys = keys_and_value[:-1]
        value = keys_and_value[-1]

        config = self._config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    def get_int(self, key: str, default: Optional[int] = None) -> Optional[int]:
        """Get integer configuration value.

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            Integer value or default
        """
        value = self.get(key, default)
        if value is not None:
            try:
                return int(value)
            except (ValueError, TypeError):
                return default
        return default

    def get_float(self, key: str, default: Optional[float] = None) -> Optional[float]:
        """Get float configuration value.

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            Float value or default
        """
        value = self.get(key, default)
        if value is not None:
            try:
                return float(value)
            except (ValueError, TypeError):
                return default
        return default

    def get_bool(self, key: str, default: Optional[bool] = None) -> Optional[bool]:
        """Get boolean configuration value.

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            Boolean value or default
        """
        value = self.get(key, default)
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        return bool(value) if value is not None else default

    def get_list(self, key: str, default: Optional[list] = None) -> Optional[list]:
        """Get list configuration value.

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            List value or default
        """
        value = self.get(key, default)
        if isinstance(value, str):
            return value.split(",")
        return list(value) if value is not None else default
