import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from log_analyzer.utils.config import Config
from log_analyzer.utils.constants import DEFAULT_CONFIG


@pytest.fixture
def config():
    """Create fresh configuration instance"""
    return Config()


@pytest.fixture
def config_file(tmp_path):
    """Create temporary configuration file"""
    config_data = {
        "parsing": {"chunk_size": 16384, "ignore_comments": False},
        "processing": {"max_workers": 8},
    }

    config_path = tmp_path / "config.json"
    with open(config_path, "w") as f:
        json.dump(config_data, f)

    return config_path


class TestConfig:
    """Test configuration management"""

    def test_default_config(self, config):
        """Test default configuration values"""
        assert (
            config.get("parsing.chunk_size") == DEFAULT_CONFIG["parsing"]["chunk_size"]
        )
        assert (
            config.get("processing.max_workers")
            == DEFAULT_CONFIG["processing"]["max_workers"]
        )

    def test_load_file(self, config, config_file):
        """Test loading configuration from file"""
        config.load_file(config_file)

        assert config.get("parsing.chunk_size") == 16384
        assert config.get("parsing.ignore_comments") is False
        assert config.get("processing.max_workers") == 8

        # Default values should still be present
        assert (
            config.get("parsing.max_line_length")
            == DEFAULT_CONFIG["parsing"]["max_line_length"]
        )

    def test_load_environment(self, config):
        """Test loading configuration from environment variables"""
        os.environ["LOG_ANALYZER_MAX_WORKERS"] = "16"
        os.environ["LOG_ANALYZER_CHUNK_SIZE"] = "32768"

        config.load_environment()

        assert config.get("processing.max_workers") == 16
        assert config.get("parsing.chunk_size") == 32768

        # Cleanup
        del os.environ["LOG_ANALYZER_MAX_WORKERS"]
        del os.environ["LOG_ANALYZER_CHUNK_SIZE"]

    def test_invalid_environment_values(self, config):
        """Test handling of invalid environment values"""
        os.environ["LOG_ANALYZER_MAX_WORKERS"] = "invalid"

        config.load_environment()

        # Should keep default value
        assert (
            config.get("processing.max_workers")
            == DEFAULT_CONFIG["processing"]["max_workers"]
        )

        # Cleanup
        del os.environ["LOG_ANALYZER_MAX_WORKERS"]

    def test_update_config(self, config):
        """Test updating configuration"""
        new_config = {"parsing": {"chunk_size": 32768}, "custom": {"value": "test"}}

        config.update(new_config)

        assert config.get("parsing.chunk_size") == 32768
        assert config.get("custom.value") == "test"
        assert (
            config.get("processing.max_workers")
            == DEFAULT_CONFIG["processing"]["max_workers"]
        )

    def test_nested_keys(self, config):
        """Test accessing nested configuration keys"""
        assert (
            config.get("parsing.chunk_size") == DEFAULT_CONFIG["parsing"]["chunk_size"]
        )
        assert config.get("invalid.key") is None
        assert config.get("invalid.key", "default") == "default"

    def test_set_value(self, config):
        """Test setting configuration values"""
        config.set("custom.nested.value", "test")
        assert config.get("custom.nested.value") == "test"

        config["simple.key"] = "value"
        assert config["simple.key"] == "value"

    def test_validation(self, config):
        """Test configuration validation"""
        # Valid configuration
        assert config.validate() is True

        # Invalid chunk size
        config.set("parsing.chunk_size", -1)
        with pytest.raises(ValueError):
            config.validate()

        # Invalid type
        config.set("parsing.chunk_size", "invalid")
        with pytest.raises(ValueError):
            config.validate()

    def test_type_conversion(self, config):
        """Test type conversion helpers"""
        config.set("test.integer", "123")
        config.set("test.float", "123.45")
        config.set("test.bool_true", "true")
        config.set("test.bool_false", "false")
        config.set("test.list", "a,b,c")

        assert config.get_int("test.integer") == 123
        assert config.get_float("test.float") == 123.45
        assert config.get_bool("test.bool_true") is True
        assert config.get_bool("test.bool_false") is False
        assert config.get_list("test.list") == ["a", "b", "c"]

    def test_save_config(self, config, tmp_path):
        """Test saving configuration to file"""
        config_path = tmp_path / "saved_config.json"
        config.to_file(config_path)

        # Load saved config
        with open(config_path) as f:
            saved_config = json.load(f)

        assert saved_config == config.as_dict()

    def test_config_isolation(self, config):
        """Test configuration dictionary isolation"""
        original = deepcopy(config.as_dict())

        # Modify returned dictionary
        config_dict = config.as_dict()
        config_dict["parsing"]["chunk_size"] = 999999

        # Original should be unchanged
        assert config.get("parsing.chunk_size") == original["parsing"]["chunk_size"]

    def test_section_management(self, config):
        """Test configuration section management"""
        # Get section
        parsing_config = config.get_section("parsing")
        assert parsing_config["chunk_size"] == DEFAULT_CONFIG["parsing"]["chunk_size"]

        # Set section
        new_section = {"custom_key": "value"}
        config.set_section("custom", new_section)
        assert config.get_section("custom") == new_section

        # Invalid section
        with pytest.raises(KeyError):
            config.get_section("invalid")


if __name__ == "__main__":
    pytest.main([__file__])
