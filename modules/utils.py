import os
import json

class Config:
    """
    Configuration management for VIPER
    Loads settings from config/config.json including:
    - User agents for request rotation
    - Blacklisted domains to exclude from results
    - Search engine configurations
    - GitHub repository URL for updates
    """
    
    @staticmethod
    def load_config():
        """
        Load configuration from config/config.json
        
        Returns:
            dict: Configuration dictionary if successful, None otherwise
        """
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.json')
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                return config_data
        except FileNotFoundError:
            print(f"Warning: config.json not found at {config_path}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing config.json: {e}")
            return None
        except Exception as e:
            print(f"Error loading config: {e}")
            return None