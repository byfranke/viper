import os
import json

class Config:
    @staticmethod
    def load_config():
        """Load configuration from config file"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.json')
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return None

def render_html_template(template_name, **kwargs):
    """Render HTML template with given context"""
    template_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', template_name)
    try:
        with open(template_path, 'r') as f:
            template_content = f.read()
            # Simple template rendering
            for key, value in kwargs.items():
                template_content = template_content.replace('{{ ' + key + ' }}', str(value))
                template_content = template_content.replace('{{' + key + '}}', str(value))
            return template_content
    except Exception as e:
        return f"Error rendering template: {e}"