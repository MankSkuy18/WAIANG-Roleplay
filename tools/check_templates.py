from jinja2 import TemplateSyntaxError
import os
import sys
# Add the workspace to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app

errors = 0
for root, dirs, files in os.walk(os.path.join(os.path.dirname(__file__), '..', 'templates')):
    for fname in files:
        if not fname.endswith('.html'):
            continue
        rel = os.path.join(root, fname)
        template_name = os.path.relpath(rel, os.path.join(os.path.dirname(__file__), '..', 'templates'))
        try:
            with app.app_context():
                app.jinja_env.get_template(template_name)
        except TemplateSyntaxError as e:
            errors += 1
            print(f"Template syntax error in {template_name}: {e.message} (line {e.lineno})")
        except Exception as e:
            errors += 1
            print(f"Other error loading {template_name}: {e}")

if errors == 0:
    print("No template syntax errors found.")
else:
    print(f"Found {errors} template error(s).")
