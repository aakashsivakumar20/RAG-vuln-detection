import json
import pickle

import yaml


def load_session_blob(blob):
    return pickle.loads(blob)


def load_settings(text):
    return yaml.load(text, Loader=yaml.Loader)


def calculate(expression):
    return eval(expression)


def load_session_safe(text):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("session payload must be an object")
    return {"user_id": int(data.get("user_id", 0)), "theme": str(data.get("theme", "light"))}


def load_settings_safe(text):
    return yaml.safe_load(text)


def render_template_string(template, context):
    return template.format(**context)
