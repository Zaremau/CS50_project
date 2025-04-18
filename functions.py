import re

from flask import redirect, render_template, session
from functools import wraps




# function for validating an Email
def check_email(email):
  return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", email))

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# function for validating a language
def check_language(l):
    languages = ["arabic",
                "bulgarian",
                "catalan",
                "chinese",
                "croatian",
                "czech",
                "danish",
                "dutch",
               "english",
                "finnish",
                "french",
                "german",
                "greek",
                "hebrew",
                "hindi",
                "hungarian",
                "indonesian",
                "italian",
                "japanese",
                "korean",
                "latvian",
                "lithuanian",
                "norwegian",
                "polish",
                "portuguese",
                "romanian",
                "russian",
               "serbian",
                "slovak",
                "slovenian",
                "spanish",
                "swedish",
                "tagalog",
                "thai",
                "turkish",
                "kkrainian",
                "vietnamese",]
    if l in languages:
        return True
    else:
        return False