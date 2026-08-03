# Intentionally vulnerable Flask service — corpus fixture.
# Every block below exists to trigger a specific rule family.

import hashlib
import os
import pickle
import subprocess
import yaml
import ldap
import requests
import urllib.request
from lxml import etree
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/render")
def render():
    # SSTI001: user-controlled template string
    return render_template_string(request.args.get("tpl"))


@app.route("/run")
def run():
    # CMD003: shell command concatenated from user input
    os.system("ping -c1 " + request.args.get("host"))
    # CMD004: subprocess with shell=True
    user_cmd = request.args.get("cmd")
    subprocess.run(user_cmd, shell=True)
    return "ok"


@app.route("/load")
def load():
    # DESER001: pickle of untrusted bytes
    obj = pickle.loads(request.data)
    # DESER004: yaml.load without a safe Loader
    cfg = yaml.load(request.data)
    return str(obj) + str(cfg)


@app.route("/xml")
def xml():
    # XXE004: lxml parse of untrusted XML
    doc = etree.fromstring(request.data)
    return doc.tag


@app.route("/ldap")
def ldap_lookup():
    conn = ldap.initialize("ldap://directory.internal")
    # LDAP003: filter built with % formatting from user input
    conn.search_s("dc=example", ldap.SCOPE_SUBTREE, "(uid=%s)" % request.args.get("user"))
    return "ok"


@app.route("/fetch")
def fetch():
    # SSRF004: outbound request to a user-supplied URL
    r = requests.get(request.args.get("url"))
    # SSRF005: urlopen straight from request data
    urllib.request.urlopen(request.args.get("target"))
    return r.text


def weak_digest(payload: bytes) -> str:
    # ENC001: weak hash algorithm
    return hashlib.md5(payload).hexdigest()
