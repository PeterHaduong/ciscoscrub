#!/usr/bin/env python3
"""CiscoScrub: sanitize Cisco show-command output for support cases.

Remaps IPv4 / IPv6 / hostname prefixes, replaces credentials and account
names with a placeholder, and writes scrubbed copies plus one CSV report of
what changed. Standard library only (Python 3.6+). Files are streamed in
chunks, so multi-GB show tech files are fine.

Usage:
    python ciscoscrub.py                       GUI
    python ciscoscrub.py INPUT [INPUT ...]     scrub files / folders
        [-p PROFILE] [-o OUTPUT_DIR] [-r REPORT.csv] [--rules FILE]
        [--no-learn] [--detail]

Speed note: Python's regex engine scans fast only when a pattern starts with
a literal. Patterns here therefore start with a literal (or a short
alternation of literals), put boundary lookbehinds after the literal, and
spell case-insensitive words as [Uu][Ss][Ee][Rr]. Boundaries that can't be
written that way are checked in Python on each candidate match.
"""

import argparse
import copy
import csv
import ipaddress
import json
import os
import queue
import re
import shutil
import string
import sys
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
import zipfile

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter import font as tkfont
except ImportError:          # no GUI; the command line still works
    tk = None

VERSION = '0.1.0'
HERE = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(HERE, 'scrub_rules.json')
CHUNK_SIZE = 4 * 1024 * 1024
SUFFIX = '_scrubbed'

DEFAULT_CONFIG = {
    'version': 1,
    'extensions': ['.txt', '.log'],
    'include_subfolders': True,
    'placeholder': '<REMOVED>',
    'learn_accounts': True,
    # 'list' = report possible word.word accounts, 'replace' = remove them, 'off'
    'account_sweep': 'list',
    'sweep_exclude': [
        'com', 'net', 'org', 'edu', 'gov', 'int', 'io', 'us', 'uk', 'local',
        'lan', 'arpa', 'example', 'test', 'invalid', 'localhost', 'conf',
        'cfg', 'bin', 'dat', 'txt', 'log', 'pkg', 'text', 'xml', 'json',
        'tar', 'gz', 'tgz', 'zip', 'img', 'iso', 'py', 'sh', 'tcl', 'cer',
        'crt', 'pem', 'key', 'csv', 'htm', 'html', 'pdf', 'sys', 'exe',
        'old', 'bak', 'tmp', 'www', 'e.g', 'i.e',
    ],
    'common_words': [
        'admin', 'administrator', 'cisco', 'root', 'guest', 'user', 'users',
        'operator', 'monitor', 'console', 'local', 'none', 'unknown',
        'system', 'default', 'test', 'enable', 'network-admin',
        'network-operator', 'vdc-admin', 'aaa', 'tacacs', 'radius', 'all',
        'any',
    ],
    'manual_accounts': [],
    'disabled_builtins': [],
    # {'keyword': 'snmp-server location', 'what': 'word' | 'line', 'on': True}
    'custom_removals': [],
    'report_detail': False,
    'mask_secrets': True,
    'residual_hostnames': True,
    'quick_scan_mb': 300,
    'parallel_files': 0,              # files scrubbed at once; 0 = auto
    # ipv4 / ipv6 / host_prefix / host_role: {'from', 'to', 'on'}
    # text: {'from', 'to', 'word': True, 'case': False, 'on'}
    # regex: {'pattern', 'replace', 'on'}
    'remaps': {'ipv4': [], 'ipv6': [], 'host_prefix': [], 'host_role': [],
               'text': [], 'regex': []},
}

REMAP_KINDS = ('ipv4', 'ipv6', 'host_prefix', 'host_role', 'text', 'regex')


class ScrubError(Exception):
    pass


class Cancelled(Exception):
    pass


# ---------------------------------------------------------------- patterns

def _w(word):
    """Literal word not preceded by a word char or '-'."""
    e = re.escape(word)
    return e + r'(?<![\w-]' + e + ')'


def _ci(text):
    """Case-insensitive literal as per-letter classes (faster than re.I)."""
    return ''.join('[%s%s]' % (c.lower(), c.upper()) if c.isalpha()
                   else re.escape(c) for c in text)


def _ciw(word):
    """Case-insensitive word not preceded by a word char."""
    return _ci(word) + r'(?<!\w' + '.' * len(word) + ')'


_T = r'(?:\d{1,2}[ \t]+)?'                       # encryption type: "7 ", "9 "
_V = r'(?P<v>"[^"\r\n]*"|\S+)'                     # secret value
_A = r'(?P<v>[^\s,;:\'"()\[\]@]+)'                 # account name
_L = r'(?P<v>[^\r\n]*[^\s])'                       # rest of the line

# (id, kind, literal hints or None, pattern(s), at line start[, mode]).
# kind: secret (masked in the report), private, or account (learned).
# mode: None, 'email', 'dn', 'block' or 'notmac' (see Scrubber._removal).
# A rule runs on a chunk only if one of its hints occurs in it. Order matters:
# secrets, then private details, then accounts.
_LVL = r'(?:level[ \t]+\d+[ \t]+)?'               # enable secret level 15 ...

BUILTIN_RULES = [
    ('crypt hash', 'secret', ('$',),
     r'(?P<v>\$(?:\d{1,2}|[A-Za-z0-9]{1,3})\$[./A-Za-z0-9$]{4,})', False),
    ('password', 'secret', ('password',),
     _w('password') + r'[ \t]+' + _LVL + _T + _V, False),
    ('password: X', 'secret', ('assword', 'ASSWORD'),
     _ciw('password') + r'[ \t]*:[ \t]*(?P<v>[^\s"]\S*)', False),
    ('secret', 'secret', ('secret',),
     _w('secret') + r'[ \t]+' + _LVL + _T + _V, False),
    ('passwd', 'secret', ('passwd',),
     _w('passwd') + r'[ \t]+' + _V, False),
    ('ssh key-hash', 'secret', ('key-hash',),
     r'key-hash[ \t]+\S+[ \t]+' + _V, False),
    ('ssh public key', 'secret', ('sshkey',),
     r'sshkey[ \t]+(?:(?:ssh-\S+|ecdsa-\S+)[ \t]+)?' + _V, False),
    ('ezvpn group key', 'secret', ('group',),
     _w('group') + r'[ \t]+\S+[ \t]+key[ \t]+' + _T + _V, False),
    ('key-string', 'secret', ('key-string',),
     _w('key-string') + r'[ \t]+' + _T + _V, False),
    ('authentication text', 'secret', ('authentication text',),
     r'authentication[ \t]+text[ \t]+' + _V, False),
    ('hsrp plain authentication', 'secret', ('standby',),
     r'standby[ \t]+(?:\d+[ \t]+)?authentication[ \t]+(?!md5\b|text\b)' + _V,
     False),
    ('show key chain', 'secret', ('-- text',),
     r'key[ \t]+\d+[ \t]+--[ \t]+text[ \t]+' + _T + _V, False),
    ('server key', 'secret', ('-server key',),
     (r'tacacs-server[ \t]+key[ \t]+' + _T + _V,
      r'radius-server[ \t]+key[ \t]+' + _T + _V), False),
    # " key 7 X" / " key X" under tacacs / radius / aaa-server / isakmp client
    # groups; not "key chain X", " key 1" or "key config-key".
    ('key (server group)', 'secret', ('key',),
     r'key[ \t]+(?:\d[ \t]+(?!--)|(?!(?:chain|config-key|\d+|--)(?:\s|$)))'
     + _V, True),
    ('server host key', 'secret', ('-server host', 'server-private'),
     (r'tacacs-server[ \t]+host[ \t]+\S+[^\r\n]*?[ \t]key[ \t]+' + _T + _V,
      r'radius-server[ \t]+host[ \t]+\S+[^\r\n]*?[ \t]key[ \t]+' + _T + _V,
      r'server-private[ \t]+\S+[^\r\n]*?[ \t]key[ \t]+' + _T + _V), False),
    ('pac key', 'secret', ('pac',),
     _w('pac') + r'[ \t]+key[ \t]+' + _T + _V, False),
    ('snmp community', 'secret', ('snmp-server community',),
     r'snmp-server[ \t]+community[ \t]+' + _T + _V, False),
    ('snmp community (show)', 'secret', ('Community ',),
     r'Community (?:name|Index|SecurityName):[ \t]*' + _V, False),
    ('snmp host', 'secret', ('snmp-server host',),
     (r'snmp-server[ \t]+host[ \t]+\S+[^\r\n]*?[ \t]version[ \t]+'
      r'(?:1|2c|3[ \t]+(?:auth|noauth|priv))[ \t]+' + _V,
      # v1 form: snmp-server host 192.0.2.1 [traps|informs] [vrf X] COMMUNITY
      r'snmp-server[ \t]+host[ \t]+\S+(?:[ \t]+(?:traps|informs))?'
      r'(?:[ \t]+vrf[ \t]+\S+)?[ \t]+'
      r'(?P<v>(?!version\b|vrf\b|traps\b|informs\b)[^\s\d.]\S*)',
      # ASA: snmp-server host inside 192.0.2.1 community X version 2c
      r'snmp-server[ \t]+host[ \t][^\r\n]*?[ \t]community[ \t]+' + _V),
     False),
    ('snmp user auth', 'secret', ('snmp-server user',),
     r'snmp-server[ \t]+user[^\r\n]*?[ \t]auth[ \t]+'
     r'(?:md5|sha-2[ \t]+\d+|sha\S*)[ \t]+' + _V, False),
    ('snmp user priv', 'secret', ('snmp-server user',),
     r'snmp-server[ \t]+user[^\r\n]*?[ \t]priv[ \t]+'
     r'(?:(?:des\S*|3des|aes(?:-?\d+)?)[ \t]+(?:\d+[ \t]+)?)?' + _V, False),
    ('isakmp key', 'secret', ('isakmp',),
     r'crypto[ \t]+isakmp[ \t]+key[ \t]+' + _T + _V, False),
    ('pre-shared-key', 'secret', ('pre-shared-key',),
     r'pre-shared-key[ \t]+(?:address[ \t]+(?:ipv6[ \t]+)?\S+'
     r'(?:[ \t]+\d+\.\d+\.\d+\.\d+)?'
     r'[ \t]+key[ \t]+|hostname[ \t]+\S+[ \t]+key[ \t]+'
     r'|(?:local|remote)[ \t]+)?' + _T + _V, False),
    ('ikev2 pre-share key', 'secret', ('pre-share ',),
     r'pre-share[ \t]+key[ \t]+' + _T + _V, False),
    ('asa keys', 'secret', ('radius-common-pw', 'failover'),
     (r'radius-common-pw[ \t]+' + _V,
      r'failover[ \t]+key[ \t]+' + _T + _V), False),
    ('ospf/isis authentication-key', 'secret', ('authentication-key',),
     (r'ospf[^\r\n]*?authentication-key[ \t]+' + _T + _V,
      r'isis[^\r\n]*?authentication-key[ \t]+' + _T + _V), False),
    ('ntp authentication-key', 'secret', ('ntp',),
     r'ntp[ \t]+authentication-key[ \t]+\d+[ \t]+\S+[ \t]+' + _V, False),
    ('message-digest-key', 'secret', ('message-digest-key',),
     r'message-digest-key[ \t]+\d+[ \t]+md5[ \t]+' + _T + _V, False),
    ('ipsec spi', 'secret', ('spi',),
     r'ipsec[ \t]+spi[ \t]+\d+[ \t]+(?:md5|sha1)[ \t]+' + _T + _V, False),
    ('wpa-psk', 'secret', ('wpa-psk',),
     r'wpa-psk[ \t]+(?:ascii|hex)[ \t]+' + _T + _V, False),
    ('config-key', 'secret', ('config-key',),
     r'config-key[ \t]+password-encrypt[ \t]+' + _V, False),
    ('x-password', 'secret', ('-password ',),
     r'[A-Za-z]-password[ \t]+' + _T + _V, False),
    ('url credentials', 'secret', ('://',),
     r'://(?P<v>[^\s/@]+)@', False),
    ('server-key', 'secret', ('server-key',),
     _w('server-key') + r'[ \t]+' + _T + _V, False),
    ('wlc set-key', 'secret', ('set-key',),
     r'set-key[ \t]+(?:ascii|hex)[ \t]+' + _T + _V, False),
    ('nhrp authentication', 'secret', ('nhrp',),
     r'nhrp[ \t]+authentication[ \t]+' + _V, False),
    ('license idtoken', 'secret', ('idtoken',),
     r'idtoken[ \t]+' + _V, False),
    ('call-home contact', 'private',
     ('contact-email-addr', 'phone-number', 'street-address', 'customer-id',
      'site-id', 'contract-id'),
     r'(?:contact-email-addr|phone-number|street-address|customer-id|site-id'
     r'|contract-id)[ \t]+' + _L, True),
    ('smart account', 'private', (' Account',),
     r'(?:Smart|Virtual)[ \t]+Account(?:[ \t]+Name)?[ \t]*:[ \t]*' + _L,
     False),
    ('snmp location / contact', 'private', ('snmp-server ',),
     r'snmp-server[ \t]+(?:location|contact)[ \t]+' + _L, False),
    ('lldp-med location', 'private', ('-location',),
     r'location[ \t]+(?:civic|geo)-location[ \t]+identifier[^\n]*\n'
     r'(?P<v>(?:[ \t]+[^\n]*\n)+)', True, 'block'),
    ('certificate / ldap names', 'private',
     ('cn=', 'CN=', 'ou=', 'OU=', 'dc=', 'DC='),
     r'(?:[Cc][Nn]|[Oo][Uu]?|[Dd][Cc]|[Ll]|[Ss][Tt]|[Cc]|[Ee][Aa]?'
     r'|[Uu][Ii][Dd])=(?P<v>[^,+\r\n"]*[^,+\s"])', False, 'dn'),
    ('email address', 'private', ('@',),
     r'@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])', False,
     'email'),
    ('username', 'account', ('username',),
     r'username[ \t]+' + _A, True),
    ('username (not at line start)', 'account', ('username',),
     r'(?:mgmtuser|dot1x|automate-tester|\|)[ \t]*username[ \t]+' + _A,
     False),
    ('user-name (guest user)', 'account', ('user-name',),
     r'user-name[ \t]+' + _A, True),
    ('show users / show ssh', 'account', ('vty ', 'tty ', 'con ', 'aux ',
                                          'Session started'),
     tuple(w + r'[ \t]+\d+[ \t]+' + _A + r'[ \t]+(?:idle|\d)'
           for w in ('vty', 'con', 'tty', 'aux'))
     + (r'Session started[ \t]+' + _A,), False),
    ('log: User X has exited', 'account', ('has exited',),
     _w('User') + r'[ \t]+' + _A + r'[ \t]+has[ \t]+exited', False),
    ('log: as X on', 'account', (' as ',),
     _w('as') + r'[ \t]+' + _A + r'[ \t]+on[ \t]+(?:vty|tty|console|con|aux|\d)',
     False),
    ('log: user X failed', 'account', ('failed',),
     _w('user') + r'[ \t]+' + _A + r'[ \t]+failed', False),
    ('radius debug user-name', 'account', ('User-Name',),
     r'User-Name[ \t]+\[1\][ \t]+\d+[ \t]+"(?P<v>[^"\r\n]+)"', False),
    ('ip ftp / http username', 'account', ('username',),
     r'ip[ \t]+(?:ftp|http[ \t]+client)[ \t]+username[ \t]+' + _A, False),
    ('user@line', 'account', ('@vty', '@tty', '@con', '@aux'),
     r'(?P<v>[A-Za-z0-9_.\\-]+)@(?:vty|tty|console|con|aux)\d', False),
    ('802.1x user-name', 'account', ('ser-', 'SER-'),
     r'[Uu][Ss][Ee][Rr]-[Nn][Aa][Mm][Ee][ \t]*[:=][ \t]*'
     r'(?P<v>[^\s,;\'"()\[\]]+)', False, 'notmac'),
    ('snmp user', 'account', ('snmp-server user',),
     r'snmp-server[ \t]+user[ \t]+' + _A, False),
    ('sent-username', 'account', ('sent-username',),
     r'sent-username[ \t]+' + _A, False),
    ('log: by X on', 'account', (' by ',),
     _w('by') + r'[ \t]+' + _A + r'[ \t]+on[ \t]+(?:vty|tty|console|con|aux|\d)',
     False),
    ('log: user: X', 'account', None,
     _ciw('user') + r'(?:[ \t]?' + _ci('name') + r')?[ \t]*[:=][ \t]*' + _A,
     False),
    ("log: user 'X'", 'account', None,
     _ciw('user') + r"[ \t]+'(?P<v>[^'\r\n]+)'", False),
    # sshd / PAM (NX-OS, Linux-based platforms): users that may exist only in
    # TACACS / RADIUS, or not at all ("invalid user").
    ('log: for user X', 'account', ('user ',),
     _w('for') + r'[ \t]+(?:invalid[ \t]+)?user[ \t]+' + _A, False),
    ('log: sshd for X from', 'account', (' for ',),
     (r'(?:Accepted|Failed)[ \t]+\S+[ \t]+for[ \t]+(?!invalid[ \t])' + _A
      + r'[ \t]+from[ \t]',
      r'[Ii]nvalid[ \t]+user[ \t]+' + _A + r'[ \t]+from[ \t]'), False),
]

# Values after "password"/"secret" that are settings, not secrets.
NONSECRET = {
    'encryption', 'strength-check', 'secure-mode', 'restriction', 'policy',
    'history', 'required', 'prompt', 'reuse-interval', 'max-length',
    'min-length', 'lifetime', 'expiry', 'hash', 'encrypt', 'aes',
    'for',                        # "Failed password for invalid user X"
    'keyboard', 'publickey',      # ip ssh server algorithm authentication
    'accept-lifetime', 'send-lifetime', 'cryptographic-algorithm',
    'key-string',                 # key chain lines
    'is', 'not', 'key',           # prose: "the secret is not displayed"
}
# Context matches that are not accounts ("AP User Name : Not Configured").
NONACCOUNT = {'console', 'unknown', 'none', 'system', 'n/a', 'not',
              'disabled', 'enabled', 'yes', 'no', 'true', 'false', 'null',
              'idle', 'configured', 'set', 'any'}

# MAB logins use the MAC as the user name; those are left alone.
_MAC = re.compile(r'^(?:[0-9A-Fa-f]{2}[-:]?){5}[0-9A-Fa-f]{2}$'
                  r'|^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$')
# A line is a certificate / LDAP name only if it has one of these.
_DN_STRONG = re.compile(r'(?<![\w-])(?:[Cc][Nn]|[Oo][Uu]|[Dd][Cc])=')
EMAIL_LOCAL = frozenset(string.ascii_letters + string.digits + '._%+-')

LETTERS = frozenset(string.ascii_letters)
WORDISH = frozenset(string.ascii_letters + string.digits + '_')
HEX = frozenset(string.hexdigits)

# Possible accounts: candidate "x.y", expanded and checked in Python.
_SWEEP_CAND = re.compile(r'[A-Za-z]\.[A-Za-z]')
_SWEEP_FULL = re.compile(r'([A-Za-z]+)\.([A-Za-z]+)(?![\w-]|\.\w|[/:])')
# Hostname-shaped tokens: candidate is the last block ("-AS1").
# Letters then digits ("-AS1"), so "QOS-VOICE-1" / "vlan-group-10" are not
# hostname-shaped; may be followed by _ or - ("TO_A-B-EE-AS1_Gi1/0/1").
_HOST_LAST = re.compile(r'[-_][A-Za-z]+\d+(?![A-Za-z0-9])')


# ------------------------------------------------------------------ helpers

def mask(value):
    if len(value) <= 2:
        return '*' * len(value)
    return '%s***(%d)' % (value[:2], len(value))


def match_case(src, repl):
    if src.isupper():
        return repl.upper()
    if src.islower():
        return repl.lower()
    return repl


def parse_v4_prefix(text):
    """'192.168' -> '192.168', or None if not two valid octets."""
    parts = text.strip().split('.')
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return None
    nums = [int(p) for p in parts]
    if not all(n <= 255 for n in nums):
        return None
    return '%d.%d' % tuple(nums)


def parse_v6_prefix(text):
    """'2001:db8' -> top 32 bits as int, or None."""
    parts = text.strip().split(':')
    if len(parts) != 2 or not all(1 <= len(p) <= 4 and set(p) <= HEX
                                  for p in parts):
        return None
    return (int(parts[0], 16) << 16) | int(parts[1], 16)


def _hextet(value):
    """Pattern for one hextet with optional leading zeros, any case."""
    h = '%x' % value
    return '(?:%s)' % '|'.join(_ci('0' * z + h) for z in range(5 - len(h)))


def _v6_prefix_rx(keys):
    """Pattern matching 'h1:h2' (residual / collision checks)."""
    return '|'.join(_hextet(k >> 16) + ':' + _hextet(k & 0xffff)
                    + '(?![0-9A-Fa-f])' for k in keys)


def validate_remaps(prof):
    """Return a list of problems with the remap rules."""
    errors = []
    for kind, parse in (('ipv4', parse_v4_prefix), ('ipv6', parse_v6_prefix)):
        seen = set()
        for r in prof.get(kind, []):
            f, t = parse(r.get('from', '')), parse(r.get('to', ''))
            if f is None:
                errors.append('%s: bad "from" %r' % (kind, r.get('from')))
            if t is None:
                errors.append('%s: bad "to" %r' % (kind, r.get('to')))
            if f is not None and f in seen:
                errors.append('%s: duplicate "from" %r' % (kind, r['from']))
            seen.add(f)
    for kind in ('host_prefix', 'host_role'):
        seen = set()
        for r in prof.get(kind, []):
            for side in ('from', 'to'):
                if not re.match(r'^[A-Za-z0-9_-]+$', r.get(side, '')):
                    errors.append('%s: bad "%s" %r' % (kind, side, r.get(side)))
            key = r.get('from', '').upper()
            if key in seen:
                errors.append('%s: duplicate "from" %r' % (kind, r['from']))
            seen.add(key)
    seen = set()
    for r in prof.get('text', []):
        f = r.get('from', '')
        if not f:
            errors.append('text: empty "from"')
        key = f if r.get('case', False) else f.lower()
        if f and key in seen:
            errors.append('text: duplicate "from" %r' % f)
        seen.add(key)
    for r in prof.get('regex', []):
        if not r.get('pattern'):
            errors.append('regex: empty pattern')
            continue
        try:
            rx = re.compile(r['pattern'])
            if rx.match(''):
                raise re.error('it can match empty text (e.g. x*), which '
                               'would insert the replacement everywhere')
            rep = r.get('replace', '')
            if '\n' in rep or '\r' in rep or '\\n' in rep or '\\r' in rep:
                raise re.error('the replacement must stay on one line, so '
                               'line numbers keep matching')
            # Check the replacement's \1 / \g<name> references now, not
            # halfway through a run.
            for g in re.findall(r'\\(\d+)|\\g<(\w+)>', r.get('replace', '')):
                ref = g[0] or g[1]
                if ref.isdigit() and int(ref) > rx.groups:
                    raise re.error('invalid group reference %s' % ref)
                if not ref.isdigit() and ref not in rx.groupindex:
                    raise re.error('unknown group name %s' % ref)
        except re.error as e:
            errors.append('regex %r: %s' % (r.get('pattern'), e))
    return errors


def load_config(path=RULES_FILE):
    """Load the rules file, creating it with defaults if missing."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not os.path.exists(path):
        save_config(cfg, path)
        return cfg
    with open(path, encoding='utf-8') as f:
        user = json.load(f)
    cfg.update(user)
    for k in REMAP_KINDS:
        cfg['remaps'].setdefault(k, [])
    return cfg


def save_config(cfg, path=RULES_FILE):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def _v6_start_ok(s, i):
    """Can an IPv6 address start at i? Not inside a word or another address,
    but yes after "outside:" (ASA logs write interface:address)."""
    p = _prev(s, i)
    if p == ':':
        k = i - 1                       # walk back over hex digits / colons
        while k > 0 and (s[k - 1] in HEX or s[k - 1] == ':'):
            k -= 1
        return k > 0 and (s[k - 1].isalpha() or s[k - 1] == '_')
    return not (p in WORDISH or p == '.')


_ANSI_END = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]$')


def _prev(s, i):
    """Character before position i; a newline at the start of the text, and
    a space right after a terminal colour code (ESC[1m in captured prompts),
    whose final letter is not part of the next word."""
    if i <= 0:
        return '\n'
    c = s[i - 1]
    if c.isalpha():
        j = s.rfind('\x1b', max(0, i - 16), i)
        if j >= 0 and _ANSI_END.match(s, j, i):
            return ' '
    return c


def _at_line_start(s, i):
    """True if only spaces/tabs precede position i on its line."""
    return not s[s.rfind('\n', 0, i) + 1:i].strip(' \t')


def _token(s, i, j):
    """Widen s[i:j] to the surrounding whitespace-delimited token."""
    while i > 0 and not s[i - 1].isspace():
        i -= 1
    n = len(s)
    while j < n and not s[j].isspace():
        j += 1
    return s[i:j]


class _OrigMatch(object):
    """A match found in lowercased text, read back from the original."""
    __slots__ = ('m', 'string')

    def __init__(self, m, text):
        self.m, self.string = m, text

    def start(self, g=0):
        return self.m.start(g)

    def end(self, g=0):
        return self.m.end(g)

    def span(self, g=0):
        return self.m.span(g)

    def group(self, g=0):
        a, b = self.m.span(g)
        return None if a < 0 else self.string[a:b]

    @property
    def lastgroup(self):
        return self.m.lastgroup


def line_breaks(text, a=0, b=None):
    """Line breaks in text[a:b]: LF, CRLF or a lone CR (old Mac-style files)."""
    b = len(text) if b is None else b
    n = text.count('\n', a, b)
    cr = text.count('\r', a, b)
    if cr:
        n += cr - text.count('\r\n', a, b)
    return n


class _Lines(object):
    """Line numbers for match positions, counted incrementally."""

    def __init__(self, text, base):
        self.text, self.base = text, base
        self.pos, self.line = 0, base

    def at(self, pos):
        if pos < self.pos:
            self.pos, self.line = 0, self.base
        self.line += line_breaks(self.text, self.pos, pos)
        self.pos = pos
        return self.line


# Characters that can be part of a token we match (address, name, secret).
_TOKEN = frozenset(string.ascii_letters + string.digits + '._:%/@\\-$*+=')


def _chunks(f):
    """Read text in chunks of about CHUNK_SIZE that end on a line boundary
    (LF or CR).

    Memory stays bounded even for a line hundreds of MB long (one-line JSON
    output): a chunk with no line break is cut just after the last character
    that cannot be part of a token (space, comma, quote, ...), so addresses
    and names are never split. Rules that read the rest of a line can still
    miss part of a line that long."""
    carry = ''
    while True:
        data = f.read(CHUNK_SIZE)
        if not data:
            if carry:
                yield carry
            return
        data = carry + data
        cut = max(data.rfind('\n'), data.rfind('\r')) + 1
        if cut == len(data) and data.endswith('\r'):
            cut -= 1                    # keep CR with a possible LF next
        if cut <= 0:
            cut = 0
            for k in range(len(data) - 1, max(-1, len(data) - 65537), -1):
                if data[k] not in _TOKEN:
                    cut = k + 1
                    break
            if not cut:
                cut = len(data)         # 64 KB with no break at all
        carry = data[cut:]
        yield data[:cut]


def _open_in(path):
    # latin-1 maps every byte to one char, so any file round-trips exactly
    # and len(text) == bytes read.
    return open(path, 'r', encoding='latin-1', newline='')


def _open_out(path):
    return open(path, 'w', encoding='latin-1', newline='')


# ------------------------------------------------------------------- report

def _cell(value):
    """Stop Excel reading a report value as a formula (=, +, -, @)."""
    return "'" + value if value[:1] in ('=', '+', '-', '@') else value


class Report(object):
    """One CSV per run: unique values per file, or every occurrence."""

    HEAD = ['File', 'Rule', 'Before', 'After', 'Count', 'First line']
    HEAD_DETAIL = ['File', 'Line', 'Rule', 'Before', 'After']

    def __init__(self, path, detail=False, part=False):
        """part=True: no header or BOM (one file's rows, merged later)."""
        self.detail = detail
        self.f = open(path, 'w', encoding='utf-8' if part else 'utf-8-sig',
                      newline='')
        self.w = csv.writer(self.f)
        if not part:
            self.w.writerow(self.HEAD_DETAIL if detail else self.HEAD)
        self.name = None
        self.hits = {}
        self.totals = {}

    def start_file(self, name):
        self.name, self.hits = name, {}

    def add(self, rule, before, after, line):
        self.totals[rule] = self.totals.get(rule, 0) + 1
        if self.detail:
            self.w.writerow([self.name, line, rule, _cell(before),
                             _cell(after)])
            return
        key = (rule, before, after)
        hit = self.hits.get(key)
        if hit is None:
            self.hits[key] = [1, line]
        else:
            hit[0] += 1

    def end_file(self):
        rows = sorted(self.hits.items(), key=lambda kv: (kv[0][0], kv[1][1]))
        for (rule, before, after), (count, line) in rows:
            self.w.writerow([self.name, rule, _cell(before), _cell(after),
                             count, line])
        self.hits = {}

    def close(self):
        self.f.close()


# ------------------------------------------------------------------- engine

class Scrubber(object):
    """Compiled rules; scrubs text chunk by chunk."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.prof = cfg['remaps']
        errors = validate_remaps(self.prof)
        if errors:
            raise ScrubError('The rules have problems:\n  %s'
                             % '\n  '.join(errors))
        self.ph = cfg['placeholder']
        self.mask = cfg['mask_secrets']
        self.report = None
        self.line = 1
        self.learned_rx = None
        self._compile()

    # -- compile

    def _compile(self):
        cfg, prof = self.cfg, self.prof
        off = set(cfg['disabled_builtins'])
        self.removals = []
        prefix = {'secret': 'Secret: ', 'private': 'Removed: ',
                  'account': 'Account: '}
        for entry in BUILTIN_RULES:
            rid, kind, hints, pats, bol = entry[:5]
            mode = entry[5] if len(entry) > 5 else None
            if rid in off:
                continue
            for pat in (pats if isinstance(pats, tuple) else (pats,)):
                self.removals.append((prefix[kind] + rid, kind, hints,
                                      re.compile(pat), bol, mode))
        for r in cfg['custom_removals']:
            words = r.get('keyword', '').split()
            if not r.get('on', True) or not words:
                continue
            val = r'(?P<v>[^\r\n]*[^\s])' if r.get('what') == 'line' else _V
            # "keyword value", "keyword=value" or "keyword: value"
            pat = (_w(words[0]) + ''.join(r'[ \t]+' + re.escape(w)
                                          for w in words[1:])
                   + r'(?:[ \t]*[:=][ \t]*|[ \t]+)' + _T + val)
            self.removals.append(('Custom: ' + ' '.join(words), 'secret',
                                  (words[0],), re.compile(pat), False, None))
        self.account_rules = [x for x in self.removals if x[1] == 'account']
        self.common = {w.lower() for w in cfg['common_words']}
        self.sweep_ex = {w.lower() for w in cfg['sweep_exclude']}

        on = lambda kind: [r for r in prof[kind] if r.get('on', True)]

        # IPv4: "a.b" -> "c.d"
        self.v4 = {parse_v4_prefix(r['from']): parse_v4_prefix(r['to'])
                   for r in on('ipv4')}
        self.v4_rx = self.res4 = self.col4 = self.hex4 = None
        if self.v4:
            alts = '|'.join(re.escape(p) for p in self.v4)
            self.v4_rx = re.compile('(' + alts + r')\.(\d{1,3})\.(\d{1,3})'
                                    r'(?!\d|\.\d)')
            # Residual: a "from" left in the output. A "from" that is also
            # another rule's "to" (10.20->10.30, 10.30->10.40) is expected in
            # the output, so it is not checked.
            left = [p for p in self.v4 if p not in set(self.v4.values())]
            if left:
                self.res4 = re.compile('(?:' + '|'.join(
                    re.escape(p) for p in left) + r')\.\d')
            # The same prefix in hex (packet dumps, debugs): 192.168 = c0a8,
            # seen as C0A80A01, 0xc0a80a01, "c0a8 0a01" or c0a8:101.
            hx = ['%02x%02x' % tuple(int(o) for o in p.split('.'))
                  for p in self.v4]
            self.hex4 = re.compile('(?:' + '|'.join(hx)          # lowercase
                                   + r')(?: ?[0-9a-f]{4}|:[0-9a-f]{1,4})'
                                   r'(?![0-9a-f])')
            tos = set(self.v4.values()) - set(self.v4)
            if tos:
                self.col4 = re.compile('(?:' + '|'.join(
                    re.escape(p) for p in tos) + r')\.\d{1,3}\.\d{1,3}'
                    r'(?!\d|\.\d)')

        # IPv6: top 32 bits -> top 32 bits
        self.v6 = {parse_v6_prefix(r['from']): parse_v6_prefix(r['to'])
                   for r in on('ipv6')}
        self.v6_rx = self.res6 = self.col6 = self.hex6 = None
        if self.v6:
            firsts = sorted({k >> 16 for k in self.v6})
            # Searched in the lowercased text (see _apply).
            self.v6_rx = re.compile('(?:' + '|'.join(
                '0' * z + '%x' % h for h in firsts
                for z in range(5 - len('%x' % h))) + r')(?=:)[0-9a-f:.]*')
            left = [k for k in self.v6 if k not in set(self.v6.values())]
            if left:
                self.res6 = re.compile(_v6_prefix_rx(left))
            self.hex6 = re.compile('(?:' + '|'.join(
                '%04x ?%04x' % (k >> 16, k & 0xffff) for k in self.v6)
                + r')(?![0-9a-f])')
            tos = set(self.v6.values()) - set(self.v6)
            if tos:
                self.col6 = re.compile(_v6_prefix_rx(tos))

        # Hostnames: prefix blocks, optional last-block role
        self.hp = {r['from'].upper(): r['to'] for r in on('host_prefix')}
        self.hr = {r['from'].upper(): r['to'] for r in on('host_role')}
        self.h_rx = None
        if self.hp:
            alts = '|'.join(re.escape(p.lower()) for p in
                            sorted(self.hp, key=len, reverse=True))
            self.h_rx = re.compile('(?P<pre>' + alts       # lowercased text
                                   + r')(?P<rest>(?:[-_][a-z0-9]+)*)'
                                   r'(?![a-z0-9])')
        self.h_tos = tuple(t.upper() for t in self.hp.values())

        # Text: one alternation so replacements never chain
        self.text = on('text')
        self.text_rx = None
        if self.text:
            alts = []
            order = sorted(range(len(self.text)),
                           key=lambda i: -len(self.text[i]['from']))
            # All ignore-case (the usual case): search the lowercased text
            # with plain literals and no groups (named groups make the scan
            # ~20x slower); the rule is looked up from the matched text.
            # Any match-case rule: one pattern with a named group per rule.
            self.text_low = not any(r.get('case', False) for r in self.text)
            self.text_map = {}
            for i in order:
                r = self.text[i]
                if self.text_low:
                    p = re.escape(r['from'].lower())
                    self.text_map.setdefault(r['from'].lower(), i)
                elif r.get('case', False):
                    p = re.escape(r['from'])
                else:
                    p = _ci(r['from'])
                if r.get('word', True):
                    # Boundaries are in the pattern (the lookbehind goes after
                    # the literal so the scan stays fast), so a rejected spot
                    # never hides a shorter rule's match. Only on a side where
                    # "from" starts / ends with a letter or digit.
                    f = r['from']
                    if f[0].isalnum():
                        p += '(?<![A-Za-z0-9]%s)' % p
                    if f[-1].isalnum():
                        p += r'(?![A-Za-z0-9])'
                alts.append(p if self.text_low else '(?P<t%d>%s)' % (i, p))
            self.text_rx = re.compile('|'.join(alts))

        self.regex = [(re.compile(r['pattern'], re.M), r['replace'],
                       r['pattern']) for r in on('regex')]

    def set_learned(self, names):
        """Names found by learn(), plus the manual list, replaced everywhere.

        A manual entry ending in '.' or '*' is a prefix: 'adm.' (or 'adm.*')
        matches adm.jdoe, adm.j.doe ...; 'adm*' matches anything starting
        with adm.
        """
        # Only distinctive names are replaced everywhere: john.doe, jd_x,
        # CORP\jdoe, ops2. A plain word (backup, ise) would also hit config
        # keywords, so it is removed only where it is clearly an account.
        learned = {n for n in names if n.lower() not in self.common
                   and any(c in n for c in '._\\/@-0123456789')}
        exact, prefixes = set(learned), []
        for n in self.cfg['manual_accounts']:
            n = n.strip()
            if n.endswith(('.', '*')):
                base = n.rstrip('*')
                if len(base.rstrip('.')) >= 2:
                    prefixes.append(base)
            elif n:
                exact.add(n)
        self.exact_accounts = {n.lower() for n in exact}
        alts = [re.escape(n) for n in sorted(self.exact_accounts, key=len,
                                             reverse=True)]
        for p in sorted(prefixes, key=len, reverse=True):
            tail = r'[\w-]+(?:\.[\w-]+)*' if p.endswith('.') else r'[\w.-]*'
            alts.append(re.escape(p.lower()) + tail)
        self.learned_rx = None                 # searched in lowercased text
        if alts:
            self.learned_rx = re.compile(
                '(?:' + '|'.join(alts) + r')(?![\w-]|\.\w)')

    # -- applying

    def _apply(self, rx, fn, text, write=True, low=False):
        """Run rx over text. fn(m) returns None (skip) or
        (start, end, new, rule, before, after). Returns the new text, or
        text unchanged when write is False (checks only).

        low=True: rx is written in lowercase and searched in text.lower(),
        which is much faster than case-insensitive patterns. Lowercasing
        keeps every position (latin-1 text), and fn still sees the original
        text through _OrigMatch."""
        lines = _Lines(text, self.line)
        rep = self.report
        out = []
        last = 0
        if low:
            src = text.lower()
            if len(src) != len(text):   # e.g. 'İ' (only via the Test tab)
                src = ''.join(c.lower() if len(c.lower()) == 1 else c
                              for c in text)
            found = (_OrigMatch(m, text) for m in rx.finditer(src))
        else:
            found = rx.finditer(text)
        for m in found:
            res = fn(m)
            if res is None:
                continue
            start, end, new, rule, before, after = res
            if start < last:
                continue
            if rep is not None:
                rep.add(rule, before, after, lines.at(start))
            if write:
                out.append(text[last:start])
                out.append(new)
                last = end
        if not write or not out:
            return text
        out.append(text[last:])
        return ''.join(out)

    def _removal(self, label, kind, bol, mode=None):
        """fn for one removal rule: replace group 'v' with the placeholder.

        mode 'email': the match is '@domain'; the local part is found by
        walking back. 'dn': only on lines that look like a certificate / LDAP
        name (cn=, ou= or dc=). 'block': v is a block of indented lines; each
        keeps its first word. 'notmac': skip values that are MAC addresses.
        """
        ph, masked = self.ph, self.mask and kind == 'secret'
        if mode == 'email':
            def fn(m):
                s, at = m.string, m.start()
                i = at
                while i > 0 and s[i - 1] in EMAIL_LOCAL:
                    i -= 1
                if i == at:
                    return None
                tok = s[i:m.end()]
                return i, m.end(), ph, label, tok, ph
            return fn

        def fn(m):
            v = m.group('v')
            if v == ph or (kind == 'secret' and v.lower() in NONSECRET):
                return None
            if kind == 'account' and (v.isdigit() or v.lower() in NONACCOUNT
                                      or not any(c.isalnum() for c in v)):
                return None              # "*****" (masked) is not a name
            if bol and not _at_line_start(m.string, m.start()):
                return None
            if mode == 'notmac' and _MAC.match(v):
                return None
            if mode == 'dn':
                s = m.string
                p = _prev(s, m.start())
                if p in WORDISH or p in '.-':
                    return None
                ls = s.rfind('\n', 0, m.start()) + 1
                le = s.find('\n', m.start())
                # cn= / ou= / dc= on the line, or one attribute alone on its
                # line (show crypto pki certificates prints o=, l=, st= so)
                if not (_DN_STRONG.search(s, ls, le if le >= 0 else len(s))
                        or not s[ls:m.start()].strip()):
                    return None
            a, b = m.span('v')
            if mode == 'block':
                new, vals = [], []
                for line in v.splitlines(True):
                    body = line.rstrip('\r\n')
                    parts = body.split(None, 1)
                    if len(parts) == 2 and parts[1] != ph:
                        indent = body[:len(body) - len(body.lstrip())]
                        vals.append(parts[1])
                        line = indent + parts[0] + ' ' + ph + line[len(body):]
                    new.append(line)
                if not vals:
                    return None
                return a, b, ''.join(new), label, ' | '.join(vals), ph
            return a, b, ph, label, mask(v) if masked else v, ph
        return fn

    def _v4(self, m):
        s, a = m.string, m.start()
        p = _prev(s, a)
        if p.isdigit() or p == '.':
            return None
        o3, o4 = m.group(2), m.group(3)
        if int(o3) > 255 or int(o4) > 255:
            return None
        pre = m.group(1)
        new = '%s.%s.%s' % (self.v4[pre], o3, o4)
        return a, m.end(), new, 'IPv4 ' + pre, m.group(0), new

    def _v6(self, m):
        if not _v6_start_ok(m.string, m.start()):
            return None
        core = m.group(0)
        for _ in range(4):
            try:
                addr = ipaddress.IPv6Address(core)
                break
            except ValueError:
                if not core or core[-1] not in '.:':
                    return None
                core = core[:-1]
        else:
            return None
        n = int(addr)
        top = n >> 96
        if top not in self.v6:
            return None
        new_int = (self.v6[top] << 96) | (n & ((1 << 96) - 1))
        if '.' in core:
            # Embedded IPv4 (2001:db8::192.168.1.1): keep it dotted and remap
            # it too; str() would turn it into hex (c0a8:101), still readable.
            tail = self._v4_text(core.rsplit(':', 1)[1])
            head = str(ipaddress.IPv6Address(new_int & ~0xffffffff))
            new = head + tail if head.endswith('::') else head[:-3] + tail
        else:
            new = str(ipaddress.IPv6Address(new_int))
        if core.upper() == core and core.lower() != core:
            new = new.upper()
        rule = 'IPv6 %x:%x' % (top >> 16, top & 0xffff)
        return m.start(), m.start() + len(core), new, rule, core, new

    def _v4_text(self, ip):
        """Remap a dotted IPv4 string if a rule covers it."""
        parts = ip.split('.')
        if (len(parts) == 4 and all(p.isdigit() and int(p) <= 255
                                    for p in parts)):
            pre = '%d.%d' % (int(parts[0]), int(parts[1]))
            if pre in self.v4:
                return '%s.%s.%s' % (self.v4[pre], parts[2], parts[3])
        return ip

    def _host(self, m):
        # A letter or digit before means the prefix is inside another word;
        # '_', '-' and '.' are separators ("TO_A-B-EE-AS1_Gi1/0/1").
        if _prev(m.string, m.start()).isalnum():
            return None
        pre, rest = m.group('pre'), m.group('rest')
        new = match_case(pre, self.hp[pre.upper()])
        if rest and self.hr:
            # The role is the first later block that has a role rule, so
            # "A-B-EE-AS1_Gi1" still gets AS1 remapped.
            parts = re.split('([-_])', rest)
            for k in range(2, len(parts), 2):
                role = self.hr.get(parts[k].upper())
                if role is not None:
                    parts[k] = match_case(parts[k], role)
                    break
            rest = ''.join(parts)
        new += rest
        if new == m.group(0):
            return None
        return (m.start(), m.end(), new, 'Hostname ' + pre.upper(),
                m.group(0), new)

    def _text(self, m):
        src = m.group(0)
        if self.text_low:
            r = self.text[self.text_map[src.lower()]]
        else:
            r = self.text[int(m.lastgroup[1:])]
        new = r['to'] if r.get('case', False) else match_case(src, r['to'])
        return m.start(), m.end(), new, 'Text ' + r['from'], src, new

    def _learned(self, m):
        p = _prev(m.string, m.start())
        if p in WORDISH or p in '.@-':
            return None
        tok = m.group(0)
        rule = ('Account (learned)' if tok.lower() in self.exact_accounts
                else 'Account (prefix)')
        return m.start(), m.end(), self.ph, rule, tok, self.ph

    def _sweep(self, m):
        s = m.string
        i = m.start()
        while i > 0 and s[i - 1] in LETTERS:
            i -= 1
        p = _prev(s, i)
        if p in WORDISH or p in '.@/:\\-':
            return None
        fm = _SWEEP_FULL.match(s, i)
        if fm is None or fm.end(1) != m.start() + 1:
            return None
        tok = fm.group(0)
        ex = self.sweep_ex
        if (tok.lower() in ex or fm.group(1).lower() in ex
                or fm.group(2).lower() in ex):
            return None
        if self.cfg['account_sweep'] == 'replace':
            return i, fm.end(), self.ph, 'Account (pattern)', tok, self.ph
        return (i, fm.end(), tok, 'Possible account (not replaced)', tok,
                '(listed only)')

    def _regex(self, rx, repl, pat):
        def fn(m):
            new = m.expand(repl)
            return m.start(), m.end(), new, 'Regex ' + pat, m.group(0), new
        return fn

    # -- checks (report only)

    def _check(self, rule, after, kind='v4'):
        """Report-only check. kind sets what may come before a match:
        v4 (not a digit; '.' allowed, so OIDs are flagged), col4 (not a
        digit or '.'), v6 (a valid IPv6 start) or hex (not a hex digit)."""
        def fn(m):
            s, a = m.string, m.start()
            p = _prev(s, a)
            if kind == 'v6':
                if not _v6_start_ok(s, a):
                    return None
            elif kind == 'hex':
                if p in HEX:
                    return None
            elif p.isdigit() or (kind == 'col4' and p == '.'):
                return None
            tok = _token(s, a, m.end())
            return a, m.end(), tok, rule, tok, after
        return fn

    def _host_residual(self, m):
        s = m.string
        i, blocks = m.start(), 1
        while True:                       # s[i] is a separator
            j = i
            while j > 0 and s[j - 1] in LETTERS:
                j -= 1
            if j == i:
                return None
            blocks += 1
            if j > 0 and s[j - 1] in '-_':
                i = j - 1
                continue
            break
        p = _prev(s, j)
        if blocks < 3 or p in WORDISH or p in '.-':
            return None
        tok = s[j:m.end()]
        up = tok.upper()
        for t in self.h_tos:              # a remapped name, maybe after TO_
            k = up.find(t)
            while k >= 0:
                if ((k == 0 or up[k - 1] in '-_.')
                        and up[k + len(t):k + len(t) + 1] in ('-', '_', '')):
                    return None
                k = up.find(t, k + 1)
        return j, m.end(), tok, 'Residual hostname', tok, '(left as is)'

    def scrub_text(self, text):
        """Scrub one chunk (whole lines). self.line = its first line number."""
        ap = self._apply
        # Collisions are checked on the original text.
        if self.col4 is not None:
            ap(self.col4, self._check('Warning: collision IPv4',
                                      '(already in input)', 'col4'),
               text, False)
        if self.col6 is not None:
            ap(self.col6, self._check('Warning: collision IPv6',
                                      '(already in input)', 'v6'), text, False)

        for label, kind, hints, rx, bol, mode in self.removals:
            if hints is None or any(h in text for h in hints):
                text = ap(rx, self._removal(label, kind, bol, mode), text)
        if self.learned_rx is not None:
            text = ap(self.learned_rx, self._learned, text, low=True)
        if self.h_rx is not None:
            text = ap(self.h_rx, self._host, text, low=True)
        if self.v6_rx is not None:
            text = ap(self.v6_rx, self._v6, text, low=True)
        if self.v4_rx is not None:
            text = ap(self.v4_rx, self._v4, text)
        if self.text_rx is not None:
            text = ap(self.text_rx, self._text, text, low=self.text_low)
        for rx, repl, pat in self.regex:
            text = ap(rx, self._regex(rx, repl, pat), text)
        if self.cfg['account_sweep'] in ('list', 'replace'):
            text = ap(_SWEEP_CAND, self._sweep, text,
                      self.cfg['account_sweep'] == 'replace')

        # Residual checks on the scrubbed text.
        if self.res4 is not None:
            ap(self.res4, self._check('Residual IPv4', '(left as is)'),
               text, False)
        if self.res6 is not None:
            ap(self.res6, self._check('Residual IPv6', '(left as is)', 'v6'),
               text, False)
        for rx, rule in ((self.hex4, 'Residual IPv4 (hex)'),
                         (self.hex6, 'Residual IPv6 (hex)')):
            if rx is not None:
                ap(rx, self._check(rule, '(hex; check by hand)', 'hex'),
                   text, False, low=True)
        if self.cfg['residual_hostnames']:
            ap(_HOST_LAST, self._host_residual, text, False)
        return text

    # -- files

    def learn_text(self, text):
        """Account names found in account contexts in text."""
        found = set()
        for label, kind, hints, rx, bol, mode in self.account_rules:
            if hints is not None and not any(h in text for h in hints):
                continue
            fn = self._removal(label, kind, bol, mode)
            for m in rx.finditer(text):
                if fn(m) is not None:
                    found.add(m.group('v'))
        return found

    def learn(self, path, progress=None, cancel=None):
        """First pass: collect account names from account contexts."""
        found = set()
        done = 0
        with _open_in(path) as f:
            for chunk in _chunks(f):
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                found |= self.learn_text(chunk)
                done += len(chunk)
                if progress:
                    progress(done)
        return found

    def scrub_file(self, src, dst, report, progress=None, cancel=None):
        self.report = report
        self.line = 1
        done = 0
        ok = False
        out = _open_out(dst)
        try:
            with _open_in(src) as f:
                for chunk in _chunks(f):
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    out.write(self.scrub_text(chunk))
                    self.line += line_breaks(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done)
            ok = True
        finally:
            out.close()
            self.report = None
            if not ok:
                try:
                    os.remove(dst)
                except OSError:
                    pass


# ---------------------------------------------------------------------- run

def collect_files(inputs, exts, recurse=True):
    """[(src, relative output dir)] for every matching file in inputs."""
    exts = tuple(e.lower() for e in exts)
    found = []

    def want(name):
        stem, ext = os.path.splitext(name)
        return ext.lower() in exts and not stem.endswith(SUFFIX)

    for item in inputs:
        item = os.path.abspath(item)
        if os.path.isfile(item):
            if want(item):
                found.append((item, ''))
        elif os.path.isdir(item):
            for root, dirs, files in os.walk(item):
                dirs.sort()
                if not recurse:
                    dirs[:] = []
                for name in sorted(files):
                    if want(name):
                        found.append((os.path.join(root, name),
                                      os.path.relpath(root, item)))
        else:
            raise ScrubError('Not found: %s' % item)
    return found


def default_paths(inputs):
    """Default output folder and report path for a list of inputs."""
    first = os.path.abspath(inputs[0]).rstrip('\\/')
    base = first if os.path.isdir(first) else os.path.dirname(first)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    out_dir = base + SUFFIX
    report = os.path.join(os.path.dirname(base), '%s_scrub_report_%s.csv'
                          % (os.path.basename(base), stamp))
    return out_dir, report


def _inside(path, folder):
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip('\\/') + os.sep)


def _keep_awake(on):
    """Stop Windows sleeping while this thread runs a job (no-op elsewhere)."""
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(
            0x80000000 | (0x00000001 if on else 0))   # ES_CONTINUOUS | SYSTEM
    except Exception:
        pass


def _no_quick_edit():
    """Turn off console QuickEdit: a click in the window would otherwise
    freeze the run at its next print until a key is pressed."""
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)                       # STD_INPUT_HANDLE
        mode = ctypes.c_uint()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, (mode.value & ~0x40) | 0x80)
    except Exception:
        pass


def run(inputs, cfg, out_dir=None, report_path=None,
        log=print, progress=None, cancel=None):
    """Scrub inputs (files and/or folders). Returns the report totals.

    progress(phase, done_bytes, total_bytes, label) is called often.
    """
    _keep_awake(True)
    try:
        return _run(inputs, cfg, out_dir, report_path, log, progress, cancel)
    finally:
        _keep_awake(False)


def _run(inputs, cfg, out_dir, report_path, log, progress, cancel):
    files = collect_files(inputs, cfg['extensions'], cfg['include_subfolders'])
    if not files:
        raise ScrubError('No %s files found.' % ' / '.join(cfg['extensions']))
    d_out, d_rep = default_paths(inputs)
    out_dir = os.path.abspath(out_dir or d_out)
    report_path = os.path.abspath(report_path or d_rep)
    for item in inputs:
        if os.path.isdir(item) and _inside(out_dir, os.path.abspath(item)):
            raise ScrubError('The output folder is inside input folder %s.'
                             % item)
    if _inside(report_path, out_dir):
        raise ScrubError('The report must not be inside the output folder '
                         '(it holds the original values).')

    eng = Scrubber(cfg)                    # validates the rules up front
    sizes = [os.path.getsize(p) for p, _ in files]
    total = sum(sizes)
    progress = progress or (lambda *a: None)
    workers = worker_count(cfg, files)
    if workers > 1:
        log('Processing %d files, %d at a time.' % (len(files), workers))

    names = set()
    if cfg['learn_accounts']:
        jobs = [(cfg, src) for src, _ in files]
        for found in _run_jobs(_learn_job, jobs, sizes, workers,
                               'Learning accounts', progress, cancel):
            names |= found
        common = {n for n in names if n.lower() in eng.common}
        log('Learned %d account name(s); %d skipped as common words.'
            % (len(names - common), len(common)))

    # Each file's report rows go to a part file next to the report (they hold
    # original values, so not the system temp folder), merged in order.
    parts_dir = report_path + '.parts'
    os.makedirs(parts_dir, exist_ok=True)
    used = set()
    jobs, parts, shown_names = [], [], []
    for i, (src, rel) in enumerate(files):
        stem, ext = os.path.splitext(os.path.basename(src))
        dst = os.path.normpath(os.path.join(out_dir, rel, stem + SUFFIX + ext))
        n = 2
        while os.path.normcase(dst) in used:
            dst = os.path.normpath(os.path.join(
                out_dir, rel, '%s%s_%d%s' % (stem, SUFFIX, n, ext)))
            n += 1
        used.add(os.path.normcase(dst))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shown = os.path.join(rel, os.path.basename(src)) if rel not in (
            '', '.') else os.path.basename(src)
        part = os.path.join(parts_dir, '%04d.csv' % i)
        jobs.append((cfg, sorted(names), src, dst, part, shown))
        parts.append(part)
        shown_names.append(shown)

    def done(i, result):
        secs = max(result[1], 0.001)
        log('Scrubbed %s in %.1f s (%.1f MB/s)'
            % (shown_names[i], secs, sizes[i] / secs / 1e6))

    totals = {}
    try:
        for file_totals, _ in _run_jobs(_scrub_job, jobs, sizes, workers,
                                        'Scrubbing', progress, cancel, done):
            for rule, n in file_totals.items():
                totals[rule] = totals.get(rule, 0) + n
    finally:
        with open(report_path, 'w', encoding='utf-8-sig', newline='') as out:
            csv.writer(out).writerow(Report.HEAD_DETAIL
                                     if cfg['report_detail'] else Report.HEAD)
            for part in parts:
                if os.path.exists(part):
                    with open(part, encoding='utf-8', newline='') as f:
                        shutil.copyfileobj(f, out)
                    os.remove(part)
        try:
            os.rmdir(parts_dir)
        except OSError:
            pass
    log('Output: %s' % out_dir)
    log('Report: %s' % report_path)
    return totals


MAX_PARALLEL = 3          # hosts are shared, so never more than this at once


def worker_count(cfg, files):
    """How many files to process at once ('parallel_files': 0 = auto)."""
    n = cfg.get('parallel_files', 0) or max(1, (os.cpu_count() or 2) - 1)
    n = max(1, min(n, MAX_PARALLEL, len(files)))
    return n if n == 1 or _can_spawn() else 1


def _can_spawn():
    """Worker processes re-import the main script, which is impossible when
    it was read from stdin or typed interactively (they would crash)."""
    path = getattr(sys.modules.get('__main__'), '__file__', None)
    return bool(path) and os.path.isfile(path)


def _lower_priority():
    """Run a worker process below normal priority (shared hosts)."""
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetPriorityClass(k.GetCurrentProcess(), 0x4000)  # BELOW_NORMAL
    except Exception:
        try:
            os.nice(5)
        except (AttributeError, OSError):
            pass


def _in_worker():
    import multiprocessing
    return multiprocessing.current_process().name != 'MainProcess'


def _learn_job(cfg, src, progress, cancel):
    if _in_worker():
        _lower_priority()
    return Scrubber(cfg).learn(src, progress, cancel)


def _scrub_job(cfg, names, src, dst, part, shown, progress, cancel):
    """Scrub one file; its report rows go to part. Returns (totals, secs)."""
    if _in_worker():
        _lower_priority()
    eng = Scrubber(cfg)
    eng.set_learned(names)
    rep = Report(part, cfg['report_detail'], part=True)
    rep.start_file(shown)
    t0 = time.time()
    try:
        eng.scrub_file(src, dst, rep, progress, cancel)
        rep.end_file()
    finally:
        rep.close()
    return rep.totals, time.time() - t0


class _QueueProgress(object):
    """Picklable progress callback for a worker process."""

    def __init__(self, q, i):
        self.q, self.i = q, i

    def __call__(self, done):
        self.q.put((self.i, done))


def _run_jobs(fn, jobs, sizes, workers, phase, progress, cancel,
              on_done=None):
    """Run fn(*job, progress, cancel) for each job and return the results in
    job order. With workers > 1, jobs run in separate processes (one file
    each); the regex scanning is CPU-bound, so threads would not help."""
    total = sum(sizes)
    done = [0] * len(jobs)
    if cancel is not None and cancel.is_set():
        raise Cancelled()

    def report():
        progress(phase, sum(done), total,
                 '%d of %d files' % (sum(1 for i, d in enumerate(done)
                                         if d >= sizes[i]), len(jobs)))

    if workers <= 1:
        results = []
        for i, job in enumerate(jobs):
            def cb(d, i=i):
                done[i] = d
                report()
            res = fn(*(job + (cb, cancel)))
            done[i] = sizes[i]
            if on_done:
                on_done(i, res)
            results.append(res)
        return results

    import concurrent.futures as cf
    import multiprocessing
    mgr = multiprocessing.Manager()
    try:
        q, stop = mgr.Queue(), mgr.Event()
        if cancel is not None and cancel.is_set():   # pressed while starting
            raise Cancelled()
        results = [None] * len(jobs)
        with cf.ProcessPoolExecutor(workers) as pool:
            futs = {pool.submit(fn, *(job + (_QueueProgress(q, i), stop))): i
                    for i, job in enumerate(jobs)}
            pending = set(futs)
            try:
                while pending:
                    fin, pending = cf.wait(pending, timeout=0.25)
                    while not q.empty():
                        i, d = q.get_nowait()
                        done[i] = max(done[i], d)
                    if cancel is not None and cancel.is_set():
                        stop.set()
                    for f in fin:
                        i = futs[f]
                        try:
                            results[i] = f.result()   # re-raises worker errors
                        except cf.process.BrokenProcessPool:
                            raise ScrubError(
                                'A worker process stopped unexpectedly. Set '
                                '"Files at once" to 1 (Removals tab) and run '
                                'again.')
                        done[i] = sizes[i]
                        if on_done:
                            on_done(i, results[i])
                    report()
            except BaseException:
                stop.set()                        # stop the other files too
                for f in pending:
                    f.cancel()
                raise
        return results
    finally:
        mgr.shutdown()


# --------------------------------------------------------------------- scan

_IP4_ANY = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)')
_IP6_CAND = re.compile(r'[0-9A-Fa-f]{1,4}:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*')
_DOMAIN = re.compile(r'domain[ -](?:name|list)[ \t]+'
                     r'([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')
_FQDN_ID = re.compile(r'(?:Device ID|System Name):[ \t]*[A-Za-z0-9_-]+\.'
                      r'([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')
# Free text to review: interface / VLAN / other descriptions and indented
# "name X" lines (VLAN names and the like).
_DESC = re.compile(r'(description|name)[ \t]+([^\r\n]*\S)')
_KEYWORDS = re.compile(r'password|secret|key|community|psk|credential')
# Keyword lines that are settings, not secrets (not suggested).
_KW_SAFE = re.compile(
    r'(?:no )?(?:service password-|password encryption|key chain |'
    r'key \d+$|security passwords|crypto key |key config-key|'
    r'crypto ikev2 keyring |.*password-policy|.*key-string <)')
_HOST_ANY = re.compile(r'[A-Za-z]+(?:[-_][A-Za-z]+)+[-_][A-Za-z]*\d+(?![\w-])')


class _Collect(object):
    """Report stand-in that counts hits instead of writing a CSV."""

    def __init__(self, keep_rows=False):
        self.counts = {}            # (rule, before) -> [count, after]
        self.rows = [] if keep_rows else None

    def add(self, rule, before, after, line):
        hit = self.counts.get((rule, before))
        if hit is None:
            self.counts[(rule, before)] = [1, after]
        else:
            hit[0] += 1
        if self.rows is not None:
            self.rows.append((line, rule, before, after))


def host_prefix_of(token):
    """First min(3, blocks-1) blocks of a hostname: A-B-EE_X-AS1 -> A-B-EE."""
    parts = re.split('([-_])', token)
    blocks = (len(parts) + 1) // 2
    k = min(3, blocks - 1)
    return ''.join(parts[:2 * k - 1])


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def read_xlsx_text(path):
    """All cell values of every sheet in an .xlsx, one per line."""
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ScrubError('%s is not an .xlsx file (old .xls files must be '
                         'saved as .xlsx or CSV first).'
                         % os.path.basename(path))
    with z:
        shared = []
        if 'xl/sharedStrings.xml' in z.namelist():
            for si in ET.fromstring(z.read('xl/sharedStrings.xml')):
                shared.append(''.join(t.text or '' for t in si.iter()
                                      if _local(t.tag) == 't'))
        values = []
        for name in sorted(z.namelist()):
            if not re.match(r'xl/worksheets/sheet\d+\.xml$', name):
                continue
            for c in ET.fromstring(z.read(name)).iter():
                if _local(c.tag) != 'c':
                    continue
                kind = c.get('t')
                if kind == 'inlineStr':
                    values.append(''.join(t.text or '' for t in c.iter()
                                          if _local(t.tag) == 't'))
                    continue
                v = next((x.text for x in c if _local(x.tag) == 'v'), None)
                if v is None:
                    continue
                if kind == 's':
                    try:
                        v = shared[int(v)]
                    except (ValueError, IndexError):
                        continue
                values.append(v)
    return '\n'.join(values)


def hostnames_in(text):
    """Hostname-shaped tokens (3+ blocks, digits only at the end)."""
    out = []
    for m in _HOST_ANY.finditer(text):
        p = _prev(text, m.start())
        if p not in WORDISH and p not in '.-':
            out.append(m.group(0))
    return out


def scan(files, cfg, progress=None, cancel=None, limit=None):
    """Read inputs and collect what could be scrubbed, for suggestions.

    Returns a dict of findings; 'cancelled' is True if stopped early (the
    findings so far are still returned). limit = max bytes read per file.
    """
    eng = Scrubber(cfg)
    eng.set_learned(())
    col = _Collect()
    eng.report = col
    v4, v6, domains, descs, keywords = {}, {}, {}, {}, {}
    total = sum(min(os.path.getsize(p), limit or 1 << 62) for p, _ in files)
    done = 0
    cancelled = truncated = False

    def bump(d, key, example):
        hit = d.get(key)
        if hit is None:
            d[key] = [1, example]
        else:
            hit[0] += 1

    try:
        for src, _ in files:
            eng.line = 1
            read = 0
            with _open_in(src) as f:
                for chunk in _chunks(f):
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    for m in _IP4_ANY.finditer(chunk):
                        p = _prev(chunk, m.start())
                        if p.isdigit() or p == '.':
                            continue
                        o = [int(x) for x in m.groups()]
                        if (max(o) > 255 or o[0] in (0, 127) or o[0] >= 224
                                or o[:2] == [169, 254]):    # link-local
                            continue
                        bump(v4, '%d.%d' % (o[0], o[1]), m.group(0))
                    for m in _IP6_CAND.finditer(chunk):
                        p = _prev(chunk, m.start())
                        if p in WORDISH or p in ':.':
                            continue
                        core = m.group(0).rstrip('.:')
                        try:
                            n = int(ipaddress.IPv6Address(core))
                        except ValueError:
                            continue
                        # global unicast 2000::/3 or unique local fc00::/7
                        if (n >> 125) == 1 or (n >> 121) == 0x7e:
                            bump(v6, n >> 96, core)
                    for rx in (_DOMAIN, _FQDN_ID):
                        for m in rx.finditer(chunk):
                            bump(domains, m.group(1).lower(), m.group(0))
                    text = eng.scrub_text(chunk)
                    # Descriptions as they will be sent (after scrubbing).
                    for m in _DESC.finditer(text):
                        ls = text.rfind('\n', 0, m.start()) + 1
                        lead = text[ls:m.start()]
                        if lead.strip(' \t') or (m.group(1) == 'name'
                                                 and not lead):
                            continue
                        val = m.group(2)
                        if val != eng.ph:
                            bump(descs, val[:150], m.group(1))
                    low = text.lower()
                    last = -1
                    for m in _KEYWORDS.finditer(low):
                        ls = low.rfind('\n', 0, m.start()) + 1
                        if ls == last:
                            continue
                        last = ls
                        le = low.find('\n', m.start())
                        line = text[ls:le if le >= 0 else len(text)].strip()
                        if eng.ph not in line and not _KW_SAFE.match(line):
                            bump(keywords, line[:150], m.group(0))

                    eng.line += line_breaks(chunk)
                    read += len(chunk)
                    done += len(chunk)
                    if progress:
                        progress('Scanning', min(done, total), total,
                                 os.path.basename(src))
                    if limit and read >= limit:
                        truncated = True
                        break
    except Cancelled:
        cancelled = True

    found = {'ipv4': v4, 'ipv6': v6, 'domains': domains,
             'descs': dict(sorted(descs.items(),
                                  key=lambda kv: -kv[1][0])[:500]),
             'hosts': {}, 'host_mapped': {}, 'accounts': {},
             'possible_accounts': {}, 'secrets': {}, 'cancelled': cancelled,
             'truncated': truncated}
    for (rule, before), (count, after) in col.counts.items():
        if rule == 'Residual hostname':
            bump(found['hosts'], host_prefix_of(before).upper(), before)
            found['hosts'][host_prefix_of(before).upper()][0] += count - 1
        elif rule.startswith('Hostname '):
            found['host_mapped'][before] = [count, after]
        elif rule.startswith('Account: '):
            found['accounts'][before] = [count, rule]
        elif rule.startswith('Possible account'):
            found['possible_accounts'][before] = [count, before]
        elif rule.startswith(('Secret: ', 'Removed: ')):
            s = found['secrets'].setdefault(rule, [0, ''])
            s[0] += count
    # Names already seen in account contexts are learned on a real run.
    known = {a.lower() for a in found['accounts']}
    for tok in list(found['possible_accounts']):
        if tok.lower() in known:
            del found['possible_accounts'][tok]
    # Keyword lines: most frequent first, capped.
    found['keywords'] = dict(sorted(keywords.items(),
                                    key=lambda kv: -kv[1][0])[:300])
    return found


def _v4_pool():
    """Prefixes to suggest: private space first, then any other a.b."""
    for i in range(100, 256):
        yield '10.%d' % i
    for i in range(16, 32):
        yield '172.%d' % i
    for i in range(1, 100):
        yield '10.%d' % i
    for a in range(11, 224):
        if a not in (127, 172, 192):
            for b in range(256):
                yield '%d.%d' % (a, b)


def suggest_v4(n, avoid):
    """Up to n unused 'a.b' prefixes (not in avoid) to map to."""
    out = []
    for p in _v4_pool():
        if len(out) == n:
            break
        if p not in avoid:
            out.append(p)
    return out


def keyword_phrase(line, kw):
    """The words of line up to and including the one holding kw, cut where
    the value starts: 'wifi psk=X' -> 'wifi psk'."""
    low = line.lower()
    i = low.find(kw)
    if i < 0:
        return ' '.join(line.split()[:1])
    j = i + len(kw)
    while j < len(line) and (line[j].isalnum() or line[j] in '-_'):
        j += 1
    return ' '.join(line[:j].split())


def suggest_v6(n, avoid):
    """n unused ULA 'fd00:x' prefixes (avoid holds top-32-bit ints)."""
    out = []
    i = 1
    while len(out) < n:
        key = (0xfd00 << 16) | i
        if key not in avoid:
            out.append('fd00:%x' % i)
        i += 1
    return out


def suggest_host(prefix, n):
    """Generic replacement with the same block layout: A-B-EE -> HA-X-X."""
    parts = re.split('([-_])', prefix)
    tag = ''
    i = n
    while True:
        tag = chr(65 + i % 26) + tag
        i = i // 26 - 1
        if i < 0:
            break
    parts[0] = 'H' + tag
    for k in range(2, len(parts), 2):
        parts[k] = 'X'
    return ''.join(parts)


def suggest_domain(n):
    return 'example.com' if n == 0 else 'example%d.com' % (n + 1)


def empty_found():
    return {'ipv4': {}, 'ipv6': {}, 'domains': {}, 'descs': {}, 'hosts': {},
            'host_mapped': {}, 'accounts': {}, 'possible_accounts': {},
            'secrets': {}, 'keywords': {}, 'cancelled': False,
            'truncated': False}


# ---------------------------------------------------------------------- GUI

KIND_LABELS = [('ipv4', 'IPv4 prefix'), ('ipv6', 'IPv6 prefix'),
               ('host_prefix', 'Hostname prefix'),
               ('host_role', 'Hostname role'), ('text', 'Replace text'),
               ('regex', 'Advanced regex')]
KIND_NAME = dict(KIND_LABELS)
KIND_OF = {v: k for k, v in KIND_LABELS}
KIND_HINT = {
    'ipv4': 'First two octets, e.g. 192.168 -> 172.16',
    'ipv6': 'First two hextets, e.g. 2001:db8 -> fd00:1',
    'host_prefix': 'Leading blocks, e.g. A-B-EE -> X-Y-ZZ '
                   '(the rest of the name is kept)',
    'host_role': 'Last block of a remapped hostname, e.g. AS1 -> SW1',
    'text': 'Literal text, e.g. a domain or site name',
    'regex': 'Python regex -> replacement (\\1 for groups); one line only',
}
BUILTIN_IDS = []
for _r in BUILTIN_RULES:
    if _r[0] not in BUILTIN_IDS:
        BUILTIN_IDS.append(_r[0])
BUILTIN_KIND = {r[0]: r[1] for r in BUILTIN_RULES}

# (group, short title for the From column, explanation for the wide Example
# column; the table cannot wrap text).
SCAN_GROUPS = [
    ('ipv4', 'IPv4 prefixes', 'First two octets.'),
    ('ipv6', 'IPv6 prefixes', 'First two hextets.'),
    ('host', 'Hostname prefixes',
     'Double-click From to shorten a prefix to 2 blocks.'),
    ('domain', 'Domain names', ''),
    ('account', 'Possible accounts',
     'word.word names not seen as an account. Checked ones are removed.'),
    ('keyword', 'Uncovered key / password lines',
     'To = the keyword to remove the value after.'),
    ('desc', 'Descriptions and names',
     'As sent. To change one word, edit From to that word.'),
    ('info', 'Already handled', 'For information.'),
]
NEEDS_TO = ('ipv4', 'ipv6', 'host', 'domain', 'keyword', 'desc')
CHECK, UNCHECK = '\u2611', '\u2610'


def _words(text):
    return [w for w in re.split(r'[\s,]+', text) if w]


# Windows 11-style light palette.
UI = {
    'bg': '#f3f3f3', 'field': '#ffffff', 'border': '#e0e0e0',
    'border2': '#c9c9c9', 'text': '#1b1b1b', 'muted': '#616161',
    'disabled': '#a0a0a0', 'accent': '#005fb8', 'accent_hover': '#196ebf',
    'accent_press': '#004c94', 'hover': '#f6f6f6', 'press': '#ececec',
    'select': '#d6e8f8', 'thumb': '#c2c2c2', 'thumb_hover': '#9e9e9e',
    'hit': '#fff1c2',
}


def _apply_theme(root):
    """Restyle ttk ('clam' base) to look like a Windows 11 app.

    Returns the fonts used. Standard library only: no theme packages.
    """
    c = UI
    fam = set(tkfont.families(root))
    pick = lambda *names: next((n for n in names if n in fam), 'TkDefaultFont')
    body = pick('Segoe UI Variable Text', 'Segoe UI')
    semi = pick('Segoe UI Variable Text Semibold', 'Segoe UI Semibold', body)
    disp = pick('Segoe UI Variable Display Semib', 'Segoe UI Semibold', body)
    fonts = {'body': (body, 10), 'semi': (semi, 10), 'title': (disp, 17),
             'mono': (pick('Cascadia Mono', 'Consolas', 'Courier New'), 10)}
    for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont',
                 'TkHeadingFont', 'TkCaptionFont'):
        tkfont.nametofont(name).configure(family=body, size=10)
    line = tkfont.nametofont('TkDefaultFont').metrics('linespace')
    pad = max(4, int(line * 0.3))

    root.configure(background=c['bg'])
    for cls, extra in (('Listbox', {'font': fonts['body']}),
                       ('Text', {'font': fonts['mono'], 'padX': 8,
                                 'padY': 6, 'insertBackground': c['text']})):
        opts = {'background': c['field'], 'foreground': c['text'],
                'relief': 'flat', 'borderWidth': 0,
                'highlightThickness': 1, 'highlightBackground': c['border2'],
                'highlightColor': c['accent'], 'selectBackground': c['select'],
                'selectForeground': c['text'], 'activeStyle': 'none'}
        opts.update(extra)
        for k, v in opts.items():
            root.option_add('*%s.%s' % (cls, k), v)
    root.option_add('*Toplevel.background', c['bg'])
    root.option_add('*TCombobox*Listbox.font', fonts['body'])

    s = ttk.Style(root)
    s.theme_use('clam')
    s.configure('.', background=c['bg'], foreground=c['text'],
                font=fonts['body'], bordercolor=c['border2'],
                lightcolor=c['bg'], darkcolor=c['bg'], troughcolor=c['bg'],
                focuscolor=c['bg'], selectbackground=c['select'],
                selectforeground=c['text'], fieldbackground=c['field'],
                insertcolor=c['text'], arrowcolor=c['muted'])
    s.configure('Hint.TLabel', foreground=c['muted'])
    s.configure('Title.TLabel', font=fonts['title'])
    s.configure('Section.TLabel', font=fonts['semi'])
    s.configure('Status.TLabel', foreground=c['muted'])
    s.configure('Box.TFrame', background=c['border2'])

    # Buttons: white with a hairline border; accent buttons solid blue.
    s.configure('TButton', background=c['field'], lightcolor=c['field'],
                darkcolor=c['field'], bordercolor=c['border2'],
                padding=(int(line * 0.9), pad), anchor='center')
    flat = lambda states: {k: states for k in ('background', 'lightcolor',
                                                'darkcolor')}
    s.map('TButton', foreground=[('disabled', c['disabled'])],
          **flat([('disabled', c['bg']), ('pressed', c['press']),
                  ('active', c['hover'])]))
    s.configure('Accent.TButton', foreground='#ffffff',
                background=c['accent'], lightcolor=c['accent'],
                darkcolor=c['accent'], bordercolor=c['accent'],
                font=fonts['semi'])
    s.map('Accent.TButton',
          foreground=[('disabled', '#ffffff')],
          bordercolor=[('disabled', '#c5c5c5')],
          **flat([('disabled', '#c5c5c5'), ('pressed', c['accent_press']),
                  ('active', c['accent_hover'])]))

    # Entry / combobox: white fields, blue border when focused.
    for w in ('TEntry', 'TCombobox'):
        s.configure(w, padding=(6, pad - 1), lightcolor=c['field'],
                    darkcolor=c['field'], background=c['field'])
        s.map(w, bordercolor=[('focus', c['accent'])],
              lightcolor=[('focus', c['field'])])
    s.map('TCombobox', fieldbackground=[('readonly', c['field'])],
          selectbackground=[('readonly', c['field'])],
          selectforeground=[('readonly', c['text'])],
          background=[('active', c['hover'])])

    s.configure('TCombobox', arrowsize=max(12, int(line * 0.75)))
    # Check and radio buttons: blue when on.
    for w in ('TCheckbutton', 'TRadiobutton'):
        s.configure(w, indicatorsize=max(13, int(line * 0.7)),
                    indicatormargin=(0, 0, int(line * 0.35), 0),
                    indicatorbackground=c['field'],
                    indicatorforeground=c['field'],
                    upperbordercolor=c['border2'],
                    lowerbordercolor=c['border2'], padding=(2, 2))
        s.map(w, background=[('active', c['bg'])],
              indicatorbackground=[('selected', c['accent']),
                                   ('pressed', c['press'])],
              upperbordercolor=[('selected', c['accent'])],
              lowerbordercolor=[('selected', c['accent'])])

    # Tabs: flat; the selected one is white with bold text.
    s.configure('TNotebook', borderwidth=0, tabmargins=(0, 0, 0, 0),
                bordercolor=c['border'])
    s.configure('TNotebook.Tab', background=c['bg'], lightcolor=c['bg'],
                bordercolor=c['bg'], foreground=c['muted'],
                padding=(int(line * 1.1), pad))
    s.map('TNotebook.Tab',
          background=[('selected', c['field']), ('active', c['hover'])],
          lightcolor=[('selected', c['accent'])],
          bordercolor=[('selected', c['border'])],
          foreground=[('selected', c['text'])],
          font=[('selected', fonts['semi'])])
    s.configure('Card.TFrame', background=c['field'])
    s.configure('Card.TLabel', background=c['field'])
    s.configure('CardHint.TLabel', background=c['field'],
                foreground=c['muted'])
    s.configure('Card.TCheckbutton', background=c['field'])
    s.map('Card.TCheckbutton', background=[('active', c['field'])])

    # Tables.
    s.configure('Treeview', background=c['field'], fieldbackground=c['field'],
                bordercolor=c['field'], lightcolor=c['field'],
                darkcolor=c['field'], rowheight=int(line * 1.7),
                borderwidth=0)
    s.map('Treeview', background=[('selected', c['select'])],
          foreground=[('selected', c['text'])])
    s.configure('Treeview.Heading', background=c['field'],
                foreground=c['muted'], font=fonts['semi'], relief='flat',
                bordercolor=c['field'], lightcolor=c['field'],
                darkcolor=c['field'], padding=(6, pad))
    s.map('Treeview.Heading', background=[('active', c['hover'])])
    s.layout('Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])

    # Slim scrollbars without arrows.
    for o in ('Vertical', 'Horizontal'):
        s.layout('%s.TScrollbar' % o, [('%s.Scrollbar.trough' % o, {
            'sticky': 'ns' if o == 'Vertical' else 'we', 'children': [
                ('%s.Scrollbar.thumb' % o,
                 {'expand': '1', 'sticky': 'nswe'})]})])
        s.configure('%s.TScrollbar' % o, troughcolor=c['field'],
                    background=c['thumb'], bordercolor=c['field'],
                    lightcolor=c['thumb'], darkcolor=c['thumb'],
                    arrowsize=max(8, int(line * 0.45)), gripcount=0)
        s.map('%s.TScrollbar' % o,
              background=[('active', c['thumb_hover'])],
              lightcolor=[('active', c['thumb_hover'])],
              darkcolor=[('active', c['thumb_hover'])])

    s.configure('Horizontal.TProgressbar', background=c['accent'],
                troughcolor=c['border'], bordercolor=c['border'],
                lightcolor=c['accent'], darkcolor=c['accent'],
                thickness=max(4, int(line * 0.3)))
    s.configure('TLabelframe', bordercolor=c['border'], relief='solid',
                borderwidth=1)
    s.configure('TLabelframe.Label', font=fonts['semi'])
    s.configure('Sash', sashthickness=max(6, int(line * 0.4)),
                gripcount=0, background=c['bg'])

    try:                              # title bar the same colour (Windows 11)
        import ctypes
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        rgb = int(c['bg'][1:], 16)
        bgr = ctypes.c_int(((rgb & 0xff) << 16) | (rgb & 0xff00)
                           | (rgb >> 16))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 35, ctypes.byref(bgr), ctypes.sizeof(bgr))
    except Exception:
        pass
    return fonts


class App(object):
    """tkinter front end. Rules are saved to the rules file on each change."""

    def __init__(self, root, rules_path):
        self.root = root
        self.rules_path = rules_path
        try:
            self.cfg = load_config(rules_path)
        except (OSError, ValueError) as e:
            messagebox.showerror('CiscoScrub', 'Could not read %s:\n%s\n\n'
                                 'Starting with defaults.' % (rules_path, e))
            self.cfg = copy.deepcopy(DEFAULT_CONFIG)
        self.q = queue.Queue()
        self.cancel = None
        self.worker = None
        self.found = None
        self.scan_rows = {}
        self.scan_edits = {}            # (cat, found value) -> user's edits
        self.prog = None
        self.t_start = 0
        self.last_out = None
        self._test_job = None
        root.title('CiscoScrub %s' % VERSION)
        scale = root.winfo_fpixels('1i') / 96.0      # Windows display scaling
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry('%dx%d' % (min(1150 * scale, sw * 0.92),
                                 min(780 * scale, sh * 0.85)))
        root.minsize(int(min(900 * scale, sw * 0.8)),
                     int(min(600 * scale, sh * 0.7)))
        root.protocol('WM_DELETE_WINDOW', self._close)
        self.scale = scale
        self.fonts = _apply_theme(root)
        self.mono = self.fonts['mono']
        self._build()
        self._load_removals()
        self._refresh_rules()
        self.root.after(150, self._poll)

    # ------------------------------------------------------------ layout

    def _tree(self, parent, cols, height=5, show='headings'):
        """Treeview + slim scrollbar inside a 1-px border."""
        f = ttk.Frame(parent, style='Box.TFrame', padding=1)
        inner = ttk.Frame(f, style='Card.TFrame')
        inner.pack(fill='both', expand=True)
        t = ttk.Treeview(inner, columns=[c[0] for c in cols], show=show,
                         height=height)
        for cid, head, width in cols:
            t.heading(cid, text=head, anchor='w')
            t.column(cid, width=int(width * self.scale), stretch=width >= 150,
                     anchor='w')
        sb = ttk.Scrollbar(inner, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side='left', fill='both', expand=True)
        sb.pack(side='left', fill='y', padx=(0, 2), pady=2)
        return f, t

    def _build(self):
        r = self.root
        px = 16
        head = ttk.Frame(r)
        head.pack(fill='x', padx=px, pady=(12, 6))
        ttk.Label(head, text='CiscoScrub', style='Title.TLabel').pack(
            side='left')
        ttk.Label(head, style='Hint.TLabel', text=(
            '   Sanitize Cisco show output for support cases')).pack(
            side='left', pady=(6, 0))
        ttk.Label(head, text='v' + VERSION, style='Hint.TLabel').pack(
            side='right', pady=(6, 0))

        top = ttk.Frame(r)
        top.pack(fill='x', padx=px, pady=(0, 6))
        cap = ttk.Frame(top)
        cap.grid(row=0, column=0, sticky='w')
        ttk.Label(cap, text='Inputs', style='Section.TLabel').pack(side='left')
        ttk.Label(cap, text='  .txt / .log files or folders',
                  style='Hint.TLabel').pack(side='left')
        self.inputs = tk.Listbox(top, height=3, selectmode='extended')
        self.inputs.grid(row=1, column=0, sticky='nsew', pady=(4, 0))
        bf = ttk.Frame(top)
        bf.grid(row=1, column=1, sticky='n', padx=(8, 0), pady=(4, 0))
        for i, (text, cmd) in enumerate((
                ('Add files...', self._add_files),
                ('Add folder...', self._add_folder),
                ('Remove', self._remove_inputs),
                ('Clear', lambda: self.inputs.delete(0, 'end')))):
            ttk.Button(bf, text=text, command=cmd, width=12).grid(
                row=i // 2, column=i % 2, sticky='ew', padx=(0, 4), pady=(0, 4))
        self.v_sub = tk.BooleanVar(value=self.cfg['include_subfolders'])
        ttk.Checkbutton(bf, text='Include subfolders',
                        variable=self.v_sub).grid(row=2, column=0,
                                                  columnspan=2, sticky='w')
        top.columnconfigure(0, weight=1)

        paths = ttk.Frame(r)
        paths.pack(fill='x', padx=px, pady=(0, 4))
        self.v_out, self.v_rep = tk.StringVar(), tk.StringVar()
        for row, (label, var, cmd, hint) in enumerate((
                ('Output folder', self.v_out, self._pick_out,
                 'blank = <input>_scrubbed'),
                ('Report file', self.v_rep, self._pick_rep,
                 'blank = next to the output folder'))):
            ttk.Label(paths, text=label).grid(row=row, column=0, sticky='w',
                                              padx=(0, 10))
            ttk.Entry(paths, textvariable=var).grid(row=row, column=1,
                                                    sticky='ew', pady=2)
            ttk.Button(paths, text='Browse...', command=cmd).grid(
                row=row, column=2, padx=(8, 8))
            ttk.Label(paths, text=hint, style='Hint.TLabel').grid(
                row=row, column=3, sticky='w')
        paths.columnconfigure(1, weight=1)

        # Status and buttons are packed before the notebook so they keep
        # their space when the window is small.
        self.v_status = tk.StringVar(value='Ready. Add inputs, then Scan '
                                           'to get rule suggestions.')
        ttk.Label(r, textvariable=self.v_status, anchor='w',
                  style='Status.TLabel').pack(side='bottom', fill='x',
                                              padx=px, pady=(4, 10))
        bottom = ttk.Frame(r)
        bottom.pack(side='bottom', fill='x', padx=px, pady=(6, 0))
        self.b_scrub = ttk.Button(bottom, text='Scrub', width=12,
                                  style='Accent.TButton', command=self._scrub)
        self.b_scrub.pack(side='left')
        self.b_cancel = ttk.Button(bottom, text='Cancel', state='disabled',
                                   command=self._cancel)
        self.b_cancel.pack(side='left', padx=8)
        self.b_open = ttk.Button(bottom, text='Open output folder',
                                 state='disabled', command=self._open_out)
        self.b_open.pack(side='right')
        self.pb = ttk.Progressbar(bottom, maximum=1000)
        self.pb.pack(side='left', fill='x', expand=True, padx=8)

        self.nb = ttk.Notebook(r)
        self.nb.pack(fill='both', expand=True, padx=px, pady=(8, 0))
        self._build_scan()
        self._build_rules()
        self._build_removals()
        self._build_test()
        self._build_log()

    def _build_scan(self):
        tab = ttk.Frame(self.nb, padding=(0, 12, 0, 0))
        self.nb.add(tab, text='Scan')
        bar = ttk.Frame(tab)
        bar.pack(fill='x', pady=(0, 4))
        self.b_scan = ttk.Button(bar, text='Scan inputs', command=self._scan,
                                 style='Accent.TButton')
        self.b_scan.pack(side='left')
        ttk.Button(bar, text='Import node list...',
                   command=self._import_nodes).pack(side='left', padx=(4, 0))
        ttk.Button(bar, text='Paste node list...',
                   command=self._paste_nodes).pack(side='left', padx=4)
        self.v_quick = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, variable=self.v_quick,
                        text='Quick (first %d MB of each file)'
                        % self.cfg['quick_scan_mb']).pack(side='left', padx=8)
        ttk.Button(bar, text='Add checked to rules', style='Accent.TButton',
                   command=self._add_checked).pack(side='right')
        ttk.Button(bar, text='Suggest "To" values',
                   command=self._suggest).pack(side='right', padx=4)
        ttk.Label(tab, style='Hint.TLabel', text=(
            'Click a box to check a row. Double-click From (hostnames) or To '
            'to edit. Secrets and known accounts are already handled by the '
            'Removals tab.')).pack(anchor='w', pady=(0, 4))
        f, self.st = self._tree(tab, (
            ('use', '', 34), ('from', 'Found / From', 330), ('to', 'To', 180),
            ('count', 'Count', 80), ('example', 'Example', 420)),
            show='tree headings')
        self.st.column('#0', width=22, stretch=False)
        f.pack(fill='both', expand=True)
        self.st.bind('<Button-1>', self._scan_click)
        self.st.bind('<Double-1>', self._scan_edit)

    def _build_rules(self):
        tab = ttk.Frame(self.nb, padding=(0, 12, 0, 0))
        self.nb.add(tab, text='Remap rules')
        bar = ttk.Frame(tab)
        bar.pack(fill='x', pady=(0, 4))
        for text, cmd in (('Add...', self._rule_add),
                          ('Edit...', self._rule_edit),
                          ('Delete', self._rule_delete),
                          ('Enable / disable', self._rule_toggle)):
            ttk.Button(bar, text=text, command=cmd).pack(side='left',
                                                         padx=(0, 4))
        ttk.Label(bar, style='Hint.TLabel', text=(
            'Remaps. Saved to %s on every change.'
            % os.path.basename(self.rules_path))).pack(side='left', padx=8)
        f, self.rt = self._tree(tab, (
            ('on', 'On', 40), ('type', 'Type', 130), ('from', 'From', 300),
            ('to', 'To', 300), ('opts', 'Options', 150)))
        f.pack(fill='both', expand=True)
        self.rt.bind('<Double-1>', lambda e: self._rule_edit())

    def _build_removals(self):
        tab = ttk.Frame(self.nb, padding=(0, 12, 0, 0))
        self.nb.add(tab, text='Removals')
        left = ttk.LabelFrame(tab, text='Built-in rules (click On to toggle)')
        left.pack(side='left', fill='both', expand=True, padx=(0, 4))
        f, self.bt = self._tree(left, (('on', 'On', 40),
                                       ('rule', 'Rule', 230),
                                       ('kind', 'Removes', 80)))
        f.pack(fill='both', expand=True, padx=4, pady=4)
        self.bt.bind('<Button-1>', self._builtin_click)

        mid = ttk.LabelFrame(tab, text='Custom keywords')
        mid.pack(side='left', fill='both', expand=True, padx=4)
        f, self.ct = self._tree(mid, (('on', 'On', 40),
                                      ('kw', 'Keyword', 200),
                                      ('what', 'Removes', 100)))
        f.pack(fill='both', expand=True, padx=4, pady=4)
        self.ct.bind('<Button-1>', self._custom_click)
        cb = ttk.Frame(mid)
        cb.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Button(cb, text='Add...', command=self._custom_add).pack(
            side='left')
        ttk.Button(cb, text='Delete', command=self._custom_delete).pack(
            side='left', padx=4)

        right = ttk.LabelFrame(tab, text='Accounts and options')
        right.pack(side='left', fill='both', expand=True, padx=(4, 0))
        inner = ttk.Frame(right, padding=4)
        inner.pack(fill='both', expand=True)
        row = ttk.Frame(inner)
        row.pack(fill='x')
        ttk.Label(row, text='Manual account list (one per line):').pack(
            side='left')
        ttk.Button(row, text='Save', style='Accent.TButton',
                   command=self._save_removals).pack(side='right')
        ttk.Label(inner, style='Hint.TLabel',
                  wraplength=int(340 * self.scale), text=(
                      'john.doe = exact.   adm.  or  adm.*  = every '
                      'adm.<name>.   adm* = anything starting adm.')).pack(
            anchor='w', pady=(2, 2))
        # Text boxes expand and shrink together so everything fits.
        self.t_manual = tk.Text(inner, height=2, width=36, font=self.mono)
        self.t_manual.pack(fill='both', expand=True)
        self.v_learn, self.v_mask = tk.BooleanVar(), tk.BooleanVar()
        self.v_detail, self.v_reshost = tk.BooleanVar(), tk.BooleanVar()
        for text, var in (
                ('Learn account names first (extra pass)', self.v_learn),
                ('Mask secrets in the report', self.v_mask),
                ('Report every occurrence (not unique values)', self.v_detail),
                ('Flag leftover hostname-shaped names', self.v_reshost)):
            ttk.Checkbutton(inner, text=text, variable=var).pack(anchor='w')
        self.v_sweep, self.v_ph, self.v_ext = (tk.StringVar(), tk.StringVar(),
                                               tk.StringVar())
        self.v_par = tk.StringVar()
        grid = ttk.Frame(inner)
        grid.pack(fill='x', pady=4)
        ttk.Label(grid, text='Other word.word tokens').grid(row=0, column=0,
                                                            sticky='w')
        sw = ttk.Frame(grid)
        sw.grid(row=0, column=1, sticky='w')
        ttk.Combobox(sw, textvariable=self.v_sweep, width=8,
                     values=('list', 'replace', 'off'),
                     state='readonly').pack(side='left')
        ttk.Label(sw, text='   Files at once ').pack(side='left')
        ttk.Combobox(sw, textvariable=self.v_par, width=5,
                     values=('auto', '1', '2', '3'),
                     state='readonly').pack(side='left')
        ttk.Label(grid, text='Placeholder').grid(row=1, column=0, sticky='w',
                                                 pady=(4, 0))
        ph = ttk.Frame(grid)
        ph.grid(row=1, column=1, sticky='w', pady=(4, 0))
        ttk.Entry(ph, textvariable=self.v_ph, width=12).pack(side='left')
        ttk.Label(ph, text='   File types ').pack(side='left')
        ttk.Entry(ph, textvariable=self.v_ext, width=9).pack(side='left')
        ttk.Label(inner, text='Never learned as accounts:').pack(
            anchor='w', pady=(4, 0))
        self.t_common = tk.Text(inner, height=2, width=36, font=self.mono,
                                wrap='word')
        self.t_common.pack(fill='both', expand=True)
        ttk.Label(inner, text='Not possible accounts (endings, extensions):'
                  ).pack(anchor='w', pady=(4, 0))
        self.t_sweepex = tk.Text(inner, height=2, width=36, font=self.mono,
                                 wrap='word')
        self.t_sweepex.pack(fill='both', expand=True)

    def _build_test(self):
        tab = ttk.Frame(self.nb, padding=(0, 12, 0, 0))
        self.nb.add(tab, text='Test')
        bar = ttk.Frame(tab)
        bar.pack(fill='x', pady=(0, 4))
        ttk.Button(bar, text='Test', command=self._test).pack(side='left')
        ttk.Label(bar, style='Hint.TLabel', text=(
            'Paste sample lines on the left; the result updates as you type. '
            'Uses the current rules.')).pack(side='left', padx=8)
        # The hits list is packed first so the text panes can't squeeze it.
        f, self.ht = self._tree(tab, (('line', 'Line', 50),
                                      ('rule', 'Rule', 230),
                                      ('before', 'Before', 280),
                                      ('after', 'After', 280)), height=6)
        f.pack(side='bottom', fill='x', pady=(8, 0))
        pw = ttk.PanedWindow(tab, orient='horizontal')
        pw.pack(fill='both', expand=True)
        self.t_in = tk.Text(pw, font=self.mono, wrap='none', undo=True)
        self.t_out = tk.Text(pw, font=self.mono, wrap='none',
                             state='disabled')
        self.t_out.tag_configure('hit', background=UI['hit'])
        pw.add(self.t_in, weight=1)
        pw.add(self.t_out, weight=1)
        self.t_in.bind('<KeyRelease>', self._test_soon)
        self.t_in.bind('<<Paste>>', self._test_soon)

    def _build_log(self):
        tab = ttk.Frame(self.nb, padding=(0, 12, 0, 0))
        self.nb.add(tab, text='Log')
        self.t_log = tk.Text(tab, font=self.mono, state='disabled', wrap='none')
        sb = ttk.Scrollbar(tab, command=self.t_log.yview)
        self.t_log.config(yscrollcommand=sb.set)
        self.t_log.pack(side='left', fill='both', expand=True)
        sb.pack(side='left', fill='y')

    # ------------------------------------------------------------ config

    def _pull(self):
        """Copy widget values into self.cfg."""
        c = self.cfg
        c['include_subfolders'] = self.v_sub.get()
        c['manual_accounts'] = [l.strip() for l in
                                self.t_manual.get('1.0', 'end').splitlines()
                                if l.strip()]
        c['learn_accounts'] = self.v_learn.get()
        c['mask_secrets'] = self.v_mask.get()
        c['report_detail'] = self.v_detail.get()
        c['residual_hostnames'] = self.v_reshost.get()
        c['account_sweep'] = self.v_sweep.get() or 'list'
        c['placeholder'] = self.v_ph.get().strip() or '<REMOVED>'
        par = self.v_par.get()
        c['parallel_files'] = int(par) if par.isdigit() else 0
        exts = ['.' + e.lstrip('*.').lower() for e in _words(self.v_ext.get())
                if e.lstrip('*.')]
        c['extensions'] = exts or ['.txt', '.log']
        c['common_words'] = _words(self.t_common.get('1.0', 'end'))
        c['sweep_exclude'] = _words(self.t_sweepex.get('1.0', 'end'))

    def _save(self):
        try:
            save_config(self.cfg, self.rules_path)
            return True
        except OSError as e:
            messagebox.showerror('CiscoScrub', 'Could not save rules:\n%s' % e)
            return False

    def _load_removals(self):
        c = self.cfg
        self.bt.delete(*self.bt.get_children())
        off = set(c['disabled_builtins'])
        for rid in BUILTIN_IDS:
            self.bt.insert('', 'end', iid='b:' + rid, values=(
                UNCHECK if rid in off else CHECK, rid, BUILTIN_KIND[rid]))
        self.ct.delete(*self.ct.get_children())
        for i, r in enumerate(c['custom_removals']):
            self.ct.insert('', 'end', iid='c:%d' % i, values=(
                CHECK if r.get('on', True) else UNCHECK, r['keyword'],
                'rest of line' if r.get('what') == 'line' else 'next word'))
        for widget, items, sep in ((self.t_manual, c['manual_accounts'], '\n'),
                                   (self.t_common, c['common_words'], ' '),
                                   (self.t_sweepex, c['sweep_exclude'], ' ')):
            widget.delete('1.0', 'end')
            widget.insert('1.0', sep.join(items))
        self.v_learn.set(c['learn_accounts'])
        self.v_mask.set(c['mask_secrets'])
        self.v_detail.set(c['report_detail'])
        self.v_reshost.set(c['residual_hostnames'])
        self.v_sweep.set(c['account_sweep'])
        self.v_ph.set(c['placeholder'])
        self.v_par.set(str(c['parallel_files']) if c['parallel_files']
                       else 'auto')
        self.v_ext.set(' '.join(c['extensions']))

    def _save_removals(self):
        self._pull()
        if self._save():
            self._load_removals()
            self.v_status.set('Removal settings saved.')

    def _builtin_click(self, event):
        iid = self.bt.identify_row(event.y)
        if not iid or self.bt.identify_column(event.x) != '#1':
            return
        rid = iid[2:]
        off = self.cfg['disabled_builtins']
        if rid in off:
            off.remove(rid)
        else:
            off.append(rid)
        self._pull()
        self._save()
        self._load_removals()

    def _custom_click(self, event):
        iid = self.ct.identify_row(event.y)
        if not iid or self.ct.identify_column(event.x) != '#1':
            return
        r = self.cfg['custom_removals'][int(iid[2:])]
        r['on'] = not r.get('on', True)
        self._pull()
        self._save()
        self._load_removals()

    def _custom_add(self):
        d = tk.Toplevel(self.root)
        d.title('Custom keyword')
        d.transient(self.root)
        d.resizable(False, False)
        v_kw, v_what = tk.StringVar(), tk.StringVar(value='word')
        frm = ttk.Frame(d, padding=10)
        frm.pack()
        ttk.Label(frm, text='Keyword (one or more words):').grid(
            row=0, column=0, columnspan=2, sticky='w')
        e = ttk.Entry(frm, textvariable=v_kw, width=40)
        e.grid(row=1, column=0, columnspan=2, sticky='ew')
        ttk.Radiobutton(frm, text='Remove the next word', value='word',
                        variable=v_what).grid(row=2, column=0, sticky='w')
        ttk.Radiobutton(frm, text='Remove the rest of the line', value='line',
                        variable=v_what).grid(row=2, column=1, sticky='w')
        ttk.Label(frm, style='Hint.TLabel', text=(
            'A single-digit encryption type after the keyword is kept '
            '(key 7 <REMOVED>).')).grid(row=3, column=0, columnspan=2,
                                        sticky='w', pady=4)

        def ok():
            kw = ' '.join(v_kw.get().split())
            if kw:
                self._pull()
                self.cfg['custom_removals'].append(
                    {'keyword': kw, 'what': v_what.get(), 'on': True})
                self._save()
                self._load_removals()
            d.destroy()
        bf = ttk.Frame(frm)
        bf.grid(row=4, column=0, columnspan=2, sticky='e')
        ttk.Button(bf, text='OK', command=ok).pack(side='left', padx=4)
        ttk.Button(bf, text='Cancel', command=d.destroy).pack(side='left')
        d.bind('<Return>', lambda e: ok())
        d.bind('<Escape>', lambda e: d.destroy())
        e.focus_set()
        d.grab_set()
        d.wait_window()

    def _custom_delete(self):
        idx = sorted((int(i[2:]) for i in self.ct.selection()), reverse=True)
        if not idx:
            return
        self._pull()
        for i in idx:
            del self.cfg['custom_removals'][i]
        self._save()
        self._load_removals()

    # ------------------------------------------------------------ rules

    def _refresh_rules(self):
        self.rt.delete(*self.rt.get_children())
        for kind, label in KIND_LABELS:
            for i, r in enumerate(self.cfg['remaps'][kind]):
                if kind == 'regex':
                    src, dst, opts = r.get('pattern', ''), r.get('replace',
                                                                 ''), ''
                else:
                    src, dst = r.get('from', ''), r.get('to', '')
                    opts = ''
                    if kind == 'text':
                        opts = ', '.join(
                            o for o, on in (('whole word', r.get('word', True)),
                                            ('match case', r.get('case', False)))
                            if on)
                self.rt.insert('', 'end', iid='%s:%d' % (kind, i), values=(
                    CHECK if r.get('on', True) else UNCHECK, label, src, dst,
                    opts))

    def _rule_dialog(self, kind='ipv4', rule=None):
        """Edit one rule; returns (kind, rule) or None."""
        rule = rule or {}
        d = tk.Toplevel(self.root)
        d.title('Rule')
        d.transient(self.root)
        d.resizable(False, False)
        v_kind = tk.StringVar(value=KIND_NAME[kind])
        v_from = tk.StringVar(value=rule.get('from', rule.get('pattern', '')))
        v_to = tk.StringVar(value=rule.get('to', rule.get('replace', '')))
        v_word = tk.BooleanVar(value=rule.get('word', True))
        v_case = tk.BooleanVar(value=rule.get('case', False))
        v_on = tk.BooleanVar(value=rule.get('on', True))
        v_hint = tk.StringVar()
        frm = ttk.Frame(d, padding=10)
        frm.pack()
        ttk.Label(frm, text='Type').grid(row=0, column=0, sticky='w')
        ttk.Combobox(frm, textvariable=v_kind, state='readonly', width=20,
                     values=[l for _, l in KIND_LABELS]).grid(
            row=0, column=1, sticky='w', pady=2)
        ttk.Label(frm, text='From').grid(row=1, column=0, sticky='w')
        e_from = ttk.Entry(frm, textvariable=v_from, width=48)
        e_from.grid(row=1, column=1, sticky='ew', pady=2)
        ttk.Label(frm, text='To').grid(row=2, column=0, sticky='w')
        ttk.Entry(frm, textvariable=v_to, width=48).grid(
            row=2, column=1, sticky='ew', pady=2)
        opts = ttk.Frame(frm)
        opts.grid(row=3, column=1, sticky='w')
        c_word = ttk.Checkbutton(opts, text='Whole word', variable=v_word)
        c_case = ttk.Checkbutton(opts, text='Match case', variable=v_case)
        ttk.Checkbutton(opts, text='Enabled', variable=v_on).pack(side='right')
        ttk.Label(frm, textvariable=v_hint, style='Hint.TLabel').grid(
            row=4, column=0, columnspan=2, sticky='w', pady=4)

        def on_kind(*_):
            k = KIND_OF[v_kind.get()]
            v_hint.set(KIND_HINT[k])
            for c in (c_word, c_case):
                if k == 'text':
                    c.pack(side='left', padx=(0, 8))
                else:
                    c.pack_forget()
        v_kind.trace_add('write', on_kind)
        on_kind()
        result = {}

        def ok():
            k = KIND_OF[v_kind.get()]
            if k == 'regex':
                r = {'pattern': v_from.get(), 'replace': v_to.get(),
                     'on': v_on.get()}
            else:
                r = {'from': v_from.get().strip(), 'to': v_to.get().strip(),
                     'on': v_on.get()}
            if k == 'text':
                r.update(word=v_word.get(), case=v_case.get())
            errors = validate_remaps({k: [r]})
            if errors:
                messagebox.showerror('Rule', '\n'.join(errors), parent=d)
                return
            result['v'] = (k, r)
            d.destroy()
        bf = ttk.Frame(frm)
        bf.grid(row=5, column=0, columnspan=2, sticky='e')
        ttk.Button(bf, text='OK', command=ok).pack(side='left', padx=4)
        ttk.Button(bf, text='Cancel', command=d.destroy).pack(side='left')
        d.bind('<Return>', lambda e: ok())
        d.bind('<Escape>', lambda e: d.destroy())
        e_from.focus_set()
        d.grab_set()
        d.wait_window()
        return result.get('v')

    def _commit_remaps(self, remaps):
        """Validate and save a new remaps dict; False if rejected."""
        errors = validate_remaps(remaps)
        if errors:
            messagebox.showerror('Remap rules', '\n'.join(errors))
            return False
        self._pull()
        self.cfg['remaps'] = remaps
        self._save()
        self._refresh_rules()
        if self.found is not None:
            self._render_scan()
        return True

    def _selected_rule(self):
        sel = self.rt.selection()
        if not sel:
            return None, None
        kind, i = sel[0].split(':')
        return kind, int(i)

    def _rule_add(self):
        res = self._rule_dialog()
        if res:
            remaps = copy.deepcopy(self.cfg['remaps'])
            remaps[res[0]].append(res[1])
            self._commit_remaps(remaps)

    def _rule_edit(self):
        kind, i = self._selected_rule()
        if kind is None:
            return
        res = self._rule_dialog(kind, self.cfg['remaps'][kind][i])
        if res:
            remaps = copy.deepcopy(self.cfg['remaps'])
            del remaps[kind][i]
            if res[0] == kind:
                remaps[kind].insert(i, res[1])
            else:
                remaps[res[0]].append(res[1])
            self._commit_remaps(remaps)

    def _rule_delete(self):
        sel = sorted(((s.split(':')[0], int(s.split(':')[1]))
                      for s in self.rt.selection()),
                     key=lambda x: -x[1])
        if not sel:
            return
        remaps = copy.deepcopy(self.cfg['remaps'])
        for kind, i in sel:
            del remaps[kind][i]
        self._commit_remaps(remaps)

    def _rule_toggle(self):
        remaps = copy.deepcopy(self.cfg['remaps'])
        for s in self.rt.selection():
            kind, i = s.split(':')
            r = remaps[kind][int(i)]
            r['on'] = not r.get('on', True)
        self._commit_remaps(remaps)

    # ------------------------------------------------------------ scan

    def _render_scan(self):
        st, f, c = self.st, self.found, self.cfg
        for r in self.scan_rows.values():      # keep edits across redraws
            self._remember(r)
        st.delete(*st.get_children())
        self.scan_rows = {}
        rm = c['remaps']
        on = lambda kind: [r for r in rm[kind] if r.get('on', True)]
        have4 = {parse_v4_prefix(r['from']) for r in on('ipv4')}
        have6 = {parse_v6_prefix(r['from']) for r in on('ipv6')}
        haveh = {r['from'].upper() for r in on('host_prefix')}
        havet = {r['from'].lower() for r in on('text')}
        manual = {a.lower() for a in c['manual_accounts']}
        customs = {r['keyword'] for r in c['custom_removals']}
        rows = {grp[0]: [] for grp in SCAN_GROUPS}
        info = rows['info']

        def add(cat, src, count, example, to='', checked=True):
            row = {'cat': cat, 'from': src, 'to': to, 'checked': checked,
                   'count': count, 'example': example, 'key': (cat, src)}
            row.update(self.scan_edits.get(row['key'], {}))   # user's edits
            rows[cat].append(row)

        def host_handled(p):
            up = p.upper()
            return any(up == h or up.startswith(h + '-')
                       or up.startswith(h + '_') for h in haveh)

        for p, (n, ex) in f['ipv4'].items():
            if p in have4:
                info.append(('IPv4 %s (rule exists)' % p, n, ex))
            else:
                add('ipv4', p, n, ex)
        for k, (n, ex) in f['ipv6'].items():
            p = '%x:%x' % (k >> 16, k & 0xffff)
            if k in have6:
                info.append(('IPv6 %s (rule exists)' % p, n, ex))
            else:
                add('ipv6', p, n, ex)
        for p, (n, ex) in f['hosts'].items():
            if host_handled(p):
                info.append(('Hostname prefix %s (rule exists)' % p, n, ex))
            else:
                add('host', p, n, ex)
        if f['host_mapped']:
            n = sum(v[0] for v in f['host_mapped'].values())
            info.append(('Hostnames remapped by existing rules', n,
                         ', '.join(sorted(f['host_mapped'])[:5])))
        for dom, (n, ex) in f['domains'].items():
            if dom in havet:
                info.append(('Domain %s (rule exists)' % dom, n, ex))
            else:
                add('domain', dom, n, ex)
        for tok, (n, _) in f['possible_accounts'].items():
            if tok.lower() not in manual:
                add('account', tok, n, '', checked=False)
        for line, (n, kw) in f['keywords'].items():
            phrase = keyword_phrase(line, kw)
            if phrase not in customs:
                add('keyword', line, n, '', phrase, checked=False)
        for text, (n, kind) in f.get('descs', {}).items():
            if text.lower() not in havet:
                add('desc', text, n, kind, checked=False)
        if f['accounts']:
            names = sorted(f['accounts'])
            info.append(('Accounts removed automatically (%d)' % len(names),
                         sum(v[0] for v in f['accounts'].values()),
                         ', '.join(names[:8])
                         + (' ...' if len(names) > 8 else '')))
        for rule, (n, _) in sorted(f['secrets'].items()):
            info.append((rule, n, ''))

        st.tag_configure('group', font=self.fonts['semi'])
        for g, title, hint in SCAN_GROUPS:
            items = rows[g]
            if not items:
                continue
            parent = st.insert('', 'end', open=g != 'info', tags=('group',),
                               values=('', '%s  [%d]' % (title, len(items)),
                                       '', '', hint))
            if g == 'info':
                for src, n, ex in sorted(items, key=lambda x: -x[1]):
                    st.insert(parent, 'end', values=('', src, '',
                                                     '{:,}'.format(n), ex))
                continue
            for row in sorted(items, key=lambda x: -x['count']):
                iid = st.insert(parent, 'end')
                self.scan_rows[iid] = row
                self._show_row(iid)
        note = []
        if f['truncated']:
            note.append('quick scan: only the first %d MB of each file'
                        % c['quick_scan_mb'])
        if f['cancelled']:
            note.append('scan cancelled: partial results')
        self.v_status.set('Scan results ready' + (' (%s)' % '; '.join(note)
                                                  if note else '') + '.')

    def _show_row(self, iid):
        r = self.scan_rows[iid]
        self.st.item(iid, values=(CHECK if r['checked'] else UNCHECK,
                                  r['from'], r['to'],
                                  '{:,}'.format(r['count']), r['example']))

    def _remember(self, r):
        """Keep a row's edits across re-renders (until the next scan)."""
        self.scan_edits[r['key']] = {'from': r['from'], 'to': r['to'],
                                     'checked': r['checked']}

    def _scan_click(self, event):
        iid = self.st.identify_row(event.y)
        if iid in self.scan_rows and self.st.identify_column(event.x) == '#1':
            r = self.scan_rows[iid]
            r['checked'] = not r['checked']
            self._remember(r)
            self._show_row(iid)
            return 'break'

    def _scan_edit(self, event):
        iid = self.st.identify_row(event.y)
        if iid not in self.scan_rows:
            return
        r = self.scan_rows[iid]
        col = self.st.identify_column(event.x)
        if col == '#2' and r['cat'] == 'host':
            field, label = 'from', 'Hostname prefix to match:'
        elif col == '#2' and r['cat'] == 'desc':
            field, label = 'from', 'Text to replace (e.g. one word of it):'
        elif col == '#3' and r['cat'] in NEEDS_TO:
            field, label = 'to', ('Keyword to remove the value after:'
                                  if r['cat'] == 'keyword' else
                                  'Replace %s with:' % r['from'])
        else:
            return
        val = simpledialog.askstring('Edit', label, initialvalue=r[field],
                                     parent=self.root)
        if val is not None:
            r[field] = val.strip()
            r['checked'] = True
            self._remember(r)
            self._show_row(iid)
        return 'break'

    def _suggest(self):
        if not self.scan_rows:
            return
        rm, f = self.cfg['remaps'], self.found
        rows = [(i, r) for i, r in self.scan_rows.items() if r['checked']
                and not r['to'] and r['cat'] in ('ipv4', 'ipv6', 'host',
                                                 'domain')]
        avoid4 = set(f['ipv4']) | {parse_v4_prefix(r[s]) for r in rm['ipv4']
                                   for s in ('from', 'to')}
        avoid4 |= {r['to'] for r in self.scan_rows.values()
                   if r['cat'] == 'ipv4' and r['to']}
        avoid6 = set(f['ipv6']) | {parse_v6_prefix(r[s]) for r in rm['ipv6']
                                   for s in ('from', 'to')}
        avoid6 |= {parse_v6_prefix(r['to']) for r in self.scan_rows.values()
                   if r['cat'] == 'ipv6' and r['to']}
        s4 = iter(suggest_v4(sum(1 for _, r in rows if r['cat'] == 'ipv4'),
                             avoid4))
        s6 = iter(suggest_v6(sum(1 for _, r in rows if r['cat'] == 'ipv6'),
                             avoid6))
        typed = [r for r in self.scan_rows.values() if r['to']]
        used_to = ({r['to'].upper() for r in rm['host_prefix']}
                   | {r['to'].upper() for r in typed if r['cat'] == 'host'})
        used_dom = ({r['to'].lower() for r in rm['text']} | set(f['domains'])
                    | {r['to'].lower() for r in typed if r['cat'] == 'domain'})
        nh = nd = 0
        short = 0
        for iid, r in rows:
            if r['cat'] == 'ipv4':
                r['to'] = next(s4, '')
                short += not r['to']
            elif r['cat'] == 'ipv6':
                r['to'] = next(s6, '')
                short += not r['to']
            elif r['cat'] == 'host':
                while suggest_host(r['from'], nh).upper() in used_to:
                    nh += 1
                r['to'] = suggest_host(r['from'], nh)
                nh += 1
            else:
                while suggest_domain(nd) in used_dom:
                    nd += 1
                r['to'] = suggest_domain(nd)
                nd += 1
            self._remember(r)
            self._show_row(iid)
        if short:
            messagebox.showwarning('Suggest', (
                '%d row(s) could not be given a free prefix. Type a To value '
                'for them, or untick them.' % short))

    def _add_checked(self):
        rows = [r for r in self.scan_rows.values() if r['checked']]
        if not rows:
            messagebox.showinfo('Scan', 'Nothing is checked.')
            return
        missing = [r['from'] for r in rows if r['cat'] in NEEDS_TO
                   and not r['to']]
        if missing:
            messagebox.showwarning('Scan', (
                'These need a "To" value (double-click To, or use Suggest):'
                '\n\n' + '\n'.join(missing[:15])))
            return
        # A keyword must leave something after it on the line, or the rule
        # would hold the secret itself and remove nothing.
        def nothing_after(r):
            line = ' '.join(r['from'].split()).lower()
            kw = ' '.join(r['to'].split()).lower()
            i = line.find(kw)
            return i >= 0 and not line[i + len(kw):].strip(' :=')
        whole = [r['from'] for r in rows if r['cat'] == 'keyword'
                 and nothing_after(r)]
        if whole:
            messagebox.showwarning('Scan', (
                'For these lines, To must be only the keyword before the '
                'value (e.g. "snmp-server community"), not the whole line:'
                '\n\n' + '\n'.join(whole[:15])))
            return
        self._pull()
        remaps = copy.deepcopy(self.cfg['remaps'])
        kinds = {'ipv4': 'ipv4', 'ipv6': 'ipv6', 'host': 'host_prefix'}
        for r in rows:
            if r['cat'] in kinds:
                remaps[kinds[r['cat']]].append(
                    {'from': r['from'], 'to': r['to'], 'on': True})
            elif r['cat'] == 'domain':
                remaps['text'].append({'from': r['from'], 'to': r['to'],
                                       'word': True, 'case': False,
                                       'on': True})
        # Text rules run after the IP / hostname remaps, so a description is
        # matched as it will look then.
        descs = [r for r in rows if r['cat'] == 'desc']
        if descs:
            cfg2 = copy.deepcopy(self.cfg)
            cfg2['remaps'] = copy.deepcopy(remaps)
            cfg2['remaps']['text'] = []
            try:
                eng = Scrubber(cfg2)
                eng.set_learned(())
                after = lambda s: eng.scrub_text(s)
            except ScrubError:
                after = lambda s: s
            for r in descs:
                remaps['text'].append({'from': after(r['from']),
                                       'to': r['to'], 'word': True,
                                       'case': False, 'on': True})
        errors = validate_remaps(remaps)
        if errors:
            messagebox.showerror('Scan', 'Not added:\n' + '\n'.join(errors))
            return
        for r in rows:
            if r['cat'] == 'account':
                self.cfg['manual_accounts'].append(r['from'])
            elif r['cat'] == 'keyword':
                self.cfg['custom_removals'].append(
                    {'keyword': r['to'], 'what': 'word', 'on': True})
        self.cfg['remaps'] = remaps
        self._save()
        self._load_removals()
        self._refresh_rules()
        self._render_scan()
        self.v_status.set('Added %d item(s) to the rules.' % len(rows))

    def _import_nodes(self):
        path = filedialog.askopenfilename(
            title='Node / hostname list', filetypes=[
                ('Excel, text or CSV', '*.xlsx *.xlsm *.txt *.csv'),
                ('All files', '*.*')])
        if not path:
            return
        try:
            if path.lower().endswith(('.xlsx', '.xlsm')):
                text = read_xlsx_text(path)
            elif path.lower().endswith('.xls'):
                raise ScrubError('Old .xls files are not supported; save it '
                                 'as .xlsx or CSV, or use Paste node list.')
            else:
                with open(path, 'rb') as fh:
                    raw = fh.read()
                # Excel "Unicode Text" is UTF-16; CSV UTF-8 has a BOM.
                if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
                    text = raw.decode('utf-16')
                elif raw[:3] == b'\xef\xbb\xbf':
                    text = raw[3:].decode('utf-8', 'replace')
                else:
                    text = raw.decode('latin-1')
        except (OSError, ScrubError, ET.ParseError, UnicodeError) as e:
            messagebox.showerror('Import', str(e))
            return
        self._add_nodes(text, os.path.basename(path))

    def _paste_nodes(self):
        d = tk.Toplevel(self.root)
        d.title('Paste node list')
        d.transient(self.root)
        frm = ttk.Frame(d, padding=10)
        frm.pack(fill='both', expand=True)
        ttk.Label(frm, text='Paste hostnames (e.g. a column copied from '
                  'Excel). Anything that is not hostname-shaped is ignored.'
                  ).pack(anchor='w')
        t = tk.Text(frm, width=60, height=20, font=self.mono)
        t.pack(fill='both', expand=True, pady=4)

        def ok():
            text = t.get('1.0', 'end')
            d.destroy()
            self._add_nodes(text, 'pasted list')
        bf = ttk.Frame(frm)
        bf.pack(anchor='e')
        ttk.Button(bf, text='OK', command=ok).pack(side='left', padx=4)
        ttk.Button(bf, text='Cancel', command=d.destroy).pack(side='left')
        d.bind('<Escape>', lambda e: d.destroy())
        t.focus_set()
        d.grab_set()
        d.wait_window()

    def _add_nodes(self, text, source):
        """Add hostname prefixes from a node list to the scan results."""
        names = set(hostnames_in(text))
        if not names:
            messagebox.showinfo('Node list', 'No hostname-shaped names '
                                '(like A-B-EE-AS1) found in %s.' % source)
            return
        if self.found is None:
            self.found = empty_found()
        hosts = self.found['hosts']
        for name in names:
            p = host_prefix_of(name).upper()
            if p in hosts:
                hosts[p][0] += 1
            else:
                hosts[p] = [1, name]
        msg = ('Node list (%s): %d hostname(s), %d prefix(es). Check them in '
               'the Hostname group and Add checked to rules; they are then '
               'saved, so this is only needed once.'
               % (source, len(names),
                  len({host_prefix_of(n).upper() for n in names})))
        self._log(msg)
        self._render_scan()
        self.v_status.set(msg)
        self.nb.select(0)

    # ------------------------------------------------------------ test

    def _test_soon(self, event=None):
        if self._test_job is not None:
            self.root.after_cancel(self._test_job)
        self._test_job = self.root.after(500, self._test)

    def _test(self):
        self._test_job = None
        self._pull()
        text = self.t_in.get('1.0', 'end-1c')
        self.ht.delete(*self.ht.get_children())
        try:
            eng = Scrubber(self.cfg)
        except ScrubError as e:
            out, rows = str(e), []
        else:
            eng.set_learned(eng.learn_text(text)
                            if self.cfg['learn_accounts'] else ())
            col = _Collect(keep_rows=True)
            eng.report = col
            out = eng.scrub_text(text)
            rows = col.rows
        self.t_out.config(state='normal')
        self.t_out.delete('1.0', 'end')
        self.t_out.insert('1.0', out)
        for line, rule, before, after in rows:
            self.ht.insert('', 'end', values=(line, rule, before, after))
            if not after or after.startswith('('):
                continue                # nothing visible to highlight
            pos = '%d.0' % line
            while True:
                pos = self.t_out.search(after, pos, '%d.end' % line)
                if not pos:
                    break
                end = '%s+%dc' % (pos, len(after))
                self.t_out.tag_add('hit', pos, end)
                if self.t_out.compare(end, '<=', pos):
                    break
                pos = end
        self.t_out.config(state='disabled')

    # ------------------------------------------------------------ inputs

    def _add_files(self):
        for p in filedialog.askopenfilenames(
                title='Show output files', filetypes=[
                    ('Show output', ' '.join('*' + e for e in
                                             self.cfg['extensions'])),
                    ('All files', '*.*')]):
            self._add_input(p)

    def _add_folder(self):
        p = filedialog.askdirectory(title='Folder of show output')
        if p:
            self._add_input(p)

    def _add_input(self, path):
        path = os.path.normpath(path)
        if path not in self.inputs.get(0, 'end'):
            self.inputs.insert('end', path)

    def _remove_inputs(self):
        for i in reversed(self.inputs.curselection()):
            self.inputs.delete(i)

    def _pick_out(self):
        p = filedialog.askdirectory(title='Output folder')
        if p:
            self.v_out.set(os.path.normpath(p))

    def _pick_rep(self):
        p = filedialog.asksaveasfilename(
            title='Report file', defaultextension='.csv',
            filetypes=[('CSV', '*.csv')])
        if p:
            self.v_rep.set(os.path.normpath(p))

    # ------------------------------------------------------------ running

    def _log(self, msg):
        self.t_log.config(state='normal')
        self.t_log.insert('end', time.strftime('%H:%M:%S  ') + msg + '\n')
        self.t_log.see('end')
        self.t_log.config(state='disabled')

    def _qlog(self, msg):
        self.q.put(('log', msg))

    def _set_prog(self, phase, done, total, name):
        self.prog = (phase, done, total, name)      # read by _poll

    def _busy(self, on):
        st = 'disabled' if on else 'normal'
        self.b_scrub.config(state=st)
        self.b_scan.config(state=st)
        self.b_cancel.config(state='normal' if on else 'disabled')
        if not on:
            self.prog = None
            self.pb['value'] = 0

    def _start(self, name, fn):
        self.cancel = threading.Event()
        self.t_start = time.time()
        self._busy(True)

        def job():
            try:
                self.q.put(('done', name, fn()))
            except Cancelled:
                self.q.put(('cancelled', name, None))
            except ScrubError as e:
                self.q.put(('error', name, str(e)))
            except Exception:            # show it rather than lose it
                import traceback
                self.q.put(('error', name, traceback.format_exc()))
        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def _inputs_or_warn(self):
        inputs = list(self.inputs.get(0, 'end'))
        if not inputs:
            messagebox.showinfo('CiscoScrub', 'Add input files or folders '
                                'first.')
        return inputs

    def _scan(self):
        inputs = self._inputs_or_warn()
        if not inputs:
            return
        self._pull()
        try:
            files = collect_files(inputs, self.cfg['extensions'],
                                  self.cfg['include_subfolders'])
            Scrubber(self.cfg)
        except ScrubError as e:
            messagebox.showerror('Scan', str(e))
            return
        if not files:
            messagebox.showinfo('Scan', 'No %s files found.'
                                % ' / '.join(self.cfg['extensions']))
            return
        cfg = copy.deepcopy(self.cfg)
        limit = (cfg['quick_scan_mb'] * 1024 * 1024 if self.v_quick.get()
                 else None)
        self._log('Scan started: %d file(s).' % len(files))
        self._start('scan', lambda: scan(files, cfg, self._set_prog,
                                         self.cancel, limit))

    def _scrub(self):
        inputs = self._inputs_or_warn()
        if not inputs:
            return
        self._pull()
        if not self._save():
            return
        cfg = copy.deepcopy(self.cfg)
        if not any(cfg['remaps'][k] for k in REMAP_KINDS):
            scan_first = messagebox.askyesno('Scrub', (
                'There are no remap rules yet, so IPs and hostnames will not '
                'change (secrets and accounts still will).\n\n'
                'Run Scan first to get suggestions? Choose No to scrub '
                'anyway.'), icon='warning', default='yes')
            if scan_first:
                self.nb.select(0)
                return
        out = self.v_out.get().strip() or None
        rep = self.v_rep.get().strip() or None
        out_dir = os.path.abspath(out or default_paths(inputs)[0])
        self._log('Scrub started.')
        self.nb.select(4)

        def fn():
            totals = run(inputs, cfg, out, rep, log=self._qlog,
                         progress=self._set_prog, cancel=self.cancel)
            return totals, out_dir
        self._start('scrub', fn)

    def _cancel(self):
        if self.cancel is not None:
            self.cancel.set()
            self.v_status.set('Cancelling...')

    def _poll(self):
        p = self.prog
        if p is not None:
            phase, done, total, name = p
            frac = done / float(max(total, 1))
            self.pb['value'] = int(frac * 1000)
            el = time.time() - self.t_start
            eta = ''
            if frac > 0.02:
                left = el / frac - el
                eta = '  about %d:%02d left' % (left // 60, left % 60)
            self.v_status.set('%s %s  %.0f%%  (%.2f of %.2f GB)%s' % (
                phase, name, frac * 100, done / 1e9, total / 1e9, eta))
        while True:
            try:
                item = self.q.get_nowait()
            except queue.Empty:
                break
            kind = item[0]
            if kind == 'log':
                self._log(item[1])
                continue
            name, result = item[1], item[2]
            self._busy(False)
            if kind == 'error':
                self._log('Error: ' + result)
                self.v_status.set('Error - see the Log tab.')
                messagebox.showerror('CiscoScrub', result)
            elif kind == 'cancelled':
                self._log('%s cancelled.' % name.capitalize())
                self.v_status.set('Cancelled.')
            elif name == 'scan':
                self.found = result
                self.scan_edits = {}
                self._log('Scan cancelled (partial results).'
                          if result['cancelled'] else 'Scan finished.')
                self._render_scan()
                self.nb.select(0)
            else:
                self._scrub_done(*result)
        self.root.after(150, self._poll)

    def _scrub_done(self, totals, out_dir):
        self.last_out = out_dir
        self.b_open.config(state='normal')
        warn = 0
        for rule in sorted(totals):
            self._log('  %-44s %s' % (rule, '{:,}'.format(totals[rule])))
            if rule.startswith(('Residual', 'Warning', 'Possible')):
                warn += totals[rule]
        self.v_status.set('Done.')
        msg = 'Scrub finished.\n\nOutput: %s' % out_dir
        if warn:
            msg += ('\n\n%s item(s) need a look (Residual / Warning / '
                    'Possible rows in the report).' % '{:,}'.format(warn))
        msg += ('\n\nThe report holds the original values. Do not send it '
                'with the case.')
        messagebox.showinfo('CiscoScrub', msg)

    def _open_out(self):
        if self.last_out and os.path.isdir(self.last_out):
            if hasattr(os, 'startfile'):
                os.startfile(self.last_out)
            else:
                webbrowser.open('file://' + self.last_out)

    def _close(self):
        if self.worker is not None and self.worker.is_alive():
            if not messagebox.askyesno('CiscoScrub', 'A run is in progress. '
                                       'Cancel it and quit?'):
                return
            self.cancel.set()
            self.worker.join(5)
        self.root.destroy()


def gui(rules_path=RULES_FILE):
    if tk is None:
        sys.stderr.write('tkinter is not available; give input files or '
                         'folders on the command line instead.\n')
        return 1
    try:                                   # sharp text on high-DPI screens
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root, rules_path)
    root.mainloop()
    return 0


# ---------------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Sanitize Cisco show output for support cases.')
    ap.add_argument('inputs', nargs='*', help='files and/or folders')
    ap.add_argument('-o', '--output', help='output folder')
    ap.add_argument('-r', '--report', help='report CSV path')
    ap.add_argument('--rules', default=RULES_FILE, help='rules JSON file')
    ap.add_argument('--no-learn', action='store_true',
                    help='skip the account-learning first pass')
    ap.add_argument('--detail', action='store_true',
                    help='report every occurrence, not unique values')
    ap.add_argument('--version', action='version', version=VERSION)
    args = ap.parse_args(argv)

    if not args.inputs:
        return gui(args.rules)

    _no_quick_edit()
    cfg = load_config(args.rules)
    if args.no_learn:
        cfg['learn_accounts'] = False
    if args.detail:
        cfg['report_detail'] = True

    state = {'t': 0}

    def progress(phase, done, total, name):
        now = time.time()
        if now - state['t'] >= 0.5 or done >= total:
            state['t'] = now
            sys.stderr.write('\r%s %s  %5.1f%%   ' % (
                phase, name[-40:], 100.0 * done / max(total, 1)))
            sys.stderr.flush()

    def log(msg):
        sys.stderr.write('\r' + ' ' * 70 + '\r')
        print(msg)

    try:
        totals = run(args.inputs, cfg, args.output, args.report,
                     log=log, progress=progress)
    except (ScrubError, Cancelled) as e:
        sys.stderr.write('\nError: %s\n' % e)
        return 1
    for rule in sorted(totals):
        print('  %-40s %d' % (rule, totals[rule]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
