#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         CYBER-EAGLE  ///  OSINT Intelligence Framework           ║
║         Version 2.0  //  Standalone Single-File Edition          ║
║                                                                  ║
║  Kurulum:  pip install requests beautifulsoup4 aiohttp           ║
║            colorama tqdm dnspython python-whois                  ║
║                                                                  ║
║  Kullanım: python cyber_eagle_standalone.py                      ║
║            python cyber_eagle_standalone.py -k <kullanici_adi>   ║
║            python cyber_eagle_standalone.py -d <dork sorgusu>    ║
║            python cyber_eagle_standalone.py --domain example.com ║
║            python cyber_eagle_standalone.py --full <hedef>       ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

# ─── Standard library ────────────────────────────────────────────────────────
import argparse
import asyncio
import json
import math
import os
import random
import re
import socket
import sys
import time
import unicodedata
import urllib.robotparser
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generator, NoReturn
from urllib.parse import urlparse

# ─── Third-party ─────────────────────────────────────────────────────────────
try:
    import aiohttp
except ImportError:
    print("[FATAL] aiohttp bulunamadı. Kurun: pip install aiohttp"); sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[FATAL] beautifulsoup4 bulunamadı. Kurun: pip install beautifulsoup4"); sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    print("[FATAL] colorama bulunamadı. Kurun: pip install colorama"); sys.exit(1)

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    import whois as pywhois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

# ─── Python version check ─────────────────────────────────────────────────────
if sys.version_info < (3, 10):
    print("Cyber-Eagle Python 3.10+ gerektirir."); sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 1 — GLOBAL KONFİGÜRASYON
# ══════════════════════════════════════════════════════════════════════════════

TIMEOUT            = 10
MAX_CONCURRENT     = 80
RATE_LIMIT_DELAY   = 0.35
COOLDOWN_THRESHOLD = 50
COOLDOWN_DURATION  = 3.0

DEFAULT_HEADERS = {
    "Accept":                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language":         "en-US,en;q=0.9,tr;q=0.8",
    "Accept-Encoding":         "gzip, deflate, br",
    "Connection":              "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest":          "document",
    "Sec-Fetch-Mode":          "navigate",
    "Sec-Fetch-Site":          "none",
    "Cache-Control":           "max-age=0",
    "DNT":                     "1",
}

DORK_TEMPLATES = [
    'intext:"{query}"',
    'intitle:"{query}"',
    'inurl:"{query}"',
    '"{query}" site:linkedin.com',
    '"{query}" site:twitter.com',
    '"{query}" site:instagram.com',
    '"{query}" site:facebook.com',
    '"{query}" site:github.com',
    '"{query}" filetype:pdf',
    '"{query}" filetype:xlsx OR filetype:csv',
    '"{query}" site:pastebin.com',
    '"{query}" site:reddit.com',
    '"{query}" site:medium.com',
    'intext:"{query}" inurl:profile',
    'intext:"{query}" dating OR "tanisma"',
    'intext:"{query}" forum',
]

SOCIAL_PLATFORMS = {
    "Twitter/X":    "https://twitter.com/{username}",
    "Instagram":    "https://www.instagram.com/{username}/",
    "GitHub":       "https://github.com/{username}",
    "Reddit":       "https://www.reddit.com/user/{username}",
    "LinkedIn":     "https://www.linkedin.com/in/{username}",
    "TikTok":       "https://www.tiktok.com/@{username}",
    "Pinterest":    "https://www.pinterest.com/{username}/",
    "Tumblr":       "https://{username}.tumblr.com",
    "Medium":       "https://medium.com/@{username}",
    "Twitch":       "https://www.twitch.tv/{username}",
    "YouTube":      "https://www.youtube.com/@{username}",
    "Steam":        "https://steamcommunity.com/id/{username}",
    "SoundCloud":   "https://soundcloud.com/{username}",
    "DeviantArt":   "https://{username}.deviantart.com",
    "Flickr":       "https://www.flickr.com/people/{username}",
    "Vimeo":        "https://vimeo.com/{username}",
    "Dailymotion":  "https://www.dailymotion.com/{username}",
    "Keybase":      "https://keybase.io/{username}",
    "Telegram":     "https://t.me/{username}",
    "GitLab":       "https://gitlab.com/{username}",
    "Bitbucket":    "https://bitbucket.org/{username}",
    "HackerNews":   "https://news.ycombinator.com/user?id={username}",
    "ProductHunt":  "https://www.producthunt.com/@{username}",
    "Quora":        "https://www.quora.com/profile/{username}",
    "Codecademy":   "https://www.codecademy.com/profiles/{username}",
    "Replit":       "https://replit.com/@{username}",
    "StackOverflow":"https://stackoverflow.com/users/{username}",
    "Xbox":         "https://account.xbox.com/en-US/profile?gamertag={username}",
    "PSN":          "https://psnprofiles.com/{username}",
    "Spotify":      "https://open.spotify.com/user/{username}",
    "Snapchat":     "https://www.snapchat.com/add/{username}",
    "Patreon":      "https://www.patreon.com/{username}",
    "OnlyFans":     "https://onlyfans.com/{username}",
    "Fiverr":       "https://www.fiverr.com/{username}",
    "Etsy":         "https://www.etsy.com/shop/{username}",
    "Behance":      "https://www.behance.net/{username}",
    "Dribbble":     "https://dribbble.com/{username}",
    "500px":        "https://500px.com/p/{username}",
    "Letterboxd":   "https://letterboxd.com/{username}",
    "Goodreads":    "https://www.goodreads.com/{username}",
    "Chess.com":    "https://www.chess.com/member/{username}",
    "Duolingo":     "https://www.duolingo.com/profile/{username}",
    "Hackerrank":   "https://www.hackerrank.com/{username}",
    "LeetCode":     "https://leetcode.com/{username}",
    "Codeforces":   "https://codeforces.com/profile/{username}",
    "Kaggle":       "https://www.kaggle.com/{username}",
    "Gravatar":     "https://en.gravatar.com/{username}",
}

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 2 — ASCII BANNER KÜTÜPHANESİ
# ══════════════════════════════════════════════════════════════════════════════

PALETTES = [
    [Fore.CYAN,    Fore.WHITE,  Fore.LIGHTCYAN_EX],
    [Fore.GREEN,   Fore.WHITE,  Fore.LIGHTGREEN_EX],
    [Fore.RED,     Fore.WHITE,  Fore.LIGHTRED_EX],
    [Fore.YELLOW,  Fore.WHITE,  Fore.LIGHTYELLOW_EX],
    [Fore.MAGENTA, Fore.WHITE,  Fore.LIGHTMAGENTA_EX],
    [Fore.BLUE,    Fore.WHITE,  Fore.LIGHTBLUE_EX],
    [Fore.CYAN,    Fore.GREEN,  Fore.WHITE],
    [Fore.RED,     Fore.YELLOW, Fore.WHITE],
    [Fore.MAGENTA, Fore.CYAN,   Fore.WHITE],
    [Fore.GREEN,   Fore.CYAN,   Fore.LIGHTWHITE_EX],
]

MAIN_BANNERS = [
r"""
     ██████╗██╗   ██╗██████╗ ███████╗██████╗       ███████╗ █████╗  ██████╗ ██╗     ███████╗
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝
    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗█████╗  ███████║██║  ███╗██║     █████╗
    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝
    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ███████╗██║  ██║╚██████╔╝███████╗███████╗
     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
                  ____________________
                 /____________________\
                |    ._____________.   |
                |    |  [H A C K]  |   |
                |    |_____________|   |
          _____/________________________\_____
         /   ___________________________   \
        /   /  /-\                 /-\  \   \
       /   /  /   \               /   \  \   \
      /___/__/ (o) \___________/ (o) \__\___\
      |     |  \___/     _     \___/  |     |
      |     |     |  [=====]  |     |     |
      |     |     \___________/     |     |
      |_____|_______________________|_____|
""",
r"""
    ╔═╗╦ ╦╔╗ ╔═╗╦═╗  ╔═╗╔═╗╔═╗╦  ╔═╗
    ║  ╚╦╝╠╩╗║╣ ╠╦╝  ║╣ ╠═╣║ ╦║  ║╣
    ╚═╝ ╩ ╚═╝╚═╝╩╚═  ╚═╝╩ ╩╚═╝╩═╝╚═╝
              ,#####,
             #########
           ###/^\   /^\###
          ###  (o)-(o)  ###
          ##    _____    ##
          ##   /     \   ##
          ###  |ANON |  ###
           ####\_____/####
       ____##############____
      /######################\
     /##########################\
     |  ____________________  |
     | |  [CYBER-EAGLE v2]  | |
     | |____________________| |
     |__________________________|
       |  ==================  |
""",
r"""
   ░█████╗░██╗░░░██╗██████╗░███████╗██████╗░░░░░░░███████╗░█████╗░░██████╗░██╗░░░░░███████╗
   ██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗░░░░░░██╔════╝██╔══██╗██╔════╝░██║░░░░░██╔════╝
   ██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝█████╗█████╗░░███████║██║░░██╗░██║░░░░░█████╗░░
   ██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗╚════╝██╔══╝░░██╔══██║██║░░╚██╗██║░░░░░██╔══╝░░
   ╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║░░░░░░███████╗██║░░██║╚██████╔╝███████╗███████╗
   ░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝░░░░░░╚══════╝╚═╝░░╚═╝░╚═════╝░╚══════╝╚══════╝

                 _______________
                |   _________   |
                |  | LEVEL 5 |  |
                |  |_________|  |
           _____|_______________|_____
          /  #####################  \
         / ###  /~~~~\   /~~~~\  ### \
        /####  ( o  o ) ( o  o )  ####\
        |####   \ __ /   \ __ /   ####|
        |#####   \____V___/____   #####|
        |######    |  [=]  |    ######|
         \######\__|_______|__/######/
          \#######################/
           \_____________________/
""",
r"""
    ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███      ▓█████ ▄▄▄        ▄████  ██▓    ▓█████
   ▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒    ▓█   ▀▒████▄     ██▒ ▀█▒▓██▒    ▓█   ▀
   ▒▓█    ▄  ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒    ▒███  ▒██  ▀█▄  ▒██░▄▄▄░▒██░    ▒███
   ▒▓▓▄ ▄██▒ ░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄      ▒▓█  ▄░██▄▄▄▄██ ░▓█  ██▓▒██░    ▒▓█  ▄
   ▒ ▓███▀ ░ ░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒    ░▒████▒▓█   ▓██▒░▒▓███▀▒░██████▒░▒████▒

         _.-''''-.
       .'  ______  '.         [GUY FAWKES MASK]
      / .-'      '-. \
     / /  0     0  \ \
    | |     __      | |
    | |    /__\     | |
     \ \  \____/   / /
      \ '-________-' /
       '.          .'
     __/'-..____.-'\__
""",
r"""
    ─────────────────────────────────────────────────────────────────────────
     ██████╗ ██████╗ ███████╗███╗   ██╗    ███████╗ ██████╗ ██╗   ██╗██╗ ██████╗ ██████╗
    ██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔════╝██╔═══██╗██║   ██║██║██╔════╝██╔════╝
    ██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ███████╗██║   ██║██║   ██║██║██║     █████╗
    ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ╚════██║██║   ██║██║   ██║██║██║     ██╔══╝
    ╚██████╔╝██║     ███████╗██║ ╚████║    ███████║╚██████╔╝╚██████╔╝██║╚██████╗███████╗
     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝ ╚═════╝╚══════╝
    ─────────────────────────────────────────────────────────────────────────
         .---.  .---.
        /     \/     \
       ( ◈    |    ◈ )
        \   (===)   /
         `---) (---'
       ____| | | |____
      /  []|_| |_|[]  \
     /_____|     |_____\
     |  [CYBER-EAGLE]  |
     |_________________|
""",
r"""
     ██████╗  █████╗ ██████╗ ██╗  ██╗███╗   ██╗███████╗████████╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝████╗  ██║██╔════╝╚══██╔══╝
    ██║  ██║███████║██████╔╝█████╔╝ ██╔██╗ ██║█████╗     ██║
    ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██║╚██╗██║██╔══╝     ██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗██║ ╚████║███████╗   ██║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝
         .    .
        / \  / \
       / _ \/ _ \
      | /   |   \ |
      |/ (O)|(O) \|
      |     |     |
      |  /--+--\  |
       \ \     / /
        \ \___/ /
    .----\     /----.
   /  ____\___/____  \
   | /   [AGENT]   \ |
   |/               \|
""",
r"""
    ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗  ╔╦╗╔═╗╔╦╗╦ ╦╦  ╔═╗
    ╠═╣╠═╣║  ╠╩╗║╣ ╠╦╝  ║║║║ ║ ║║║ ║║  ║╣
    ╩ ╩╩ ╩╚═╝╩ ╩╚═╝╩╚═  ╩ ╩╚═╝═╩╝╚═╝╩═╝╚═╝
                ██████████
              ██░░░░░░░░░░██
            ██░░  ██  ██  ░░██
           ██░░   ██  ██   ░░██
           ██░░░░░░░░░░░░░░░░██
           ██░░ /~~~~~~~~\ ░░██
           ██░░|  ANON.  |░░██
            ██░░\________/░░██
              ██░░░░░░░░░░██
                ████████████
         _______|        |_______
        /  [OPEN SOURCE INTEL]  \
        \________________________/
""",
r"""
    ███╗   ██╗███████╗██╗  ██╗████████╗     ██████╗ ███████╗███╗   ██╗
    ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝    ██╔════╝ ██╔════╝████╗  ██║
    ██╔██╗ ██║█████╗   ╚███╔╝    ██║       ██║  ███╗█████╗  ██╔██╗ ██║
    ██║╚██╗██║██╔══╝   ██╔██╗    ██║       ██║   ██║██╔══╝  ██║╚██╗██║
    ██║ ╚████║███████╗██╔╝ ██╗   ██║       ╚██████╔╝███████╗██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝╚═╝  ╚═══╝
          _____     _____
         /     \   /     \
        / (◉)   \ / (◉)   \
       |    _____|_____    |
       |   /           \   |
        \_/ ,---------. \_/
           /   V  V  V  \
          |    _______    |
          |   |       |   |
          |   |  [█]  |   |
          |   |_______|   |
           \             /
            `___________'
""",
r"""
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░  ██████╗██╗   ██╗██████╗ ███████╗██████╗      ███████╗ █████╗  ██████╗ ██╗     ███████╗  ░
    ░ ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝  ░
    ░ ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     █████╗  ███████║██║  ███╗██║     █████╗    ░
    ░ ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗     ██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝    ░
    ░ ╚██████╗   ██║   ██████╔╝███████╗██║  ██║     ███████╗██║  ██║╚██████╔╝███████╗███████╗  ░
    ░  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝  ░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
           _____________
          /      _      \
         /    ,-' '-,    \
        /   ,'  ( )  ',   \
       /   /    |||    \   \
       |  |     |||     |  |
       |  |_____|_|_____|  |
       |   [SURVEILLANCE]  |
        \___________________/
""",
r"""
         ___  ___  ___  ___  ___      ___  ___  ___  ___  ___  ___
        /\__\/\__\/\__\/\__\/\__\    /\__\/\__\/\__\/\__\/\__\/\__\
       /  \  /  \  /  \  /  \  \/  /  \/  \/  \/  \/  \/  \/  \/
      / C / / Y / / B / / E / / R /  / E / / A / / G / / L / / E /
     /___\/___\/___\/___\/___\/___\  /___\/___\/___\/___\/___\/___\

              ()--()
             (  ~~  )
            >=|O  O|=<
             \  vv  /
              '|  |'
              /|  |\
             / |  | \
          __/  |  |  \__
         /_____|  |_____\
         |   [H4CK3R]   |
         |_______________|
         |  ///\\\///\  |
         |_______________|
""",
]

TOOL_BANNERS = [
r"""
       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
       ░   CYBER-EAGLE  //  OSINT CORE   ░
       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
       ,----.  ,----.
      /  ##  \/  ##  \           __
     | # /\ # | # /\ #|        /  \
     | #|  |# | #|  |#|       | () |
     | # \/ # | # \/ #|       | /\ |
      \  ##  /\  ##  /       /|    |\
       `----'  `----'       ( |    | )
          \    /      .     .|      |.
           \  /        `---' `------' `---(🔍)
            \/             SCANNING...
          ~~~~~~
""",
r"""
    ┌─────────────────────────────────────────────────┐
    │          💀  CYBER-EAGLE INTEL MODULE  💀        │
    └─────────────────────────────────────────────────┘
         ______
       .d888888b.           ___
      d88888888888b         \  \___
     d8888888888888b         \     \
     888888888888888          )     )
     Y8888888888888P         /  ___/
      `Y88888888888'         \ /
        `Y8888888'     🔍-----'
          `Y888'
            `Y'
     ┌──────────────────────────────────┐
     │  TARGET ACQUIRED. INITIATING...  │
     └──────────────────────────────────┘
""",
r"""
    ╔══════════════════════════════════════════════════╗
    ║      C Y B E R - E A G L E  //  S C A N         ║
    ╚══════════════════════════════════════════════════╝
      ______     ___________
     / ____ \   /           \
    / / ## \ \ /  MAGNIFYING \
   | | #--# | |    GLASS      |
    \ \ ## / / \    ___      /
     \ \__/ /   \__/ Q \____/
      \____/        \____/
         |  |          |
      ___V__V___    ___V___
     /  |    |  \  / SCAN  \
    |   |    |   ||        |
    |   | 💀 |   || ACTIVE |
    |   |    |   ||        |
     \__|____|__/  \______/
""",
r"""
    ░▒▓█ CYBER-EAGLE OSINT ENGINE █▓▒░
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        .---.                  ___
       /     \                /   \
      |  . .  |              ( 🔍  )
      |  (_)  |               \___/
       \ -=- /                  |
        `---'                   |
          |   .-----.           |
          |--| SCAN |-----------|
          |   `-----'           |
        __|__                 __|__
       /     \               /     \
      | OSINT |             | INTEL |
       \_____/               \_____/
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""",
r"""
    ▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀
     CYBER-EAGLE  :::  INTELLIGENCE HUB
    ▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄
         _____
        /  _  \      ____
       / /#\ \ \    /    \
      / /   \ \ \  /  __  \
     /_/     \_\_\/ /## \ |
     |   . .   |  | |   | |
     |   (_)   |  | |___| |
     |  ( __ ) |  |__🔍___|
      \_________/     |
          |||          \___
          |||              `---> SCANNING TARGET
         _|||_
    ▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀
""",
r"""
    ╭─────────────────────────────────────────────╮
    │  ☠  CYBER-EAGLE  ///  ACTIVE RECON MODE  ☠  │
    ╰─────────────────────────────────────────────╯
           _______
          /  ###  \             🔍
         / # \_/ # \          /
        | ## ( ) ## |        /
        | ## /_\ ## |-------'
        | ###   ### |
         \ ##_-_## /
          \  ###  /
           \     /
      ______\   /______
     |  [ C-EAGLE ]   |
     |_________________|
         |       |
        [█]     [█]
""",
r"""
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   CYBER-EAGLE  ■  OPEN SOURCE INTELLIGENCE  ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
       .-~~~~~~~-.         ___
      /    . .    \       /   \__
     /   ( o o )   \     /  🔍   \
    |     (___) .---|----'  (⌕)   |
    |    ,-._,-.    |       \_____|
    |    `-----'    |         |
     \   ___________/         |
      `-'-----------`---- TARGET LOCKED
""",
r"""
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓▓  ☠  CYBER-EAGLE :: DIGITAL FOOTPRINT  ☠  ▓▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
        _____              _____
       /     \            /     \___
      / O   O \          / LENS     \
     |    __   |   🔎   |    ___     |
     |   |__|  |--------|   / Q \    |
     |  ______  |       |  '-----'   |
      \_________/        \___________/
           |
     ______V______
    |  SCAN ENGINE |
    |_______________|
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
""",
r"""
    ══════════════════════════════════════════════
        C  Y  B  E  R  -  E  A  G  L  E
    ══════════════════════════════════════════════
           ____
          /    \
         / 0  0 \          /
        /  \__/  \        / 🔍
       /    ||    \------'
      /_____|_|____\
      |  RECON HUB |
      |    ACTIVE  |
      |____________|
       \/        \/
        |        |
       [▓]      [▓]
    ══════════════════════════════════════════════
      [ USERNAME ]  [ DORK ]  [ DOMAIN ]  [ RISK ]
    ══════════════════════════════════════════════
""",
r"""
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░  ☠  CYBER-EAGLE OSINT PLATFORM v2.0  ☠  ░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
        ,--.  ,--.
       /  ##\/##  \         .--------.
      | #  /\  # |         |  🔍    |
      | # |  | # |         | ACTIVE |
      | # |  | # |---------|        |
      | # \  / # |         '--------'
       \  ##\/##  /
        `--''--'
     .--[CYBER-EAGLE]--.
     |  OSINT PLATFORM  |
     |  ______________ |
     | |  TARGET-ID   ||
     | |______________||
     '------------------'
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
""",
]


def _colour_banner(lines: list[str]) -> str:
    c1, c2, c3 = random.choice(PALETTES)
    out = []
    for i, line in enumerate(lines):
        if i % 3 == 0:
            out.append(c1 + line)
        elif i % 3 == 1:
            out.append(c2 + line)
        else:
            out.append(c3 + line)
    return "\n".join(out) + Style.RESET_ALL


def get_main_banner() -> str:
    return _colour_banner(random.choice(MAIN_BANNERS).split("\n"))


def get_tool_banner() -> str:
    return _colour_banner(random.choice(TOOL_BANNERS).split("\n"))


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 3 — ETİK VE ORAN SINIRI MOToru
# ══════════════════════════════════════════════════════════════════════════════

class EthicsEngine:
    """robots.txt uyumu + otomatik cool-down rate limiter."""

    def __init__(self) -> None:
        self._request_count: int = 0
        self._robots_cache: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._crawl_delay_cache: dict[str, float] = {}

    def _get_parser(self, base_url: str) -> urllib.robotparser.RobotFileParser | None:
        if base_url in self._robots_cache:
            return self._robots_cache[base_url]
        rp = urllib.robotparser.RobotFileParser()
        try:
            rp.set_url(f"{base_url.rstrip('/')}/robots.txt")
            rp.read()
            self._robots_cache[base_url] = rp
            self._crawl_delay_cache[base_url] = float(rp.crawl_delay("*") or 0.0)
        except Exception:
            self._robots_cache[base_url] = None
            self._crawl_delay_cache[base_url] = 0.0
        return self._robots_cache[base_url]

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._get_parser(base)
        return True if rp is None else rp.can_fetch("*", url)

    def get_crawl_delay(self, url: str) -> float:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._crawl_delay_cache:
            self._get_parser(base)
        return self._crawl_delay_cache.get(base, 0.0)

    async def tick(self) -> None:
        self._request_count += 1
        if self._request_count % COOLDOWN_THRESHOLD == 0:
            print(
                f"\n{Fore.YELLOW}[ETHICS] ⚠  Rate threshold ({self._request_count} istek). "
                f"Cool-down {COOLDOWN_DURATION}s …{Style.RESET_ALL}",
                flush=True,
            )
            await asyncio.sleep(COOLDOWN_DURATION)
        else:
            await asyncio.sleep(RATE_LIMIT_DELAY)

    @property
    def total_requests(self) -> int:
        return self._request_count


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 4 — KOGNİTİF HEURİSTİKS MOTORu
# ══════════════════════════════════════════════════════════════════════════════

_TR_MAP = str.maketrans("çÇğĞıİöÖşŞüÜ", "cCgGiIoOsSuU")
_LEET_MAP = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
    "s": ["5", "$"], "t": ["7"], "l": ["1"], "g": ["9"],
}
_SEPARATORS = ["", "_", ".", "-"]
_SUFFIXES    = ["", "1", "2", "123", "2024", "2025", "_official", "_real",
                ".official", "_tr", "_en", "_us", "_de", "_pro", "_x",
                "x", "xx", "hd", "vip"]
_PREFIXES    = ["", "the", "real", "official", "mr", "dr", "0", "x"]


class HeuristicsEngine:
    """Kullanıcı adından 300+ varyasyon üretir."""

    def __init__(self, username: str) -> None:
        self.raw   = username
        self.clean = self._normalise(username)

    @staticmethod
    def _normalise(text: str) -> str:
        text = text.translate(_TR_MAP)
        text = unicodedata.normalize("NFD", text)
        return "".join(c for c in text if unicodedata.category(c) != "Mn").lower().strip()

    @staticmethod
    def _split_tokens(name: str) -> list[str]:
        name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
        return [t.lower() for t in re.split(r"[\s_.\-]+", name) if t]

    def _basic_case(self) -> Generator[str, None, None]:
        for v in (self.clean, self.clean.upper(), self.clean.capitalize(),
                  self.raw, self.raw.lower(), self.raw.upper()):
            yield v

    def _separator_variants(self) -> Generator[str, None, None]:
        tokens = self._split_tokens(self.clean)
        if len(tokens) < 2:
            return
        for sep in _SEPARATORS:
            yield sep.join(tokens)
            yield sep.join(reversed(tokens))

    def _prefix_suffix(self) -> Generator[str, None, None]:
        base = self.clean
        for pre in _PREFIXES:
            for suf in _SUFFIXES:
                for sep in _SEPARATORS:
                    candidate = f"{pre}{sep}{base}{sep}{suf}".strip(sep)
                    if candidate:
                        yield candidate

    def _leet_speak(self) -> Generator[str, None, None]:
        base = self.clean
        for i, ch in enumerate(base):
            for rep in _LEET_MAP.get(ch, []):
                yield base[:i] + rep + base[i + 1:]

    def _year_variants(self) -> Generator[str, None, None]:
        for year in range(1980, 2026):
            yield f"{self.clean}{year}"
            yield f"{self.clean}_{year}"

    def _number_pad(self) -> Generator[str, None, None]:
        for n in range(1, 30):
            yield f"{self.clean}{n:02d}"
            yield f"{self.clean}_{n}"

    def generate(self, max_results: int = 300) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []

        def _add(v: str) -> None:
            v = v.strip()
            if v and v not in seen and len(v) <= 50:
                seen.add(v); results.append(v)

        for gen in (self._basic_case, self._separator_variants,
                    self._prefix_suffix, self._leet_speak,
                    self._number_pad, self._year_variants):
            for v in gen():
                _add(v)
                if len(results) >= max_results:
                    return results
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 5 — RİSK ANALİZÖRÜ
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RiskReport:
    target:          str
    score:           int
    level:           str
    breakdown:       dict[str, int]
    profiles_found:  list[dict[str, Any]] = field(default_factory=list)
    dork_results:    list[dict[str, Any]] = field(default_factory=list)
    domain_data:     dict[str, Any]       = field(default_factory=dict)
    metadata:        dict[str, Any]       = field(default_factory=dict)


class Analyzer:
    SENSITIVE_KEYWORDS = [
        "email", "phone", "address", "password", "leaked",
        "breach", "credential", "ssn", "dob", "passport",
        "identity", "bank", "card",
    ]

    def analyse(
        self,
        target: str,
        profiles: list[dict[str, Any]],
        dork_results: list[dict[str, Any]],
        domain_data: dict[str, Any],
    ) -> RiskReport:
        bd: dict[str, int] = {}
        found = [p for p in profiles if p.get("found")]

        bd["social_presence"] = min(len(found) * 4, 40)
        bd["dork_hits"]       = min(len(dork_results) * 5, 25)

        dp = 0
        if domain_data.get("registrar"):    dp += 5
        if domain_data.get("emails"):       dp += 5
        if domain_data.get("nameservers"):  dp += 3
        if domain_data.get("creation_date"): dp += 2
        bd["domain_data"] = min(dp, 15)

        names = {(p.get("display_name") or "").lower().strip() for p in found if p.get("display_name")}
        bd["cross_platform"] = min(max(0, len(names) - 1) * 3, 10)

        all_text = " ".join(
            str(d.get("snippet", "")) + str(d.get("title", "")) for d in dork_results
        ).lower()
        bd["sensitive_indicators"] = min(
            sum(1 for kw in self.SENSITIVE_KEYWORDS if kw in all_text) * 2, 5
        )
        bd["account_age"] = 0

        total = max(0, min(sum(bd.values()), 100))
        level = "CRITICAL" if total >= 75 else "HIGH" if total >= 50 else "MEDIUM" if total >= 25 else "LOW"

        return RiskReport(
            target=target, score=total, level=level, breakdown=bd,
            profiles_found=found, dork_results=dork_results, domain_data=domain_data,
            metadata={"total_scanned": len(profiles), "total_found": len(found),
                      "dork_count": len(dork_results)},
        )


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 6 — RAPOR MOTORU
# ══════════════════════════════════════════════════════════════════════════════

_LEVEL_COL = {"LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW,
              "HIGH": Fore.RED,  "CRITICAL": Fore.MAGENTA}
_BAR_W = 30


def _risk_bar(score: int) -> str:
    filled = round(_BAR_W * score / 100)
    col = (Fore.MAGENTA if score >= 75 else Fore.RED if score >= 50
           else Fore.YELLOW if score >= 25 else Fore.GREEN)
    return (col + "█" * filled + Fore.WHITE + "░" * (_BAR_W - filled) + Style.RESET_ALL)


def _box(title: str, w: int = 70) -> tuple[str, str, str]:
    inner = w - 2
    return (f"╔{'═'*inner}╗",
            f"║ {title.center(inner - 2)} ║",
            f"╚{'═'*inner}╝")


class Reporter:
    def __init__(self, report: RiskReport) -> None:
        self.report    = report
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def print_report(self) -> None:
        r  = self.report
        lc = _LEVEL_COL.get(r.level, Fore.WHITE)
        print()
        for line in _box("CYBER-EAGLE  //  DIGITAL FOOTPRINT MAP"):
            print(Fore.CYAN + line)
        print(Style.RESET_ALL)

        print(f"  {Fore.WHITE}TARGET   {Fore.CYAN}{r.target}")
        print(f"  {Fore.WHITE}SCANNED  {Fore.CYAN}{self.timestamp}")
        print(f"  {Fore.WHITE}PROFILES {Fore.CYAN}{r.metadata.get('total_found')} "
              f"found / {r.metadata.get('total_scanned')} checked")

        print(f"\n  {Fore.WHITE}RISK SCORE  {lc}{r.score:3d}/100  [{r.level}]{Style.RESET_ALL}")
        print(f"  {_risk_bar(r.score)}")

        print(f"\n  {Fore.CYAN}── Score Breakdown {'─'*40}{Style.RESET_ALL}")
        labels = {
            "social_presence":      "Social Presence",
            "dork_hits":            "Dork Results",
            "domain_data":          "Domain / WHOIS",
            "cross_platform":       "Cross-Platform Consistency",
            "sensitive_indicators": "Sensitive Data Signals",
            "account_age":          "Account Age",
        }
        for key, label in labels.items():
            pts     = r.breakdown.get(key, 0)
            minibar = Fore.CYAN + "█" * pts + Fore.WHITE + "░" * (10 - min(pts, 10))
            print(f"  {Fore.WHITE}{label:<28}{minibar}{Style.RESET_ALL}  {pts:2d} pts")

        if r.profiles_found:
            print(f"\n  {Fore.CYAN}── Detected Social Profiles {'─'*36}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}{'Platform':<22}{'Status':<10}URL{Style.RESET_ALL}")
            print(f"  {'─'*64}")
            for p in r.profiles_found:
                sc  = Fore.GREEN if p.get("found") else Fore.RED
                st  = "FOUND" if p.get("found") else "N/A"
                print(f"  {Fore.LIGHTCYAN_EX}{p.get('platform','?'):<22}"
                      f"{sc}{st:<10}{Fore.WHITE}{p.get('url','')}{Style.RESET_ALL}")

        if r.dork_results:
            print(f"\n  {Fore.CYAN}── Dork Search Hits {'─'*43}{Style.RESET_ALL}")
            for i, d in enumerate(r.dork_results[:10], 1):
                title   = (d.get("title") or "N/A")[:55]
                snippet = (d.get("snippet") or "")[:70]
                url     = (d.get("url") or "")[:65]
                print(f"\n  {Fore.YELLOW}[{i:02d}] {Fore.WHITE}{title}{Style.RESET_ALL}")
                if snippet:
                    print(f"       {Fore.LIGHTBLACK_EX}{snippet}…{Style.RESET_ALL}")
                print(f"       {Fore.BLUE}{url}{Style.RESET_ALL}")

        if r.domain_data:
            print(f"\n  {Fore.CYAN}── Domain Intelligence {'─'*39}{Style.RESET_ALL}")
            for k, v in r.domain_data.items():
                if v:
                    print(f"  {Fore.WHITE}{k:<20}{Fore.LIGHTCYAN_EX}{str(v)[:60]}{Style.RESET_ALL}")

        print(f"\n  {Fore.CYAN}{'═'*66}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[CYBER-EAGLE]  Report complete.  "
              f"Score: {lc}{r.score}/100 {r.level}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}{'═'*66}{Style.RESET_ALL}\n")

    def save(self) -> str:
        r = self.report
        data = {
            "meta":     {"target": r.target, "timestamp": self.timestamp, "tool": "Cyber-Eagle"},
            "risk":     {"score": r.score, "level": r.level, "breakdown": r.breakdown},
            "profiles": r.profiles_found,
            "dorks":    r.dork_results,
            "domain":   r.domain_data,
        }
        fname = f"{r.target.replace(' ', '_')}_{int(time.time())}.json"
        path  = os.path.join(REPORT_DIR, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        return path


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 7 — SOSYAL MEDYA TARAYICI
# ══════════════════════════════════════════════════════════════════════════════

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
_NOT_FOUND_SIGNALS = [
    "page not found", "user not found", "account suspended",
    "does not exist", "sorry, this page", "this account doesn't exist",
]


def _stealth_headers(referer: str = "") -> dict[str, str]:
    h = dict(DEFAULT_HEADERS)
    h["User-Agent"] = random.choice(_UA_POOL)
    if referer:
        h["Referer"] = referer
    return h


class SocialScanner:
    def __init__(self, ethics: EthicsEngine) -> None:
        self.ethics = ethics

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        platform: str,
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> dict[str, Any]:
        async with semaphore:
            await self.ethics.tick()
            try:
                async with session.get(
                    url,
                    headers=_stealth_headers(),
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    found = resp.status in (200, 201, 203)
                    if found:
                        try:
                            text = await resp.text(errors="ignore")
                            if any(sig in text.lower() for sig in _NOT_FOUND_SIGNALS):
                                found = False
                        except Exception:
                            pass
                    return {"platform": platform, "url": url,
                            "status": resp.status, "found": found, "display_name": None}
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return {"platform": platform, "url": url,
                        "status": 0, "found": False, "display_name": None}

    async def scan(
        self,
        username: str,
        variations: list[str] | None = None,
        progress_callback=None,
    ) -> list[dict[str, Any]]:
        targets: list[tuple[str, str]] = [
            (plat, tmpl.format(username=username))
            for plat, tmpl in SOCIAL_PLATFORMS.items()
        ]
        if variations:
            top = list(SOCIAL_PLATFORMS.items())[:10]
            for var in variations[:5]:
                for plat, tmpl in top:
                    targets.append((f"{plat} [{var}]", tmpl.format(username=var)))

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        connector = aiohttp.TCPConnector(ssl=False, limit=MAX_CONCURRENT)
        results: list[dict[str, Any]] = []

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._probe(session, p, u, semaphore) for p, u in targets]
            for coro in asyncio.as_completed(tasks):
                r = await coro
                results.append(r)
                if progress_callback:
                    progress_callback(r)
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 8 — WEB / DORK TARAYICI
# ══════════════════════════════════════════════════════════════════════════════

_DDG_URL = "https://html.duckduckgo.com/html/"


class WebScanner:
    def __init__(self, ethics: EthicsEngine) -> None:
        self.ethics = ethics

    async def _ddg_search(
        self,
        session: aiohttp.ClientSession,
        query: str,
        semaphore: asyncio.Semaphore,
    ) -> list[dict[str, str]]:
        async with semaphore:
            await self.ethics.tick()
            try:
                async with session.post(
                    _DDG_URL,
                    data={"q": query, "b": "", "kl": "tr-tr"},
                    headers=_stealth_headers("https://duckduckgo.com/"),
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text(errors="ignore")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return []

        soup  = BeautifulSoup(html, "html.parser")
        items = []
        for result in soup.select(".result")[:8]:
            title   = (result.select_one(".result__title")   or type("", (), {"get_text": lambda *a, **k: ""})()).get_text(strip=True)
            snippet = (result.select_one(".result__snippet") or type("", (), {"get_text": lambda *a, **k: ""})()).get_text(strip=True)
            url     = (result.select_one(".result__url")     or type("", (), {"get_text": lambda *a, **k: ""})()).get_text(strip=True)
            if title or url:
                items.append({"title": title, "snippet": snippet, "url": url, "query": query})
        return items

    async def dork_scan(
        self,
        query: str,
        templates: list[str] | None = None,
        progress_callback=None,
    ) -> list[dict[str, str]]:
        templates = templates or DORK_TEMPLATES
        semaphore = asyncio.Semaphore(5)
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        all_results: list[dict[str, str]] = []
        seen: set[str] = set()

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._ddg_search(session, t.format(query=query), semaphore) for t in templates]
            for coro in asyncio.as_completed(tasks):
                for item in await coro:
                    u = item.get("url", "")
                    if u and u not in seen:
                        seen.add(u)
                        all_results.append(item)
                        if progress_callback:
                            progress_callback(item)
        return all_results


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 9 — DOMAIN / DNS / WHOIS TARAYICI
# ══════════════════════════════════════════════════════════════════════════════

def _detect_cms(headers) -> str:
    markers = {
        "WordPress":   ["wp-", "wordpress"],
        "Drupal":      ["drupal", "x-generator"],
        "Joomla":      ["joomla"],
        "Shopify":     ["x-shopid", "shopify"],
        "Wix":         ["x-wix-"],
        "Squarespace": ["x-servedby"],
    }
    hs = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    for cms, sigs in markers.items():
        if any(s in hs for s in sigs):
            return cms
    return ""


class DomainScanner:
    def __init__(self, ethics: EthicsEngine) -> None:
        self.ethics = ethics

    def _resolve_dns(self, domain: str) -> dict[str, Any]:
        records: dict[str, Any] = {}
        if _DNS_AVAILABLE:
            for rtype in ("A", "MX", "NS", "TXT", "AAAA"):
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    pass
        else:
            try:
                records["A"] = [socket.gethostbyname(domain)]
            except socket.gaierror:
                pass
        return records

    def _whois_lookup(self, domain: str) -> dict[str, Any]:
        if not _WHOIS_AVAILABLE:
            return {}
        try:
            w = pywhois.whois(domain)
            def _str(val):
                return str(val[0] if isinstance(val, list) else val or "")
            return {
                "registrar":       _str(w.registrar),
                "creation_date":   _str(w.creation_date),
                "expiration_date": _str(w.expiration_date),
                "nameservers":     _str(w.name_servers),
                "emails":          _str(w.emails),
                "country":         _str(w.country),
                "org":             _str(w.org),
            }
        except Exception:
            return {}

    async def _http_fingerprint(self, domain: str) -> dict[str, Any]:
        await self.ethics.tick()
        hdr = dict(DEFAULT_HEADERS)
        hdr["User-Agent"] = random.choice(_UA_POOL)
        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        f"{scheme}://{domain}",
                        headers=hdr,
                        timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        return {
                            "status":    resp.status,
                            "final_url": str(resp.url),
                            "server":    resp.headers.get("Server", ""),
                            "x_powered": resp.headers.get("X-Powered-By", ""),
                            "cms":       _detect_cms(resp.headers),
                            "tls":       scheme == "https",
                        }
            except Exception:
                continue
        return {}

    async def scan(self, domain: str) -> dict[str, Any]:
        loop      = asyncio.get_event_loop()
        dns_data  = await loop.run_in_executor(None, self._resolve_dns, domain)
        whois_data = await loop.run_in_executor(None, self._whois_lookup, domain)
        http_data = await self._http_fingerprint(domain)
        return {"domain": domain, "dns": dns_data, **whois_data, **http_data}


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 10 — MERKEZ ORKESTRATÖR (CORE ENGINE)
# ══════════════════════════════════════════════════════════════════════════════

def _animate_init() -> None:
    stages = [
        (Fore.CYAN,    "  [BOOT]      OSINT-CORE modülleri yükleniyor …"),
        (Fore.GREEN,   "  [ETHICS]    Etik & rate-limit motoru aktif …"),
        (Fore.YELLOW,  "  [HEURISTIC] Kognitif buluşsal motor hazır …"),
        (Fore.CYAN,    "  [SCANNERS]  Sosyal / Web / Domain tarayıcılar hazır …"),
        (Fore.GREEN,   "  [ANALYZER]  Risk puanlama motoru kalibre edildi …"),
        (Fore.WHITE,   "  [REPORTER]  İstihbarat rapor motoru bekliyor …"),
        (Fore.MAGENTA, "  ✔  CYBER-EAGLE OSINT-CORE INIT TAMAMLANDI"),
    ]
    for col, msg in stages:
        print(col + msg + Style.RESET_ALL, flush=True)
        time.sleep(0.18)
    print()


def _spin(label: str, duration: float = 1.2) -> None:
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.monotonic() + duration
    i   = 0
    while time.monotonic() < end:
        print(f"\r  {Fore.CYAN}{frames[i % len(frames)]}  {label}{Style.RESET_ALL}",
              end="", flush=True)
        time.sleep(0.08)
        i += 1
    print(f"\r  {Fore.GREEN}✔  {label}{Style.RESET_ALL}          ")


def _progress_line(result: dict[str, Any]) -> None:
    if result.get("found") or result.get("title"):
        label = result.get("platform") or result.get("title", "")
        url   = result.get("url", "")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} "
              f"{Fore.LIGHTCYAN_EX}{label:<28}{Fore.WHITE}{url[:60]}{Style.RESET_ALL}")


def _section(title: str) -> None:
    pad = "─" * max(0, 60 - len(title) - 2)
    print(f"\n  {Fore.CYAN}╔═ {title} {pad}╗{Style.RESET_ALL}")


class CyberEagleCore:
    def __init__(self) -> None:
        self.ethics   = EthicsEngine()
        self.social   = SocialScanner(self.ethics)
        self.web      = WebScanner(self.ethics)
        self.domain   = DomainScanner(self.ethics)
        self.analyzer = Analyzer()

    async def scan_username(self, username: str) -> None:
        _section(f"USERNAME SCAN  ›  {username}")
        _spin("Kullanıcı adı varyasyonları üretiliyor …", 0.8)
        variations = HeuristicsEngine(username).generate(max_results=60)
        print(f"  {Fore.YELLOW}→ {len(variations)} varyasyon üretildi "
              f"(ilk 10 gösteriliyor):{Style.RESET_ALL}")
        for v in variations[:10]:
            print(f"    {Fore.LIGHTBLACK_EX}• {v}{Style.RESET_ALL}")
        print()

        _section("SOSYAL PLATFORM TARAMASI")
        print(f"  {Fore.WHITE}50+ platform taranıyor …{Style.RESET_ALL}\n")
        profiles = await self.social.scan(username, variations=variations,
                                          progress_callback=_progress_line)

        _section("DORK TARAMASI  ›  kullanıcı adı modu")
        print(f"  {Fore.WHITE}Dork şablonları çalıştırılıyor …{Style.RESET_ALL}\n")
        dork_results = await self.web.dork_scan(
            username,
            progress_callback=lambda d: _progress_line(
                {"found": True, "platform": "DORK",
                 "url": d.get("url", ""), "title": d.get("title", "")}
            ),
        )

        _section("İSTİHBARAT ANALİZİ")
        report = self.analyzer.analyse(username, profiles, dork_results, {})
        r = Reporter(report)
        r.print_report()
        path = r.save()
        print(f"  {Fore.GREEN}✔  Rapor kaydedildi → {path}{Style.RESET_ALL}\n")

    async def scan_dork(self, query: str) -> None:
        _section(f"DORK TARAMASI  ›  {query}")
        print(f"  {Fore.WHITE}{len(DORK_TEMPLATES)} dork şablonu çalıştırılıyor …{Style.RESET_ALL}\n")
        results = await self.web.dork_scan(
            query,
            progress_callback=lambda d: print(
                f"  {Fore.GREEN}[+]{Style.RESET_ALL} "
                f"{Fore.YELLOW}{d.get('title','')[:55]}{Style.RESET_ALL}\n"
                f"      {Fore.BLUE}{d.get('url','')[:65]}{Style.RESET_ALL}"
            ),
        )
        report = self.analyzer.analyse(query, [], results, {})
        r = Reporter(report)
        r.print_report()
        path = r.save()
        print(f"  {Fore.GREEN}✔  Rapor kaydedildi → {path}{Style.RESET_ALL}\n")

    async def scan_domain(self, domain: str) -> None:
        _section(f"DOMAIN TARAMASI  ›  {domain}")
        _spin("DNS kayıtları çözümleniyor …", 1.0)
        _spin("WHOIS verisi alınıyor …", 1.2)
        _spin("HTTP parmak izi …", 0.9)
        data = await self.domain.scan(domain)
        print(f"\n  {Fore.CYAN}── Domain İstihbaratı ─────────────────────────────────{Style.RESET_ALL}")
        for k, v in data.items():
            if v and k != "domain":
                print(f"  {Fore.WHITE}{k:<20}{Fore.LIGHTCYAN_EX}{str(v)[:60]}{Style.RESET_ALL}")
        report = self.analyzer.analyse(domain, [], [], data)
        r = Reporter(report)
        r.print_report()
        path = r.save()
        print(f"  {Fore.GREEN}✔  Rapor kaydedildi → {path}{Style.RESET_ALL}\n")

    async def full_scan(self, target: str) -> None:
        await self.scan_username(target)
        await self.scan_dork(target)
        domain = target if "." in target else f"{target}.com"
        await self.scan_domain(domain)


# ══════════════════════════════════════════════════════════════════════════════
#  BÖLÜM 11 — ANA MENÜ VE GİRİŞ NOKTASI
# ══════════════════════════════════════════════════════════════════════════════

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _goodbye() -> NoReturn:
    print(f"\n  {Fore.CYAN}Cyber-Eagle oturumu sonlandırılıyor …{Style.RESET_ALL}")
    time.sleep(0.5)
    print(f"  {Fore.YELLOW}[ SESSION TERMINATED ]{Style.RESET_ALL}\n")
    sys.exit(0)


_ABOUT = ""  # Dinamik olarak oluşturulur (colorama başlatılması gerekir)


def _build_about() -> str:
    return f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                  CYBER-EAGLE  //  BU ARAÇ NE?                  ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.WHITE}CYBER-EAGLE; dijital araştırmacılar, sızma testi uzmanları ve
siber güvenlik analistleri için tasarlanmış yeni nesil, açık kaynaklı
bir OSINT (Açık Kaynak İstihbaratı) çerçevesidir.{Style.RESET_ALL}

{Fore.YELLOW}YETENEKLERİ:{Style.RESET_ALL}
  {Fore.GREEN}•{Style.RESET_ALL} 50+ sosyal platformda eş zamanlı kullanıcı adı keşfi
  {Fore.GREEN}•{Style.RESET_ALL} 300+ kullanıcı adı varyasyonu üreten buluşsal motor
  {Fore.GREEN}•{Style.RESET_ALL} 16 şablonlu Google dork motoru
  {Fore.GREEN}•{Style.RESET_ALL} Domain istihbaratı — DNS, WHOIS, HTTP parmak izi
  {Fore.GREEN}•{Style.RESET_ALL} 0-100 çok faktörlü risk puanlama sistemi
  {Fore.GREEN}•{Style.RESET_ALL} ASCII "Dijital Ayak İzi Haritası" raporlama
  {Fore.GREEN}•{Style.RESET_ALL} Etik motor — robots.txt uyumu + oran sınırlama
  {Fore.GREEN}•{Style.RESET_ALL} Stealth modu — gerçekçi tarayıcı User-Agent rotasyonu

{Fore.YELLOW}HUKUKİ UYARI:{Style.RESET_ALL}
  {Fore.RED}Bu araç yalnızca yetkili güvenlik değerlendirmeleri içindir.
  Üçüncü taraf sistemlere yetkisiz kullanım yasal ihlal oluşturabilir.
  Yazarlar kötüye kullanımdan sorumlu değildir.{Style.RESET_ALL}
"""


def _build_howto() -> str:
    return f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                  CYBER-EAGLE  //  NASIL KULLANILIR?            ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}KOMUT SATIRI BAYRAKLARI:{Style.RESET_ALL}

  {Fore.GREEN}-k  <kullanici_adi>{Style.RESET_ALL}
      Sosyal medya taraması + buluşsal varyasyonlar
      Örnek: {Fore.CYAN}python cyber_eagle_standalone.py -k JohnDoe{Style.RESET_ALL}

  {Fore.GREEN}-d  <sorgu>{Style.RESET_ALL}
      Dork araması — DuckDuckGo üzerinden 16 şablon
      Örnek: {Fore.CYAN}python cyber_eagle_standalone.py -d "Omer Can"{Style.RESET_ALL}

  {Fore.GREEN}--domain  <alan_adi>{Style.RESET_ALL}
      DNS çözümü, WHOIS ve HTTP parmak izi
      Örnek: {Fore.CYAN}python cyber_eagle_standalone.py --domain example.com{Style.RESET_ALL}

  {Fore.GREEN}--full  <hedef>{Style.RESET_ALL}
      Tam tarama — kullanıcı + dork + domain
      Örnek: {Fore.CYAN}python cyber_eagle_standalone.py --full johndoe{Style.RESET_ALL}

{Fore.YELLOW}İNTERAKTİF KONSOL KOMUTLARI:{Style.RESET_ALL}
  {Fore.CYAN}scan username  <ad>{Style.RESET_ALL}      Sosyal medya & dork taraması
  {Fore.CYAN}scan dork      <sorgu>{Style.RESET_ALL}   Google dork motoru
  {Fore.CYAN}scan domain    <domain>{Style.RESET_ALL}  Domain / DNS / WHOIS
  {Fore.CYAN}scan full      <hedef>{Style.RESET_ALL}   Tam kapsamlı tarama
  {Fore.CYAN}clear{Style.RESET_ALL}                    Ekranı temizle
  {Fore.CYAN}help{Style.RESET_ALL}                     Bu yardım menüsü
  {Fore.RED}exit{Style.RESET_ALL}                     Çıkış

{Fore.YELLOW}RAPORLAR:{Style.RESET_ALL}
  Her tarama {Fore.CYAN}reports/{Style.RESET_ALL} dizinine otomatik JSON raporu kaydeder.
"""


def _main_menu() -> None:
    _clear()
    print(get_main_banner())
    print(f"  {Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}[1]{Style.RESET_ALL}  {Fore.LIGHTCYAN_EX}Bu araç ne işe yarıyor?  {Fore.LIGHTBLACK_EX}(What is this tool?){Style.RESET_ALL}")
    print(f"  {Fore.WHITE}[2]{Style.RESET_ALL}  {Fore.LIGHTCYAN_EX}Bu araç nasıl kullanılır?  {Fore.LIGHTBLACK_EX}(How to use){Style.RESET_ALL}")
    print(f"  {Fore.WHITE}[3]{Style.RESET_ALL}  {Fore.LIGHTCYAN_EX}Araca giriş yap  {Fore.LIGHTBLACK_EX}(Launch OSINT Console){Style.RESET_ALL}")
    print(f"  {Fore.WHITE}[0]{Style.RESET_ALL}  {Fore.RED}Çıkış  {Fore.LIGHTBLACK_EX}(Exit){Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'─'*60}{Style.RESET_ALL}\n")

    while True:
        try:
            choice = input(f"  {Fore.YELLOW}▶  Seçiminiz / Select: {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            _goodbye()

        if choice == "1":
            _clear(); print(get_main_banner()); print(_build_about())
            input(f"\n  {Fore.CYAN}[ENTER] Ana menüye dön …{Style.RESET_ALL}")
            _main_menu(); return
        elif choice == "2":
            _clear(); print(get_main_banner()); print(_build_howto())
            input(f"\n  {Fore.CYAN}[ENTER] Ana menüye dön …{Style.RESET_ALL}")
            _main_menu(); return
        elif choice == "3":
            _launch_console(); return
        elif choice == "0":
            _goodbye()
        else:
            print(f"  {Fore.RED}Geçersiz seçim. Lütfen 0–3 arası girin.{Style.RESET_ALL}")


def _print_console_help() -> None:
    print(f"""
  {Fore.CYAN}┌─────────────────────────────────────────────────────────┐
  │                    KONSOL KOMUTLARI                     │
  └─────────────────────────────────────────────────────────┘{Style.RESET_ALL}
  {Fore.GREEN}scan username  <ad>{Style.RESET_ALL}      Sosyal medya & dork taraması
  {Fore.GREEN}scan dork      <sorgu>{Style.RESET_ALL}   Google dork motoru
  {Fore.GREEN}scan domain    <alan>{Style.RESET_ALL}    Domain / DNS / WHOIS istihbaratı
  {Fore.GREEN}scan full      <hedef>{Style.RESET_ALL}   Tam kapsamlı tarama (hepsi)
  {Fore.YELLOW}clear{Style.RESET_ALL}                    Ekranı temizle
  {Fore.YELLOW}help{Style.RESET_ALL}                     Bu yardım menüsü
  {Fore.RED}exit{Style.RESET_ALL}                     Çıkış
    """)


def _launch_console() -> None:
    _clear()
    print(get_tool_banner())
    _animate_init()
    core = CyberEagleCore()
    print(f"  {Fore.GREEN}OSINT Konsolu aktif.{Style.RESET_ALL}  "
          f"Komut girmek için {Fore.CYAN}'help'{Style.RESET_ALL} yazın.\n")
    _print_console_help()

    while True:
        try:
            raw = input(
                f"\n  {Fore.MAGENTA}[CYBER-EAGLE]{Fore.CYAN} ▶ {Style.RESET_ALL}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            _goodbye()

        if not raw:
            continue
        parts = raw.split(maxsplit=2)
        cmd   = parts[0].lower()

        if cmd in ("exit", "quit", "q", "çıkış", "cikis"):
            _goodbye()
        elif cmd == "help":
            _print_console_help()
        elif cmd == "clear":
            _clear(); print(get_tool_banner())
        elif cmd == "scan":
            if len(parts) < 3:
                print(f"  {Fore.RED}Kullanım: scan <username|dork|domain|full> <hedef>{Style.RESET_ALL}")
                continue
            mode, target = parts[1].lower(), parts[2]
            try:
                if mode in ("username", "user", "-k", "kullanici"):
                    asyncio.run(core.scan_username(target))
                elif mode in ("dork", "-d"):
                    asyncio.run(core.scan_dork(target))
                elif mode in ("domain", "alan", "--domain"):
                    asyncio.run(core.scan_domain(target))
                elif mode in ("full", "tam"):
                    asyncio.run(core.full_scan(target))
                else:
                    print(f"  {Fore.RED}Bilinmeyen mod: {mode}. "
                          f"[username / dork / domain / full]{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n  {Fore.YELLOW}⚠  Tarama kullanıcı tarafından durduruldu.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}Bilinmeyen komut: '{cmd}'. "
                  f"Yardım için 'help' yazın.{Style.RESET_ALL}")


def _cli_mode(args: argparse.Namespace) -> None:
    print(get_tool_banner())
    _animate_init()
    core = CyberEagleCore()
    try:
        if args.username:
            asyncio.run(core.scan_username(args.username))
        elif args.dork:
            asyncio.run(core.scan_dork(args.dork))
        elif args.domain:
            asyncio.run(core.scan_domain(args.domain))
        elif args.full:
            asyncio.run(core.full_scan(args.full))
    except KeyboardInterrupt:
        print(f"\n  {Fore.YELLOW}⚠  İşlem kullanıcı tarafından kesildi.{Style.RESET_ALL}")
        sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cyber-eagle",
        description="Cyber-Eagle OSINT Intelligence Framework",
    )
    parser.add_argument("-k", "--username", metavar="USERNAME",
                        help="Kullanıcı adı taraması (sosyal + buluşsal + dork)")
    parser.add_argument("-d", "--dork", metavar="QUERY",
                        help="Dork araması (16 şablon / DuckDuckGo)")
    parser.add_argument("--domain", metavar="DOMAIN",
                        help="Domain istihbaratı (DNS + WHOIS + HTTP)")
    parser.add_argument("--full", metavar="TARGET",
                        help="Tam tarama — kullanıcı adı + dork + domain")

    args = parser.parse_args()
    if args.username or args.dork or args.domain or args.full:
        _cli_mode(args)
    else:
        _main_menu()


if __name__ == "__main__":
    main()
