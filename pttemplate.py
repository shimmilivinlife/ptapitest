#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptapitest - Security testing tool for RPC and SOAP API

    ptapitest is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptapitest is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptapitest.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import sys
import os
import requests

# Import z aktuálneho priečinka
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

try:
    from modules.soap_scanner import SoapScanner
    from modules.xmlrpc_scanner import XmlRpcScanner
    from modules.discovery import Discovery
    from modules.fingerprinter import Fingerprinter
except ImportError as e:
    ptprint(f"Could not import modules: {e}", "ERROR")
    sys.exit(1)

SCRIPTNAME = "ptapitest"


class PtApiTest:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.args = args

        # Inicializácia HTTP session
        self.session = requests.Session()
        self.session.verify = False

        if self.args.headers:
            self.session.headers.update(self.args.headers)
        if self.args.proxy:
            self.session.proxies = self.args.proxy
        if self.args.cookie:
            self.session.headers.update({"Cookie": self.args.cookie})

    def run(self) -> None:
        ptprint(f"Starting {SCRIPTNAME} v{__version__} scan",
                "TITLE", condition=not self.args.json)

        # 1. Globálna kontrola Insecure Transport
        if not self.args.url.lower().startswith("https"):
            ptprint("Insecure Transport detected (HTTP)!",
                    "VULN", condition=not self.args.json, colortext=True)

        # 2. DISCOVERY — nájdenie endpointov
        disco = Discovery(self.session, self.args)
        potential_targets = disco.find_endpoints()

        ptprint(f"Testing {len(potential_targets)} endpoint(s)...",
                "INFO", condition=not self.args.json)

        # 3. FINGERPRINT + TEST každého endpointu
        tested_count = 0
        for target_url in potential_targets:
            ptprint(f"\n--- Analyzing: {target_url} ---",
                    "TITLE", condition=not self.args.json)

            # Dočasne nastavíme URL na aktuálny cieľ
            original_url = self.args.url
            self.args.url = target_url

            try:
                fp = Fingerprinter(self.session, self.args)
                service_type = fp.identify()

                if service_type == "SOAP":
                    ptprint(f"SOAP service detected at {target_url}",
                            "OK", condition=not self.args.json)

                    # Ak fingerprinter objavil skutočný endpoint (napr. /service),
                    # použijeme ho namiesto WSDL URL
                    if fp.discovered_soap_endpoint:
                        ptprint(f"Using discovered endpoint: {fp.discovered_soap_endpoint}",
                                "INFO", condition=not self.args.json)
                        self.args.url = fp.discovered_soap_endpoint

                    scanner = SoapScanner(self.session, self.args, self.ptjsonlib)
                    scanner.run()
                    tested_count += 1

                elif service_type == "XML-RPC":
                    ptprint(f"XML-RPC service detected at {target_url}",
                            "OK", condition=not self.args.json)
                    scanner = XmlRpcScanner(self.session, self.args, self.ptjsonlib)
                    scanner.run()
                    tested_count += 1

                else:
                    ptprint(f"Unknown service type at {target_url} — skipping.",
                            "WARNING", condition=not self.args.json)

            except Exception as e:
                ptprint(f"Error testing {target_url}: {e}",
                        "ERROR", condition=not self.args.json)
            finally:
                self.args.url = original_url

        # Záverečné zhrnutie
        if tested_count == 0:
            ptprint("No SOAP or XML-RPC services were identified.",
                    "WARNING", condition=not self.args.json)

        self.ptjsonlib.set_status("finished")

        if self.args.json:
            print(self.ptjsonlib.get_result_json())
        else:
            ptprint(f"\nScan finished. Tested {tested_count} service(s).", "TITLE")


def get_help():
    return [
        {"description": ["Security testing tool for RPC and SOAP API"]},
        {"usage": [f"{SCRIPTNAME} -u <url> [options]"]},
        {"options": [
            ["-u", "--url", "<url>", "Target API URL"],
            ["-p", "--proxy", "<proxy>", "Proxy (e.g. http://127.0.0.1:8080)"],
            ["-T", "--timeout", "<sec>", "Timeout (default 10)"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-c", "--cookie", "<cookie>", "Cookie header value"],
            ["-H", "--headers", "<headers>", "Additional headers (key:value)"],
            ["-a", "--user-agent", "<ua>", "Custom User-Agent"],
        ]}
    ]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url", type=str, required=True)
    parser.add_argument("-p", "--proxy", type=str)
    parser.add_argument("-T", "--timeout", type=int, default=10)
    parser.add_argument("-a", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("-c", "--cookie", type=str)
    parser.add_argument("-H", "--headers", type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action='version',
                        version=f'{SCRIPTNAME} {__version__}')

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    # Normalizácia URL
    if args.url and not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url

    if args.proxy:
        args.proxy = {"http": args.proxy, "https": args.proxy}

    args.headers = ptnethelper.get_request_headers(args)
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtApiTest(args)
    script.run()


if __name__ == "__main__":
    main()