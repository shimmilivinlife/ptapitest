import requests
import re
import time
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint


class Fingerprinter:
    CONFIDENCE_THRESHOLD = 2
    BACKOFF_SECONDS = 11

    def __init__(self, session, args):
        self.session = session
        self.args = args
        self.discovered_soap_endpoint = None

    def _get_with_backoff(self, url):
        """GET s automatickým backoff pri 429."""
        try:
            r = self.session.get(url, timeout=self.args.timeout, verify=False)
            if r.status_code == 429:
                ptprint(f"    Rate limit hit, waiting {self.BACKOFF_SECONDS}s...",
                        "INFO", condition=not self.args.json)
                time.sleep(self.BACKOFF_SECONDS)
                r = self.session.get(url, timeout=self.args.timeout, verify=False)
            return r
        except requests.RequestException as e:
            return None

    def _post_with_backoff(self, url, data, headers):
        """POST s automatickým backoff pri 429."""
        try:
            r = self.session.post(url, data=data, headers=headers,
                                  timeout=self.args.timeout, verify=False)
            if r.status_code == 429:
                ptprint(f"    Rate limit hit, waiting {self.BACKOFF_SECONDS}s...",
                        "INFO", condition=not self.args.json)
                time.sleep(self.BACKOFF_SECONDS)
                r = self.session.post(url, data=data, headers=headers,
                                      timeout=self.args.timeout, verify=False)
            return r
        except requests.RequestException:
            return None

    def identify(self):
        ptprint(f"Identifying service type at {self.args.url}...",
                "INFO", condition=not self.args.json)

        xmlrpc_score = self._test_xmlrpc()
        soap_score = self._test_soap()

        ptprint(f"  Confidence scores — XML-RPC: {xmlrpc_score}, SOAP: {soap_score}",
                "INFO", condition=not self.args.json)

        if xmlrpc_score >= self.CONFIDENCE_THRESHOLD and xmlrpc_score > soap_score:
            ptprint(f"Identified as XML-RPC (confidence: {xmlrpc_score})",
                    "OK", condition=not self.args.json)
            return "XML-RPC"

        if soap_score >= self.CONFIDENCE_THRESHOLD and soap_score > xmlrpc_score:
            ptprint(f"Identified as SOAP (confidence: {soap_score})",
                    "OK", condition=not self.args.json)
            return "SOAP"

        if soap_score >= self.CONFIDENCE_THRESHOLD and soap_score == xmlrpc_score:
            ptprint(f"Ambiguous — defaulting to SOAP (confidence: {soap_score})",
                    "WARNING", condition=not self.args.json)
            return "SOAP"

        ptprint("Service type could not be determined.",
                "WARNING", condition=not self.args.json)
        return "UNKNOWN"

    # =========================================================================
    # XML-RPC
    # =========================================================================

    def _test_xmlrpc(self):
        score = 0
        payload = (
            "<?xml version='1.0'?>"
            "<methodCall><methodName>system.listMethods</methodName></methodCall>"
        )
        r = self._post_with_backoff(self.args.url, payload,
                                     {"Content-Type": "text/xml"})
        if r is None:
            return 0

        content_type = r.headers.get("Content-Type", "").lower()
        body_lower = r.text.lower()

        if "<methodresponse" in body_lower:
            score += 3
        if "<params>" in body_lower and "<value>" in body_lower:
            score += 2
        if "faultcode" in body_lower and "faultstring" in body_lower:
            if "schemas.xmlsoap.org" not in body_lower:
                score += 2
        if "xml" in content_type and "<fault>" in body_lower:
            if "envelope" not in body_lower:
                score += 1
        if "xml" in content_type and "html" not in content_type:
            score += 1

        return score

    # =========================================================================
    # SOAP
    # =========================================================================

    def _test_soap(self):
        score = 0

        # Test 1: WSDL
        wsdl_score, wsdl_content = self._probe_wsdl()
        score += wsdl_score

        # Test 2: SOAP envelope na hlavnú URL
        score += self._probe_soap_envelope(self.args.url)

        # Test 3: Endpoint z WSDL
        if wsdl_content:
            extracted = self._extract_endpoint_from_wsdl(wsdl_content)
            if extracted and extracted.rstrip('/') != self.args.url.rstrip('/'):
                ptprint(f"  WSDL references endpoint: {extracted}",
                        "INFO", condition=not self.args.json)
                ep_score = self._probe_soap_envelope(extracted)
                score += ep_score
                if ep_score > 0:
                    self.discovered_soap_endpoint = extracted

        return score

    def _probe_soap_envelope(self, target_url):
        score = 0
        soap_payload = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body/></soap:Envelope>'
        )

        r = self._post_with_backoff(target_url, soap_payload,
                                     {"Content-Type": "text/xml; charset=utf-8",
                                      "SOAPAction": '""'})
        if r is None:
            return 0

        content_type = r.headers.get("Content-Type", "").lower()
        body_lower = r.text.lower()

        if r.status_code == 405:
            return 0

        if "envelope" in body_lower and "schemas.xmlsoap.org" in body_lower:
            score += 3
        elif "envelope" in body_lower and ("soap:" in body_lower or "soapenv:" in body_lower):
            score += 3
        elif "soap:fault" in body_lower or "soapenv:fault" in body_lower:
            score += 3

        if "application/soap+xml" in content_type:
            score += 2

        if r.status_code in [200, 400, 500] and "html" not in content_type:
            if "xml" in content_type and ("fault" in body_lower or "error" in body_lower):
                score += 1

        if r.status_code == 400 and "xml parse error" in body_lower:
            score += 1

        return score

    def _probe_wsdl(self):
        """Hľadá WSDL na viacerých URL s backoff. Vracia (score, wsdl_text)."""
        parsed = urlparse(self.args.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        candidates = []
        candidates.append(self.args.url.rstrip('/') + "?wsdl")
        if base_url.rstrip('/') != self.args.url.rstrip('/'):
            candidates.append(base_url + "/?wsdl")
        # Čistý GET — kľúčové pre Flask servery
        candidates.append(self.args.url)
        if base_url.rstrip('/') != self.args.url.rstrip('/'):
            candidates.append(base_url + "/")

        # Deduplikácia
        seen = set()
        unique = []
        for url in candidates:
            key = url.rstrip('/').lower()
            if key not in seen:
                seen.add(key)
                unique.append(url)

        for wsdl_url in unique:
            ptprint(f"  Probing WSDL at: {wsdl_url}",
                    "INFO", condition=not self.args.json)

            r = self._get_with_backoff(wsdl_url)

            if r is None:
                ptprint(f"    -> Connection error", "INFO",
                        condition=not self.args.json)
                continue

            if r.status_code != 200:
                ptprint(f"    -> HTTP {r.status_code}", "INFO",
                        condition=not self.args.json)
                continue

            content_type = r.headers.get("Content-Type", "").lower()
            body_lower = r.text.lower()

            is_xml = ("xml" in content_type or
                      body_lower.lstrip().startswith("<?xml"))
            if not is_xml:
                ptprint(f"    -> Not XML", "INFO", condition=not self.args.json)
                continue

            has_definitions = ("definitions" in body_lower or
                               "wsdl:definitions" in body_lower)
            has_porttype = ("wsdl:porttype" in body_lower or
                            "<porttype " in body_lower)
            has_operation = ("<wsdl:operation" in body_lower or
                             "<operation " in body_lower)
            has_service = ("wsdl:service" in body_lower or
                           "<service " in body_lower)
            has_binding = ("wsdl:binding" in body_lower or
                           "<binding " in body_lower)

            if has_definitions:
                wsdl_score = 3
                if has_service:
                    wsdl_score += 1
                if has_binding:
                    wsdl_score += 1
                if has_porttype or has_operation:
                    wsdl_score += 1

                ptprint(f"    -> WSDL found! (score: {wsdl_score})",
                        "OK", condition=not self.args.json)
                return wsdl_score, r.text
            else:
                ptprint(f"    -> XML but no WSDL definitions", "INFO",
                        condition=not self.args.json)

        ptprint("  No WSDL found.", "INFO", condition=not self.args.json)
        return 0, ""

    def _extract_endpoint_from_wsdl(self, wsdl_content):
        parsed = urlparse(self.args.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        patterns = [
            r'<[\w:]*address\s+location\s*=\s*["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, wsdl_content, re.IGNORECASE)
            if match:
                endpoint = match.group(1)
                if not endpoint.startswith("http"):
                    endpoint = base_url.rstrip('/') + '/' + endpoint.lstrip('/')

                # Oprava: ak WSDL obsahuje localhost ale testujeme vzdialený server
                ep_parsed = urlparse(endpoint)
                target_parsed = urlparse(self.args.url)
                ep_host = ep_parsed.hostname or ""
                target_host = target_parsed.hostname or ""

                is_localhost = ep_host in ("localhost", "127.0.0.1", "::1")
                is_remote = target_host not in ("localhost", "127.0.0.1", "::1", "")

                if is_localhost and is_remote:
                    endpoint = endpoint.replace(
                        f"{ep_parsed.scheme}://{ep_parsed.netloc}",
                        base_url
                    )
                    ptprint(f"  WSDL has localhost endpoint, remapped to: {endpoint}",
                            "INFO", condition=not self.args.json)

                return endpoint

        # WSDL bez endpointu — skúsime bežné cesty
        ptprint("  WSDL has no explicit endpoint, probing common paths...",
                "INFO", condition=not self.args.json)
        common_paths = ["/service", "/soap", "/ws", "/Service.asmx",
                        "/Service.svc", "/webservice", "/api"]
        for path in common_paths:
            test_url = base_url + path
            if test_url.rstrip('/') == self.args.url.rstrip('/'):
                continue

            r = self._post_with_backoff(test_url, '<?xml version="1.0"?><test/>',
                                         {"Content-Type": "text/xml"})
            if r is None:
                continue
            if r.status_code not in [404, 405]:
                ct = r.headers.get("Content-Type", "").lower()
                if "html" not in ct:
                    ptprint(f"  Found probable endpoint: {test_url}",
                            "INFO", condition=not self.args.json)
                    return test_url

        return None