import time
import requests
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint


class Discovery:
    """Modul pre objavovanie SOAP a XML-RPC endpointov na cieľovej URL.

    Rate-limit aware:
    - Pri HTTP 429 automaticky počká a zopakuje request
    - Najprv testuje základnú URL, potom cesty z wordlistu
    - Ak nájde endpoint cez GET, preskočí POST probu (šetrí requesty)
    """

    COMMON_PATHS = [
        "/service", "/soap", "/api", "/v1/soap", "/v1/api",
        "/Service.asmx", "/Service.svc", "/rpc", "/xmlrpc",
        "/xmlrpc.php", "/webservice", "/ws", "/services",
        "/api/xmlrpc", "/communication", "/wsdl", "/RPC2",
        "/server.php", "/endpoint",
    ]

    SOAP_INDICATORS = [
        "envelope", "wsdl:definitions", "wsdl:service", "soap:body",
        "schemas.xmlsoap.org", "soapenv:", "soap12:",
        "<definitions", "targetnamespace",
    ]

    XMLRPC_INDICATORS = [
        "methodresponse", "methodcall", "<fault>", "<params>",
        "xml-rpc", "xmlrpc", "<member>", "<value>",
        "faultcode", "faultstring",
    ]

    XML_PROCESSING_INDICATORS = [
        "xml parse error", "xml syntax error", "no message element",
        "invalid xml", "parse error", "malformed xml",
        "xmlsyntaxerror", "not well-formed",
    ]

    BACKOFF_SECONDS = 11  # Čas čakania pri 429 (musí byť > server window)

    def __init__(self, session, args):
        self.session = session
        self.args = args

    def _request_with_backoff(self, method, url, **kwargs):
        """Odošle HTTP request s automatickým backoff pri 429.

        Vracia Response alebo None pri chybe.
        """
        kwargs.setdefault("timeout", self.args.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)

        try:
            if method == "GET":
                r = self.session.get(url, **kwargs)
            else:
                r = self.session.post(url, **kwargs)

            if r.status_code == 429:
                ptprint(f"  Rate limit hit, waiting {self.BACKOFF_SECONDS}s...",
                        "INFO", condition=not self.args.json)
                time.sleep(self.BACKOFF_SECONDS)
                if method == "GET":
                    r = self.session.get(url, **kwargs)
                else:
                    r = self.session.post(url, **kwargs)

            return r

        except requests.RequestException:
            return None

    def find_endpoints(self):
        """Hlavná metóda — objaví aktívne SOAP/XML-RPC endpointy."""
        ptprint("Starting endpoint discovery...", "INFO", condition=not self.args.json)
        found_endpoints = []
        seen_responses = set()  # Hash odpovedí pre detekciu catch-all serverov
        base_url = self.args.url.rstrip('/')

        paths_to_test = [""] + self.COMMON_PATHS

        for path in paths_to_test:
            target = base_url + path

            # FÁZA 1: GET — hľadáme WSDL alebo XML popis
            result = self._check_get_for_service(target)
            if result:
                resp_hash = result if isinstance(result, str) else ""
                if resp_hash and resp_hash in seen_responses:
                    # Server vracia rovnakú odpoveď na rôzne cesty (catch-all)
                    # Preskočíme — už máme tento endpoint
                    continue
                if resp_hash:
                    seen_responses.add(resp_hash)
                found_endpoints.append(target)
                continue

            # FÁZA 2: POST s XML probou
            if self._check_post_for_service(target):
                found_endpoints.append(target)
                continue

        unique_endpoints = self._deduplicate(found_endpoints)

        if not unique_endpoints:
            ptprint("No API endpoints discovered. Will test base URL as fallback.",
                    "WARNING", condition=not self.args.json)
            unique_endpoints.append(base_url)
        else:
            ptprint(f"Discovered {len(unique_endpoints)} potential endpoint(s).",
                    "OK", condition=not self.args.json)

        return unique_endpoints

    def _check_get_for_service(self, url):
        """GET request — kontroluje WSDL/XML popis.

        Vracia hash obsahu odpovede (str) ak nájde službu, False ak nie.
        Hash sa používa na detekciu catch-all serverov.
        """
        import hashlib
        r = self._request_with_backoff("GET", url)
        if r is None or r.status_code != 200:
            return False

        content_type = r.headers.get("Content-Type", "").lower()
        body_lower = r.text.lower()

        is_xml_response = ("xml" in content_type or
                           body_lower.lstrip().startswith("<?xml"))
        if not is_xml_response:
            return False

        # Vypočítame hash odpovede pre detekciu duplicít
        resp_hash = hashlib.md5(r.text.encode('utf-8', errors='ignore')).hexdigest()

        if any(ind in body_lower for ind in self.SOAP_INDICATORS):
            ptprint(f"  [GET] SOAP/WSDL indicator found at {url}",
                    "INFO", condition=not self.args.json)
            return resp_hash

        if any(ind in body_lower for ind in self.XMLRPC_INDICATORS):
            ptprint(f"  [GET] XML-RPC indicator found at {url}",
                    "INFO", condition=not self.args.json)
            return resp_hash

        return False

    def _check_post_for_service(self, url):
        """POST s XML probou — len 1 probe namiesto 2 (šetríme budget)."""
        # Posielame generickú XML probu, ktorá vyvolá odpoveď od SOAP aj XML-RPC
        generic_probe = '<?xml version="1.0"?><methodCall><methodName>probe</methodName></methodCall>'

        r = self._request_with_backoff("POST", url, data=generic_probe,
                                        headers={"Content-Type": "text/xml"})

        if r is None or r.status_code in [404, 405]:
            return False

        content_type = r.headers.get("Content-Type", "").lower()
        body_lower = r.text.lower()

        # Odmietame HTML
        if "html" in content_type and "xml" not in content_type:
            return False

        # XML odpoveď s protokolovými indikátormi
        is_xml_like = ("xml" in content_type or
                       body_lower.lstrip().startswith("<?xml") or
                       "<fault" in body_lower or
                       "<methodresponse" in body_lower or
                       "envelope" in body_lower)

        all_indicators = self.SOAP_INDICATORS + self.XMLRPC_INDICATORS
        if is_xml_like and any(ind in body_lower for ind in all_indicators):
            ptprint(f"  [POST] Service indicator found at {url}",
                    "INFO", condition=not self.args.json)
            return True

        # Server parsuje XML (Flask/custom — vracia text/plain error)
        if r.status_code in [400, 500]:
            if any(ind in body_lower for ind in self.XML_PROCESSING_INDICATORS):
                ptprint(f"  [POST] XML processing detected at {url}",
                        "INFO", condition=not self.args.json)
                return True

        return False

    @staticmethod
    def _deduplicate(urls):
        seen = set()
        result = []
        for url in urls:
            normalized = url.rstrip('/').lower()
            if normalized not in seen:
                seen.add(normalized)
                result.append(url)
        return result