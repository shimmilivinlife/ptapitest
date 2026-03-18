# pttemplate: AI Coding Agent Instructions

## Project Overview
**pttemplate** is a security testing tool for RPC and SOAP APIs. It follows a three-stage pipeline architecture:
1. **Fingerprinting** - Detects the API type (SOAP, XML-RPC, or UNKNOWN)  
2. **Service Identification** - Confirms service type through WSDL/methodCall probes
3. **Vulnerability Scanning** - Runs service-specific security tests

Main entry point: [`pttemplate.py`](pttemplate.py) class `PtApiTest`

---

## Architecture & Module Patterns

### The Scanner Plugin Pattern
All security scanners follow this interface:
- **Constructor**: `__init__(self, session, args, ptjsonlib)` - receives `requests.Session`, CLI args, and JSON reporter
- **Run method**: `run(self)` creates a node via `ptjsonlib.create_node_object()`, stores its key, runs tests
- **Test methods**: Individual vulnerability tests call `self.jsonlib.add_vulnerability(vuln_id, node_key=self.node_key)`
- **Exception handling**: All network operations use bare `except: pass` to gracefully skip unavailable tests

Examples:
- [`modules/soap_scanner.py`](modules/soap_scanner.py) - Tests WSDL exposure, XXE, unsafe deserialization
- [`modules/xmlrpc_scanner.py`](modules/xmlrpc_scanner.py) - Tests introspection, brute-force

To **add a new scanner**: Create a class in `modules/`, implement the pattern above, import and instantiate it in `PtApiTest.run()` based on `service_type`.

### Fingerprinting Strategy  
[`modules/fingerprinter.py`](modules/fingerprinter.py) identifies APIs via:
1. XML-RPC: `system.listMethods` methodCall + "xmlrpc" in Server header
2. SOAP: WSDL retrieval (`?wsdl`), "soap" keywords, or 500 status on envelope post
3. Returns string: `"SOAP"`, `"XML-RPC"`, or `"UNKNOWN"`

---

## Output & Logging

### JSON vs Human-Readable Output  
- CLI flag: `--json` / `-j` sets `args.json = True`
- All test methods check `condition=not self.args.json` to suppress verbose output when JSON requested
- Final JSON output from `self.ptjsonlib.get_result_json()`

Example test pattern:
```python
ptprint("Testing feature...", "INFO", condition=not self.args.json)
# ...test logic...
ptprint("Vuln found!", "VULN", condition=not self.args.json, colortext=True)
self.jsonlib.add_vulnerability("PTV-PREFIX-VULN-NAME", node_key=self.node_key)
```

### Vulnerability ID Convention  
Format: `PTV-{SERVICE_TYPE}-{VULN_NAME}` (e.g., `PTV-SOAP-WSDL-EXPOSED`, `PTV-RPC-INTROSPECTION-ENABLED`)

---

## Configuration & Dependencies

### External Dependencies
- **ptlibs** - Provides: `ptjsonlib`, `ptprinthelper`, `ptmisclib`, `ptnethelper`
- **requests** - HTTP sessions with proxy/headers support
- **xmlrpc.client** - Built-in XML-RPC client library

### CLI Arguments (via `ptmisclib.pairs`)
- `--url` / `-u`: Target API URL (required)
- `--proxy` / `-p`: Proxy URL (auto-expanded to http/https dicts)
- `--timeout` / `-T`: Request timeout (default 10s)
- `--user-agent` / `-a`: Custom User-Agent (default: "Penterep Tools")
- `--cookie` / `-c`: Session cookie
- `--headers` / `-H`: Custom headers as key=value pairs
- `--json` / `-j`: JSON output mode
- `--version` / `-v`: Show version

Headers are processed by `ptnethelper.get_request_headers(args)` before session use.

---

## Code Style Notes

- **Comments**: Written in Slovak (developer's native language) - preserve or translate for consistency
- **Session management**: All HTTP ops via `self.session = requests.Session()` (pre-configured with proxy/headers)
- **Timeout**: Always pass `timeout=self.args.timeout` to avoid hangs
- **Error handling**: Bare `except: pass` is intentional for non-critical probes (service may not support all tests)
- **Version**: Managed in [`_version.py`](_version.py) - imported as `__version__`

---

## Common Workflows

### Run the tool
```bash
python pttemplate.py -u http://target.api/service
python pttemplate.py -u http://target.api/service --json  # JSON output
python pttemplate.py -u http://target.api/service -p http://127.0.0.1:8080 -T 5  # With proxy & timeout
```

### Adding a new vulnerability test  
1. Add test method to scanner class: `def test_vulnerability_name(self):`
2. Call `self.jsonlib.add_vulnerability()` on confirmed finding
3. Use consistent vulnerability ID format: `PTV-{SERVICE}-{ISSUE}`
4. Wrap verbose output in `condition=not self.args.json`

### Extending fingerprinting  
If new service types are needed, modify [`modules/fingerprinter.py`](modules/fingerprinter.py):`identify()` and return new service_type string, then update `PtApiTest.run()` to conditionally instantiate the appropriate scanner.
