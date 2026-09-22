// JS scope lab bundle. JS recon extracts endpoints line by line, so each case
// sits on its own line. Case ids match README.md and verify_js_scope.py.

// E1 relative path: owned by the host that served this file.
fetch('/api/users');
// E2 absolute URL on the target.
fetch("http://192.88.97.10/api/orders");
// E3 the target host on a port the scan never probes: its BaseURL comes from JS recon.
fetch("http://192.88.97.10:8080/api/admin");
// X1 third-party REST API.
fetch("https://api.payments-vendor.test/v1/charges");
// X2 a reachable lab host that is not a project target.
fetch("http://192.88.97.20/api/partner");
// X3 third-party URL in a config object (the whole URL lands in `path`).
const cfg = { apiUrl: "https://api.payments-vendor.test/v2" };
// E4 schema API on the target, relative. The words outside quotes on these two
// lines must not contain the API's name: the extractor's pattern for it pairs
// quotes across string literals and would capture the text between them.
const schemaRoute = "/graphql";
// X4 third-party schema API (the whole URL lands in `path`).
const cmsRoute = "https://cms.vendor-content.test/graphql";
// E5 WebSocket on the target: owned by the HTTP origin of its handshake.
const live = new WebSocket("ws://192.88.97.10/socket");
// X5 third-party WebSocket.
const push = new WebSocket("wss://push.vendor-realtime.test/live");
