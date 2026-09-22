// Fed to a partial JS recon run as a user URL on :8080 (see README, phase 2).
// P1 relative path: owned by http://192.88.97.10:8080, the host that served it.
fetch('/api/partial-only');
// P2 third-party URL: dropped in the partial path too.
fetch("https://api.payments-vendor.test/v3/partial");
