// Uploaded through the JS recon upload button, so it has no host of its own.
// U1 relative path: kept under the 'upload' pseudo base, no BaseURL.
fetch('/api/upload-only');
// U2 absolute URL on the target: scope-checked and owned like a crawled one.
fetch("http://192.88.97.10/api/from-upload");
// U3 third-party absolute URL: dropped even though the file was uploaded.
fetch("https://api.payments-vendor.test/v1/refunds");
