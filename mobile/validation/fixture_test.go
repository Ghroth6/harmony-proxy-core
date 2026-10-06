package validation_test

// Shared supported-subset input for semantic and original-byte scope behavior.
// This is synthetic validation data; it is not a usable proxy service.
const staticConfig = `proxies:
  - name: sample-ss
    type: ss
    server: 192.0.2.1
    port: 8388
    cipher: aes-128-gcm
    password: documentation-only
proxy-groups:
  - name: sample-select
    type: select
    proxies: [sample-ss, DIRECT]
rules:
  - DOMAIN,example.com,sample-select
  - MATCH,DIRECT
`
