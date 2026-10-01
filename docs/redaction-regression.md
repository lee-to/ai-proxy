# Redaction forwarding-boundary regression coverage

This matrix maps the scenarios in [issue #52](https://github.com/lee-to/ai-proxy/issues/52)
to existing tests and the additional fixtures in `tests/redaction_regression.rs`.
It describes current behavior; it does not introduce a new forwarding policy.

## Inspection and failure policies

- Reverse proxy and MITM HTTP requests are buffered completely before inspection
  and forwarding. A secret split across HTTP transfer chunks is inspected as one
  value, including when it ends at the final body byte. HTTP response/SSE streaming
  is a separate downstream path.
- Malformed JSON remains eligible for text scanning when its bytes are valid UTF-8.
  JSON validity is not required by the secret scanners. Failed Codex JSON
  normalization also leaves the body available to text scanning.
- When normalization is required, corrupt gzip/zstd bodies return `400`, and decoded
  bodies exceeding `max_body_size` return `413`. Neither case contacts the upstream
  or invokes scanners. Incomplete HTTP request bodies fail before inspection.
- Unsupported content encodings and non-UTF-8 bodies are forwarded unchanged and
  emit a warning that inspection was skipped. They do not have a text-redaction
  guarantee, even when the downstream HTTP response is successful.
- Optional model and Privacy Filter scanner failures use the configured policy.
  `regex_only` contributes no findings from the failed scanner and retains findings
  from the other configured scanners. It does not guarantee detection of content
  that only the failed scanner could recognize. In model `direct` mode there may be
  no deterministic scanner to fall back to.
- `fail_closed` contributes a finding covering the entire inspected text, which is
  passed through the configured redactor. This is whole-text masking/placeholder
  replacement, not HTTP rejection. Partial masking still preserves the configured
  prefix and suffix. The failure remains visible in `ScanReport.failed_scanners`
  and warning logs, even when replacement produced findings. A failed empty scan
  is no longer logged as a successful scan with no sensitive data.
- Blind CONNECT cannot inspect encrypted application content. It forwards opaque
  bytes, including partial traffic sent before client cancellation. MITM-excluded
  hosts and hosts outside its allowlist retain this tunnel behavior.

## Coverage matrix

The existing names below refer to `tests/integration_test.rs` unless a scanner
module is specified. New tests capture bodies independently at a local TLS
upstream; its response is always a fixed `ok`, never an echo of the capture.

| Scenario | Existing coverage | Added forwarding-boundary coverage |
| --- | --- | --- |
| Clean and secret-bearing controls | `test_proxy_redacts_aws_key_in_body`, `test_proxy_passes_clean_body_unchanged`, `test_mitm_connect_redacts_https_body` | `redaction_captures_controls_and_canaries_across_request_chunks`: clean control and every interior canary split in reverse, MITM and blind CONNECT; final secret byte is at EOF |
| Malformed JSON | Model scanner unit test `model_scanner_falls_back_on_malformed_json` covers adapter JSON, not client JSON | `redaction_scans_malformed_json_as_text`: invalid client JSON still redacts its synthetic canary in reverse and MITM |
| Compression decode failure | `test_proxy_rejects_content_encoding_when_decode_fails` checks `400` | `redaction_rejects_corrupt_compression_without_contacting_upstream`: corrupt gzip and zstd return `400`, with zero upstream requests and zero scans in reverse and MITM |
| Valid compression and expansion limits | `test_codex_zstd_body_is_decompressed_before_forwarding`, `test_proxy_rejects_oversized_decompressed_body`, `test_mitm_connect_rejects_oversized_decompressed_body` | `redaction_captures_decoded_compression_and_rejects_expansion_over_limit`: capture redacted decoded gzip/zstd controls and assert zero upstream requests on `413` in reverse and MITM |
| Unsupported inspection | `test_proxy_preserves_non_utf8_body`, `test_proxy_supports_http_connect_tunnel`, `test_mitm_excluded_host_uses_blind_connect_tunnel` | `redaction_distinguishes_opaque_bodies_from_successful_inspection` and `blind_connect_forwards_opaque_compression_without_running_scanners`: unchanged captures and no scanner calls |
| Scanner endpoint failure | Model and Privacy Filter unit tests exercise local successful adapter responses; model test covers invalid JSON fallback | `redaction_preserves_scanner_failure_policies_at_the_upstream_boundary`: successful empty response, invalid JSON, `503` and a permanently pending response; both adapters, both policies, clean and canary-bearing bodies, reverse and MITM |
| Scanner process failure | Privacy Filter unit tests `privacy_filter_scanner_reads_opf_command_json` and `privacy_filter_scanner_passes_command_args` | `redaction_handles_unavailable_scanner_process_without_claiming_success`; on Unix, `redaction_handles_scanner_process_errors_and_reaps_timed_out_children`: missing executable, successful command control, nonzero exit, invalid JSON, timeout and child reaping; both policies, reverse and MITM |
| Client cancellation / truncated body | No forwarding-boundary fixture | `redaction_cleans_up_truncated_and_cancelled_requests_before_scanning`: wait for handler/session termination, assert no scan or upstream request, then complete a fresh control request in reverse and MITM |
| Blind tunnel cancellation / truncation | Basic TCP echo tunnel test | `blind_connect_preserves_partial_traffic_and_closes_on_cancellation`: wait until upstream receives the partial canary, terminate the client, assert incomplete capture and no scanner calls |
| Inspection failure status | Individual scanner warning logs | Scanner observations distinguish successful empty results from failures; pipeline unit test `preserves_failure_status_when_other_scanners_find_secrets` verifies failure status survives alongside deterministic findings |

## Fixture boundaries

All fixtures use loopback addresses, temporary test certificates and synthetic
canaries. No provider API calls or external model/process installations are needed.
The command fixtures use `sh` on Unix; endpoint and unavailable-process fixtures
are platform-independent. Temporary files, listeners and fixture connection tasks
are cleaned up on drop. Cancellation assertions synchronize with terminal events,
and scanner timeouts use pending endpoints rather than timing a fixture sleep.

This suite covers cancellation **before the complete request body is read**.
Cancellation after a scan has started or after upstream forwarding is not a rollback
guarantee. Existing MITM WebSocket text-message and SSE tests remain in
`integration_test.rs`; these HTTP request-chunk fixtures do not claim to test
WebSocket protocol fragmentation or downstream response cancellation.

Run the new fixtures with:

```bash
cargo test --test redaction_regression
```
