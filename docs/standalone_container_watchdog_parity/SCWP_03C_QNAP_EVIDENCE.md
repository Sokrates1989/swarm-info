# SCWP-03C QNAP Evidence

- Date: 2026-09-02
- Operator: Repository owner
- Host class and architecture: QNAP Container Station host, `linux/amd64`
- Repository commits: producer
  `7cf56795489e287b3e4f68bb591055ffe6f9e822`; unchanged watchdog checkout
  `e7f8e1f374811cd11e6048add75f42dec38d18c3`
- Report paths and schema versions: private schema-version-2 focused and
  post-check evidence plus schema-version-1 transaction evidence under the
  disposable `/share/Public/swarm-info/scwp-03c-fixture.*` directory
- Commands executed: clean producer fast-forward followed by
  `SCWP_03C_CURRENT_IMAGE=alpine:3.16`
  `SCWP_03C_CANDIDATE_IMAGE=alpine:3.18`
  `bash "$HOME/tools/swarm-info/tests/acceptance/scwp_03c_qnap.sh"`
- Automated result: the gate selected the QNAP container runtime, created one
  namespaced disposable Compose service, detected one fixable high finding in
  the digest-pinned current image, validated a digest-pinned clean candidate,
  proved the dry-run changed neither source nor container, recorded a default-No
  cancellation, applied the reviewed exact source diff after two confirmations,
  passed exact image-ID convergence and a fresh focused post-check, and restored
  the original source and image through explicit rollback
- Manual result: the operator unfolded every security card and confirmed that
  only read-only evidence, refresh actions, and host-side commands were present;
  separate inspection of the exact admin API and web containers confirmed no
  Docker socket mount and no inline token-, password-, or secret-like
  environment value
- Documented skips and reasons: the original `alpine:3.18` to `alpine:3.22`
  registry fixture was rejected safely after the current image became clean;
  the accepted rerun used the evidence-backed `3.16` to `3.18` pair. No
  production Compose project, image reference, container, or source was changed.
  Standalone Debian/Ubuntu remains Tier 2 because no non-Swarm host is available
- Sanitization performed: secret values were never printed; the boundary check
  reduced environment inspection to key names, and private endpoint, container,
  source, and registry details unrelated to the disposable fixture are omitted
- Final verdict: PASS

The operator explicitly accepted this slice as tested. The browser remains
unable to invoke Compose, remove images, or access the Docker daemon.
