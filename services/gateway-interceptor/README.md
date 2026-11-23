# Gateway interceptor

An OpenShell `GatewayInterceptor` gRPC service (`proto/gateway_interceptor.proto`, vendored from OpenShell v0.1.9). It is the gateway-side enforcement of one invariant:

> A sandbox exists only if the Policy API issued its name to an active session. It runs exactly that session's compiled policy and has exactly that session's providers, all built from tether-vended profiles. Nothing at the gateway can widen it afterwards.

The authority is the Policy API (`GET /v1/sandboxes/{name}/authorization`), not the caller. So valid gateway credentials, including stolen orchestrator credentials, can neither create unissued sandboxes nor widen issued ones.

## Bindings (all `fail_closed`, `binding_policy = "exact"`)
| RPC | Decision |
|---|---|
| `CreateSandbox` | **modify:** replace `spec.policy` and `spec.providers` with the issued ones and annotate the session id. **validate:** deny if the name was not issued, the policy (compared as protobuf messages) or provider set differs, services are exposed, a workload template is used, no image is named (`spec.template.image`; without `--from` the CLI sends none and the driver's `default_image` would be used), or the image is not in `ALLOWED_SANDBOX_IMAGES` |
| `StartSandbox`, `ResumeSandbox` | Only for a name issued to an active session (re-activation is validated like creation) |
| `UpdateConfig` | Sandbox scope: only the full issued policy for that sandbox (live network updates). A sandbox principal (the supervisor saving its baseline-path-enriched policy at startup) may also add OpenShell's baseline filesystem paths with their baseline access, nothing else; the compiler already lists them all, so this is normally a no-op. Gateway-stamped `token_grant_owner` is ignored; fields unknown to the vendored v0.1.9 schema make the policy unparseable (denied). No merge operations or other settings. Global scope: never a policy, never `proposal_approval_mode=auto`; other settings only for `PLATFORM_ADMIN_ROLE` |
| `AttachSandboxProvider` | Only providers issued to that sandbox |
| `CreateProvider`, `UpdateProvider` | Company profile type, company naming (`<sandbox>-llm\|policy\|github\|aws`), issued to an active session |
| `Import/UpdateProviderProfiles`, `DeleteProviderProfile` | Denied: profiles are vended by this service (`SnapshotProviderProfiles`), and the gateway's only profile source is this service, so stock profiles such as `github` do not exist |
| `ApproveDraftChunk`, `ApproveAllDraftChunks`, `EditDraftChunk`, `UndoDraftChunk` | Denied (would widen an issued policy) |
| `SubmitPolicyAnalysis` | Sandbox principals only, without proposed chunks |
| `CreateSshSession`, `ExposeService` | Denied: access goes through the orchestrator's terminal relay only |
| `ConfigureProviderRefresh`, `RotateProviderCredential` | Denied: credentials come from the broker, which records them for revocation |
| `openshell.v1.SandboxUpdates/UpdateSandbox` | Denied: image, command and environment are fixed at creation (`enable_sandbox_updates = false` as well) |

Teardown and narrowing RPCs (`DeleteSandbox`, `StopSandbox`, `SuspendSandbox`, `DetachSandboxProvider`, `DeleteProvider`, `RevokeSshSession`, …) are deliberately **unbound**, so the kill switch works even while this service is down. Stop and suspend only halt a workload, and any holder of gateway credentials can already delete one; bringing a sandbox back (`StartSandbox`, `ResumeSandbox`) is bound.

**Failure behavior:** if the Policy API is unreachable, the service aborts with `UNAVAILABLE`, and the gateway applies `fail_closed`.

## Deployment
- **Gateway configuration:** `infra/openshell/gateway.toml`, a complete example (schema version 2, Docker driver, sandbox updates off). A test keeps its bindings identical to the manifest.
- **Gateway authentication:** gateway extension JWTs are verified as EdDSA with `typ: openshell-ext+jwt`, `iss: openshell-gateway:<GATEWAY_ID>`, the configured audience and `caller_kind: gateway`. Configure `GATEWAY_ID` and `GATEWAY_EXTENSION_PUBLIC_KEY(_FILE)`. Use `INTERCEPTOR_ALLOW_UNAUTHENTICATED=1` for local development only.
- **Listener:** `INTERCEPTOR_LISTEN` (`LISTEN` still works): `host:port`, or `unix:///path` for a gateway on the same host (socket created 0660; calls still carry the gateway JWT). With JWT signing on the gateway sends its token only over `https://` or `unix://`; plaintext `http://` carries none.
- **TLS:** `TLS_CERT_FILE` / `TLS_KEY_FILE` for a network listener.
- **Debian-package gateway:** `GATEWAY_ID=openshell`, `GATEWAY_EXTENSION_PUBLIC_KEY_FILE=~/.local/state/openshell/tls/jwt/public.pem` (the signing bundle `openshell-gateway generate-certs` writes under `OPENSHELL_LOCAL_TLS_DIR`).
- **Profiles:** the `PROFILES_DIR` directory, mounted from `openshell/profiles`. The file name is the profile id.
- **Policy API:** `POLICY_API` and `INTERCEPTOR_TOKEN`. Set the same `PLATFORM_*` values on the Policy API that the orchestrator's sandboxes use.

## Not covered by the gateway
- `ExecSandbox`, `ExecSandboxInteractive` and `ForwardTcp` are streaming RPCs and cannot be intercepted. Whoever holds gateway credentials can open a shell in an existing sandbox, so only the orchestrator holds them. The orchestrator identity should be a dedicated OIDC client with short-lived credentials.
