# Gateway interceptor

An OpenShell `GatewayInterceptor` gRPC service (`proto/gateway_interceptor.proto`, vendored from OpenShell 76cfd0e). It is the gateway-side enforcement of one invariant:

> A sandbox exists only if the Policy API issued its name to an active session. It runs exactly that session's compiled policy and has exactly that session's providers, all built from company-vended profiles. Nothing at the gateway can widen it afterwards.

The authority is the Policy API (`GET /v1/sandboxes/{name}/authorization`), not the caller. So valid gateway credentials, including stolen orchestrator credentials, can neither create unissued sandboxes nor widen issued ones.

## Bindings (all `fail_closed`, `binding_policy = "exact"`)
| RPC | Decision |
|---|---|
| `CreateSandbox` | **modify:** replace `spec.policy` and `spec.providers` with the issued ones and annotate the session id. **validate:** deny if the name was not issued, the policy (compared as protobuf messages) or provider set differs, services are exposed, a workload template is used, or the image is not in `ALLOWED_SANDBOX_IMAGES` |
| `UpdateConfig` | Sandbox scope: only the full issued policy for that sandbox (live network updates). No merge operations or other settings. Global scope: never a policy, never `proposal_approval_mode=auto`; other settings only for `PLATFORM_ADMIN_ROLE` |
| `AttachSandboxProvider` | Only providers issued to that sandbox |
| `CreateProvider`, `UpdateProvider` | Company profile type, company naming (`<sandbox>-llm\|policy\|github\|aws`), issued to an active session |
| `Import/UpdateProviderProfiles`, `DeleteProviderProfile` | Denied: profiles are vended by this service (`SnapshotProviderProfiles`), and the gateway's only profile source is this service, so stock profiles such as `github` do not exist |
| `ApproveDraftChunk`, `ApproveAllDraftChunks`, `EditDraftChunk`, `UndoDraftChunk` | Denied (would widen an issued policy) |
| `SubmitPolicyAnalysis` | Sandbox principals only, without proposed chunks |
| `CreateSshSession`, `ExposeService` | Denied: access goes through the orchestrator's terminal relay only |
| `ConfigureProviderRefresh`, `RotateProviderCredential` | Denied: credentials come from the broker, which records them for revocation |

Teardown and narrowing RPCs (`DeleteSandbox`, `DetachSandboxProvider`, `DeleteProvider`, `RevokeSshSession`, …) are deliberately **unbound**, so the kill switch works even while this service is down.

**Failure behavior:** if the Policy API is unreachable, the service aborts with `UNAVAILABLE`, and the gateway applies `fail_closed`.

## Deployment
- **Gateway configuration:** `infra/openshell/gateway-interceptor.toml`. A test keeps it identical to the manifest.
- **Gateway authentication:** gateway extension JWTs are verified as EdDSA with `typ: openshell-ext+jwt`, `iss: openshell-gateway:<GATEWAY_ID>`, the configured audience and `caller_kind: gateway`. Configure `GATEWAY_ID` and `GATEWAY_EXTENSION_PUBLIC_KEY(_FILE)`. Use `INTERCEPTOR_ALLOW_UNAUTHENTICATED=1` for local development only.
- **TLS:** `TLS_CERT_FILE` / `TLS_KEY_FILE`, since the gateway requires https when JWT signing is on.
- **Profiles:** the `PROFILES_DIR` directory, mounted from `openshell/profiles`. The file name is the profile id.
- **Policy API:** `POLICY_API` and `INTERCEPTOR_TOKEN`. Set the same `PLATFORM_*` values on the Policy API that the orchestrator's sandboxes use.

## Not covered by the gateway
- `ExecSandbox`, `ExecSandboxInteractive` and `ForwardTcp` are streaming RPCs and cannot be intercepted. Whoever holds gateway credentials can open a shell in an existing sandbox, so only the orchestrator holds them. The orchestrator identity should be a dedicated OIDC client with short-lived credentials.
