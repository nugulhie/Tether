# Credential Broker

Issues short-lived, session-scoped credentials to agent sessions. Developer long-lived keys are never returned.

## Flow

1. The launcher calls the broker with the developer's OIDC token and a `session_id`.
2. The broker reads the session from the Policy API (`GET /v1/agent/sessions/{id}`) using that same token, so only the session owner gets credentials. The Policy API refuses expired sessions and sessions whose policy has changed since they started.
3. The broker issues only what the session's policy grants, and refuses any `production` session.
4. Each issuance or refusal is reported to the Policy API as an OCSF `credential.issue` audit event. Credential values are never included.

## Endpoints

| Endpoint | Grant in policy | Result |
|---|---|---|
| `POST /v1/credentials/aws` | `aws.role`, `aws.duration_seconds` | STS `AssumeRole` credentials in `credential_process` format. Duration is capped by the session's remaining lifetime. |
| `POST /v1/credentials/github` | `github.permissions` | GitHub App installation token limited to the session's repository and the granted permissions (1 hour) |

## AWS

Each `AssumeRole` call sets:
- `SourceIdentity` = user id. This shows up in CloudTrail and cannot be changed by later role chaining.
- Session tags `user`, `device`, `repo`, `agent` and `session_id`.

The broker's own role needs `sts:AssumeRole`, `sts:TagSession` and `sts:SetSourceIdentity` on the agent role.

Recommended role: `AIAgentDevelopmentRole`. Keep it separate from human developer roles and give it no production access and no IAM mutation. Its trust policy should require the tags and the source identity:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<account>:role/CredentialBrokerRole"},
    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
    "Condition": {
      "Null": {"aws:RequestTag/session_id": "false", "aws:RequestTag/user": "false", "sts:SourceIdentity": "false"}
    }
  }]
}
```

The role's `MaxSessionDuration` must be at least the policy's `aws.duration_seconds`. The sandbox network policy must also allow the AWS endpoints the agent will call, for example `sts.<region>.amazonaws.com` and `s3.<region>.amazonaws.com`.

## GitHub

Create a GitHub App with at most the permissions agents may be granted, and install it on the allowed repositories. Never grant `administration`.

## Configuration

| Variable | Purpose |
|---|---|
| `POLICY_API` | Policy API base URL |
| `CREDENTIAL_BROKER_TOKEN` | Shared secret for reporting audit events. Must match the Policy API's value. |
| AWS SDK default chain | The broker's own AWS identity |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_FILE` | GitHub App identity |

## Revocation (kill switch)
The orchestrator calls `POST /v1/admin/revoke {session_ids, reason}` with its service token. The broker then:
- **AWS:** writes an inline deny policy `TetherRevokedSessions` on each agent role, conditioned on `aws:PrincipalTag/session_id`. It lists only revoked sessions whose credentials have not expired yet, which keeps the policy small. The broker role needs `iam:PutRolePolicy` on the agent role.
- **GitHub:** revokes each issued installation token (`DELETE /installation/token`).

Issued credentials are recorded in `BROKER_DB` (SQLite). GitHub tokens are stored encrypted with `BROKER_ENCRYPTION_KEY` (Fernet). Without a key the broker refuses to issue GitHub tokens, so it never issues a token it could not revoke.
