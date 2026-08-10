# aws-security-audit

A command line tool that checks an AWS account you own for common security
mistakes: root user without MFA, buckets open to the internet, SSH open to
0.0.0.0/0, CloudTrail switched off, and so on. It runs 25 checks across IAM,
S3, EC2/VPC, CloudTrail, KMS, RDS, GuardDuty and AWS Config, and writes the
results as a console table, JSON, a self-contained HTML page, SARIF and CSV.

It is read-only. It only ever calls `Describe*`, `Get*` and `List*` APIs (plus
`iam:GenerateCredentialReport`), and a guard inside the tool refuses any other
call before it is sent.

**Status:** so far this has only been run against [moto](https://github.com/getmoto/moto),
an in-process AWS mock, in the test suite and in the demo. I have not yet run
it against a real AWS account, so treat it as a working prototype: the checks
follow the AWS API documentation, but real accounts will have response shapes
and edge cases that moto does not reproduce. See [Limits](#limits).

## What it checks

CIS IDs refer to the CIS AWS Foundations Benchmark v3.0.0. A check only
carries a CIS ID where it tests what that control describes; checks with no
close match have none. Where one check covers two controls (password length
and reuse, SSH over IPv4 and over IPv6), each finding carries only the ID it
actually relates to.

| Check | Severity | CIS v3.0.0 | Scope | Passes when |
| --- | --- | --- | --- | --- |
| `iam-root-access-keys` | critical | 1.4 | global | Root user has no access keys |
| `iam-root-mfa` | critical | 1.5 | global | Root user has MFA enabled |
| `iam-user-console-mfa` | high | 1.10 | global | IAM users with a console password have MFA |
| `iam-password-policy` | medium | 1.8, 1.9 | global | Password policy requires 14+ characters and prevents reuse of the last 24 |
| `iam-access-key-rotation` | medium | 1.14 | global | Active access keys are rotated within 90 days |
| `iam-unused-credentials` | medium | 1.12 | global | No password or active key has gone unused for more than 45 days |
| `iam-user-admin-policy` | high | - | global | No IAM user has AdministratorAccess or a `*:*` policy attached directly |
| `s3-account-public-access-block` | high | 2.1.4 | global | All four account-level Block Public Access settings are on |
| `s3-bucket-public-access-block` | medium | 2.1.4 | global | Each bucket is covered by Block Public Access (its own or the account's) |
| `s3-bucket-policy-public` | critical | - | global | No bucket policy allows `Principal: "*"` without a Condition |
| `s3-default-encryption` | low | - | global | Buckets have default encryption configured |
| `s3-versioning-and-logging` | low | - | global | Buckets have versioning and server access logging |
| `ec2-sg-open-to-internet` | high | 5.2, 5.3 | regional | No security group opens SSH, RDP or common database ports to 0.0.0.0/0 or ::/0 |
| `ec2-default-sg-restricts-traffic` | medium | 5.4 | regional | Default security groups have no rules and nothing attached |
| `ec2-ebs-default-encryption` | medium | 2.2.1 | regional | EBS encryption by default is on |
| `ec2-public-amis-snapshots` | high | - | regional | No owned AMI or EBS snapshot is shared publicly |
| `ec2-imdsv2-required` | medium | 5.6 | regional | Instances require IMDSv2 (or have the metadata service off) |
| `cloudtrail-multi-region` | high | 3.1 | global | A multi-region trail is logging all read and write management events |
| `cloudtrail-log-validation` | medium | 3.2 | regional | Trails have log file validation on |
| `cloudtrail-kms-encryption` | medium | 3.5 | regional | Trails encrypt logs with a KMS key |
| `kms-key-rotation` | medium | 3.6 | regional | Enabled symmetric customer managed keys have automatic rotation on |
| `rds-public-access` | high | 2.3.3 | regional | RDS instances are not publicly accessible |
| `rds-storage-encrypted` | medium | 2.3.1 | regional | RDS instances have encrypted storage |
| `guardduty-enabled` | medium | - | regional | An enabled GuardDuty detector exists in the region |
| `config-recorder-enabled` | medium | 3.3 | regional | An AWS Config recorder is recording all supported resource types |

`aws-security-audit list-checks` prints the same list from the code.

Every finding has a status (`pass`, `fail` or `could not check`), a severity,
the resource ARN, the region, a message, the evidence it was based on (the
setting values that were read) and, for failures, remediation steps for both
the console and the AWS CLI. Account-level settings, which have no ARN of
their own, use the account's root ARN (`arn:aws:iam::<account>:root`) with
the region they apply to.

"Could not check" is its own status. If the scanner gets `AccessDenied`, a
region that is not enabled, a missing service endpoint or any other error, the
item is reported as could not check with the error code and API operation. It
never counts as a pass.

## Quick start

Python 3.12.

```sh
git clone <this repo> && cd aws-security-audit
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -e .

# Build a misconfigured mock account in moto and scan it. No AWS account needed.
.venv/bin/aws-security-audit demo --output-dir /tmp/demo-report

# Run the tests (all against moto, no network).
.venv/bin/pytest
```

`requirements.txt` pins the runtime dependencies; `requirements-dev.txt` adds
moto, pytest and ruff. The demo needs the dev set because it uses moto.

## Running it against your own account safely

1. **Use a dedicated read-only identity.** Create a role (or, if you must, a
   user) for the scanner and attach either:
   - [`iam/scanner-policy.json`](iam/scanner-policy.json), which lists exactly
     the 37 actions the checks call and nothing else. A test
     (`tests/test_demo.py`) records every API call made during the demo scan
     and fails if one is missing from this policy or if the policy grants
     something no check uses; or
   - the AWS managed `SecurityAudit` policy
     (`arn:aws:iam::aws:policy/SecurityAudit`), which is broader but also
     read-only and maintained by AWS.

   Do not run it with an admin profile just because it is convenient. The tool
   refuses write calls itself, but the point of least privilege is not having
   to trust that.

2. **Use short-lived credentials through a named profile**, for example IAM
   Identity Center (`aws sso login --profile audit`) or a role you assume. The
   tool never reads credentials itself; it hands `--profile` to boto3.

3. **Check who you are before scanning:**

   ```sh
   aws sts get-caller-identity --profile audit
   ```

4. **Scan:**

   ```sh
   aws-security-audit scan --profile audit \
     --html reports/audit.html --json reports/audit.json
   ```

   Without `--region` it scans every region the account has enabled
   (`ec2:DescribeRegions`). To limit it: `--region eu-west-2 --region us-east-1`.

5. **Keep the reports private.** They contain account IDs, resource names and
   policy excerpts. `reports/` is in `.gitignore` for that reason.

Things worth knowing before you run it:

- The calls are control-plane reads. Most AWS APIs do not charge for these;
  KMS API requests can count towards KMS request pricing, which has a monthly
  free tier. Every call
  shows up in CloudTrail under the scanner's identity, which is what you want.
- `iam:GenerateCredentialReport` asks IAM to build the credential report. AWS
  reuses a report for up to four hours, so IAM results can be that stale.
- S3 checks look at every bucket returned by `ListBuckets`, whatever
  `--region` says, and query each bucket in its own region.

## Options and exit codes

```
aws-security-audit scan [--profile P] [--region R ...] [--home-region R]
                        [--check ID ...] [--skip-check ID ...] [--service S ...]
                        [--json PATH] [--html PATH] [--sarif PATH] [--csv PATH]
                        [--suppressions FILE] [--fail-on LEVEL] [--fail-on-incomplete]
                        [--workers N] [--show-passed]
```

| Exit code | Meaning |
| --- | --- |
| 0 | Scan finished and nothing reached the `--fail-on` threshold |
| 1 | At least one unsuppressed failure at or above `--fail-on` (`critical`, `high`, `medium`, `low`, `info`) |
| 2 | Bad arguments, a bad suppressions file, or no usable credentials |
| 3 | `--fail-on-incomplete` was given and something could not be checked |

`--fail-on` defaults to `none`, so a plain scan exits 0 whatever it finds.

## Suppressions

Some findings are accepted on purpose. A suppressions file records which,
why, and until when:

```yaml
suppressions:
  - check: s3-versioning-and-logging
    resource: arn:aws:s3:::example-access-logs
    reason: Target bucket for S3 access logs. Logging it into itself would create a loop.
    expires: 2027-03-31
```

- All four keys are required. Unknown keys, unknown check IDs and bad dates
  stop the scan with exit code 2 before any AWS call, rather than being
  silently ignored.
- `resource` is an exact ARN or a shell-style pattern (`arn:aws:s3:::site-*`).
  A pattern that matches everything is rejected; use `--skip-check` instead.
- Expired entries no longer apply and are listed as warnings in the report.
  Entries more than a year out also get a warning.
- A suppressed finding still appears in every report, marked suppressed with
  its reason. It just stops counting towards `--fail-on`.
- Only failures can be suppressed. A "could not check" stays visible.
- The file is read with `yaml.safe_load`.

See [`examples/suppressions.example.yaml`](examples/suppressions.example.yaml).

## Sample output

[`sample-report/`](sample-report/) holds the output of
`aws-security-audit demo`: HTML, JSON, SARIF, CSV and the console table. **It
was generated against a moto mock account, not a real AWS account.**
[`sample-report/planted.txt`](sample-report/planted.txt) lists the
misconfigurations the demo creates first. The start of the console output:

```
Generated by 'aws-security-audit demo' against a moto mock account (123456789012). This is not a real AWS account and no real AWS API calls were made.
Account 123456789012 | 25 checks | 2 region(s): eu-west-2, us-east-1
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Status     ┃ Check                            ┃ Region    ┃ Resource                      ┃ Finding                                     ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ critical │ fail       │ iam-root-mfa                     │ global    │ arn:aws:iam::123456789012:roo │ MFA is not enabled for the root user        │
│          │            │                                  │           │ t                             │                                             │
│ critical │ fail       │ s3-bucket-policy-public          │ us-east-1 │ arn:aws:s3:::demo-public-asse │ Bucket demo-public-assets policy allows     │
│          │            │                                  │           │ ts                            │ access to anyone (Principal '*')            │
│ high     │ fail       │ cloudtrail-multi-region          │ global    │ arn:aws:iam::123456789012:roo │ No multi-region trail is fully logging      │
│          │            │                                  │           │ t                             │ management events (org-audit: logging is    │
│          │            │                                  │           │                               │ stopped)                                    │
...

41 failed, 30 passed, 0 could not be checked, 1 suppressed
Open failures by severity: critical 2, high 9, medium 18, low 12, info 0
```

The demo has no "could not check" items because moto allows every call. That
path is covered by tests that inject `AccessDenied`, `OptInRequired` and
endpoint errors with botocore's `Stubber`.

## Design

```
src/aws_security_audit/
  cli.py            typer commands: scan, list-checks, demo
  registry.py       @check decorator and CheckSpec; checks register themselves on import
  checks/           one module per service; each check is one function
  context.py        ScanContext (session, clients, caches, read-only guard) and CheckRun
  runner.py         thread pool over (check, region) pairs, ScanResult
  regions.py        enabled-region discovery with a visible fallback
  errors.py         maps AWS errors to "could not check" categories
  policy.py         small IAM/S3 policy document helpers
  suppressions.py   YAML suppressions with reasons and expiry dates
  exitcodes.py      --fail-on / --fail-on-incomplete
  output/           console, JSON, HTML (Jinja2 template), SARIF, CSV
  demo.py           the misconfigured moto account
```

- **Registry.** A check is a function decorated with `@check(id=..., severity=...,
  scope=..., cis=..., console=..., cli=...)`. It receives a `CheckRun` and
  calls `run.passed(...)`, `run.failed(...)` or `run.could_not_check(...)`.
  Checks never build `Finding` objects or handle threading themselves.
- **Scope.** `global` checks (IAM, S3) run once; `regional` checks run once
  per scanned region. The runner turns that into a list of (check, region)
  tasks and runs them on a `ThreadPoolExecutor` (`--workers`, default 8).
- **Shared lookups.** The credential report, account summary, bucket list
  and account-level public access block are fetched once per scan through
  `ScanContext.cached`, which uses a lock per key. Failures are cached too, so
  an `AccessDenied` on the credential report is reported the same way by every
  check that needed it.
- **Clients.** boto3 clients are shared between threads once created, but are
  created under a lock, since creating clients from one session is not
  thread-safe. Retries use botocore's `standard` mode.
- **Errors.** An error that stops a whole check is caught by the runner and
  recorded as could not check. Inside a check, `with run.guard(arn):` scopes an
  error to one resource, so one unreadable bucket does not hide the rest. An
  unexpected exception (a bug in a check) is also reported, not swallowed.
- **Read-only guard.** `ScanContext` registers a botocore `before-call`
  handler that raises before any operation not starting with `Describe`,
  `Get` or `List` (or `GenerateCredentialReport`) is sent. It also records
  every operation called, which is what the policy test uses.
- **Reports.** The HTML report is one file with inline CSS and a few lines of
  inline JavaScript for filtering; it makes no external requests. It is
  rendered with Jinja2 autoescaping because names, descriptions and policy
  text come from the account being scanned. The CSV writer prefixes cells
  starting with `=`, `+`, `-` or `@` so a hostile security group name cannot
  become a spreadsheet formula. SARIF results use logical locations (the ARN)
  because there is no file and line; could not check items go in the run's
  tool execution notifications.

### Testing

Every check has at least one passing and one failing test against moto
(`tests/test_*_checks.py`). Where moto cannot produce a state, the tests say
so and use another technique:

- moto always reports root MFA and root access keys as absent, so those tests
  stub `GetAccountSummary` with botocore's `Stubber`.
- moto stamps access keys with the current time, so the rotation and unused
  credential tests move the scanner's clock forward (`ScanContext.now`)
  instead of backdating the keys.
- `AccessDenied` and similar errors are injected with `Stubber` to test the
  could not check paths, including partial failures inside a check.

Other tests cover the runner, region fallback, report formats (including HTML
escaping and CSV formula guarding), exit codes, suppressions, the CLI
in-process, and the demo end to end. A conftest fixture replaces every
`AWS_*` environment variable with fake values and points the AWS config files
at `/dev/null`, so tests cannot pick up a real profile.

## Limits

- **Only tested against moto.** moto is a good model of the APIs but not a
  perfect one (for example, it does not create default SSE-S3 encryption on
  new buckets, which real AWS has done since January 2023).
- **Single account.** No AWS Organizations support, no assuming roles into
  member accounts, no delegated-admin views of GuardDuty or Config.
- **Not a compliance tool.** It maps to 20 CIS v3.0.0 controls, not the whole
  benchmark (no CloudWatch metric filters, VPC flow logs, IAM Access Analyzer,
  hardware root MFA, S3 object-level logging, and others). A pass means the
  setting was read and met the check, not that the account is secure.
- **Policies are read, not evaluated.** The public bucket policy check flags
  `Principal: "*"` statements without a Condition. It does not evaluate
  conditions, ACLs, access points or `NotPrincipal`. The admin check only looks
  at policies attached directly to users, not groups, roles, permission
  boundaries or SCPs.
- **Exposure is configuration, not reachability.** The security group check
  does not look at route tables, NACLs or whether anything listens on the
  port. `rds-public-access` reports the `PubliclyAccessible` flag only.
- **S3 is checked one bucket at a time** inside a single task, so accounts
  with thousands of buckets will be slow.
- **The credential report can be up to four hours old.**

## Next steps

- Run it against a real sandbox account and fix whatever moto did not show.
- Organizations support: assume a read-only role in each member account.
- Evaluate bucket policies properly (IAM Access Analyzer's `ValidatePolicy`
  or `GetBucketPolicyStatus`) instead of the Principal/Condition heuristic.
- More CIS controls: VPC flow logs (3.7), IAM Access Analyzer (1.20), the
  CloudWatch metric filters in section 4.
- A `diff` command comparing two JSON reports, to show what changed between
  scans.
- Parallelise per-bucket S3 calls.
