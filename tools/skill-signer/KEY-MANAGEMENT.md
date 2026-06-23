# skill-signer — Key Management Runbook

Operational runbook for the keys behind the skill supply-chain trust model. Read
`README.md` first for the signing flow; this document covers **custody, fleet
distribution, rotation, and revocation** of the signing keys.

The whole model rests on one fact: **the private signing key never reaches an agent
machine.** Everything below exists to keep that true over time, across a fleet, and
through key turnover.

---

## 1. The two keys

| Key | Lives | Used by | Distributed |
|-----|-------|---------|-------------|
| **Private** (`ci-private.pem`, Ed25519) | CI secret store / an HSM / a signing service — **never** an agent box | `skill-signer` (`sign.mjs --key`) at release time | Never. It is a release-signing secret. |
| **Public** (`ci-public.pem`) | Each agent host, provisioned out of band | The runtime plugin, to verify `.agt-attestation.json` | To the whole fleet, via config management (below). |

Ed25519 keypair (these commands are tested; see `README.md`):

```bash
openssl genpkey -algorithm ed25519 -out ci-private.pem      # SECRET — CI/HSM only
openssl pkey -in ci-private.pem -pubout -out ci-public.pem  # public — fleet-distributed
```

### Where the private key lives — and where it must not

- **Yes:** a CI secret (GitHub Actions encrypted secret, GitLab CI variable, Vault),
  or — stronger — an HSM / cloud KMS / a dedicated signing service where the raw key
  bytes are never exported and signing happens behind an API.
- **No:** an agent's machine, a developer laptop used for agent work, a shared NFS
  mount, the plugin bundle, or any repository. If a malicious skill running on an
  agent box can read the private key, it can sign itself and the entire trust model
  collapses. Treat it exactly like a code-signing or release-signing key: scope it,
  audit its use, and prefer an HSM/KMS so it is never extractable.

---

## 2. Distributing the public key to a fleet

`skillPolicies.trustedSigners` accepts **either** an inline PEM string **or a file
path** to a PEM. For a fleet, **always use the file-path form** and ship the PEM as a
managed file. That decouples the key material from the policy document, so rotating a
key is a file swap (or a one-line array edit) pushed by config management — not a
hand-edit of every host's policy.

Agent policy (OpenCode: `~/.config/opencode/agt/policy.json`, or the path under
`$OPENCODE_CONFIG_HOME` / `$XDG_CONFIG_HOME`):

```jsonc
"skillPolicies": {
  "mode": "enforce",
  "requireSignature": true,                       // only CI-signed skills run
  "trustedSigners": ["/etc/agt/ci-public.pem"]    // file path — managed by config mgmt
}
```

### Ansible (Linux/macOS fleet)

```yaml
- name: Provision AGT signer public key
  ansible.builtin.copy:
    src: keys/ci-public.pem          # from your secret store, NOT the private key
    dest: /etc/agt/ci-public.pem
    owner: root
    group: root
    mode: "0644"                     # world-readable is fine; it is PUBLIC
- name: Provision AGT policy
  ansible.builtin.copy:
    src: policy/opencode-agt-policy.json
    dest: "{{ ansible_user_dir }}/.config/opencode/agt/policy.json"
    mode: "0644"
```

### MDM (managed laptops — Jamf / Intune / similar)

Push `ci-public.pem` as a managed file to a fixed path (e.g. `/etc/agt/ci-public.pem`
or `%PROGRAMDATA%\agt\ci-public.pem`) and push the policy JSON whose `trustedSigners`
points at that path. The public key is **public** — it is integrity-sensitive (an
attacker who can overwrite it on a host could trust their own key), not
confidentiality-sensitive. Protect the file's write permissions, not its readability.

> Out of scope (stated honestly): a local attacker who already has the **user's own
> privileges** can edit that user's `policy.json`, replace `ci-public.pem`, or disable
> the plugin outright. No in-process guardrail defends against an attacker who is
> already the user. This model raises the bar against *malicious skills* and
> *tampered/unsigned content*; it is not an OS-level execution boundary. For that,
> use real isolation (containers/VMs/sandboxing).

> Verify the resolved policy path on a host with `agt-opencode doctor` (it prints the
> active policy path), and confirm the toolchain a local scan would need with the same
> command's supply-chain toolchain section.

---

## 3. Rotation

`trustedSigners` is an **array**, and that is the rotation mechanism: trust the **new
key alongside the old** for an overlap window, re-sign under the new key, then retire
the old. Because the array is OR-evaluated, both old- and new-signed attestations
verify during the overlap — no flag day, no fleet-wide breakage.

**The overlap window must be longer than the attestation max-age (`maxAgeMs`).** A
skill signed by the old key just before rotation stays valid until it ages out; if you
retire the old key before the oldest old-key attestation has expired, those skills
suddenly fail to verify. So: `overlap_window > maxAgeMs` (add margin for re-sign
scheduling). Pick `notAfter` on newly issued attestations accordingly (Section 4).

Procedure:

1. **Generate the new keypair** in CI/HSM (`ci-private-v2.pem` / `ci-public-v2.pem`).
   The old private key never leaves CI; the new one is created the same way.
2. **Add the new public key to `trustedSigners` on every host** — keep the old one:
   ```jsonc
   "trustedSigners": ["/etc/agt/ci-public.pem", "/etc/agt/ci-public-v2.pem"]
   ```
   Push via Ansible/MDM. Now both old- and new-signed skills verify (dual-trust).
3. **Switch CI to sign with the new private key.** From here, all *new* releases are
   v2-signed; existing v1-signed attestations still verify during the overlap.
4. **Wait out the overlap window** — at least `maxAgeMs` plus margin — so every
   still-trusted v1 attestation has either been re-signed under v2 or aged out.
5. **Retire the old key:** remove `ci-public.pem` from `trustedSigners` (and delete the
   old private key from CI/HSM). Push the updated policy. v1 signatures no longer
   verify; the fleet is fully on v2.

Routine rotation is a calendar event (e.g. annually). A *suspected compromise* is not
routine — go straight to revocation (Section 4) instead of waiting out an overlap.

---

## 4. Revocation

> The policy primitives below — `revokedKeyIds`, `revokedAttestationKeys`, and the
> embedded `keyId` / `notAfter` fields on each attestation — are the revocation
> primitives the policy supports. (Field plumbing is owned by the policy/attestation
> engine; this runbook describes how to *operate* them, not how they are implemented.)

Rotation handles planned turnover; **revocation handles a key you no longer trust
right now** (suspected private-key compromise, a mis-issued attestation, a
decommissioned signer). Two primitives, used at different granularities:

### Key-ID-based revocation (the whole signer)

Each attestation carries the `keyId` of the key that signed it. To stop trusting a
signer immediately, add its key id to the policy deny-list:

```jsonc
"skillPolicies": {
  "trustedSigners": ["/etc/agt/ci-public-v2.pem"],
  "revokedKeyIds": ["<keyId-of-compromised-key>"]   // takes precedence over trust
}
```

A revoked `keyId` is rejected **even if the public key is still in
`trustedSigners`** — revocation is checked before/over trust, so a half-finished
config push can't accidentally re-trust a revoked key. This is the blunt instrument:
*every* attestation that key ever produced stops verifying at once.

Procedure for a compromised private key:
1. Push `revokedKeyIds: ["<keyId>"]` to the whole fleet **first** (fastest path to
   safety — do not wait on re-signing).
2. Generate a fresh keypair and add the new public key to `trustedSigners`
   (Section 3, steps 1–3) so legitimate skills can be re-signed.
3. Re-sign all current skills under the new key in CI.
4. Remove the compromised public key from `trustedSigners` once re-signing is done.
   Leave its `keyId` in `revokedKeyIds` permanently — there is no cost to keeping a
   dead key revoked, and it protects against an old attestation resurfacing.

### Attestation-level revocation (one bad stamp)

When a *single* attestation is bad but the signer is still trusted (e.g. a skill was
signed before a CVE was disclosed in its tree, and you want to pull just that one
without burning the key), list its attestation identity:

```jsonc
"revokedAttestationKeys": ["<attestation-key>"]   // surgical: one stamp, not the signer
```

This rejects exactly that attestation while every other skill signed by the same key
keeps working. Use this for narrow recalls; use `revokedKeyIds` when the key itself is
in question.

### Validity windows (`notAfter`) — time-boxed self-expiry

Each attestation may embed a `notAfter` timestamp; the runtime rejects it once that
time passes (independent of `maxAgeMs`, which is a relative age check). This is a
*built-in* expiry rather than a reaction:

- Set `notAfter` on issued attestations no later than the end of your next planned
  rotation overlap, so stale stamps can't outlive the key they were signed with.
- It is **not** a substitute for revocation: a `notAfter` weeks out does nothing for a
  key compromised today. For "stop trusting this now," use `revokedKeyIds`. Treat
  `notAfter` as a backstop that bounds blast radius, and revocation as the active control.

---

## 5. Honest limits

- The scan behind a signature finds **known** CVEs (the scanner's DB) and known
  patterns — not novel/zero-day code. A clean signature means "CI's scanner found
  nothing known," nothing more.
- Signing makes the verdict **unforgeable**, not **complete**. It is one layer of
  defense-in-depth.
- This is a **cooperative guardrail, not a guarantee.** Its security rests entirely on
  the private key never reaching an agent box. A **local attacker holding the user's
  own privileges is out of scope** — they can already edit the policy, swap the public
  key, or disable the plugin. A real execution boundary needs OS-level isolation; this
  is not that.
