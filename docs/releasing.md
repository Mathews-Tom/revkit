# Release revkit on crates.io

The crate distributes source; Cargo builds the CLI on the user's machine. This flow does not upload the prebuilt macOS archive. Keep the Apple Silicon target claim scoped to the environments actually verified.

## Bootstrap `revkit` once

1. Land the reviewed release preparation on `main`. In a clean checkout of the exact reviewed commit, confirm `Cargo.toml` and `Cargo.lock` agree on `0.1.0`, then run `cargo package --locked --list` and `cargo publish --locked --registry crates-io --dry-run`. Do not use `--allow-dirty` for a live publish. Check [the crate API](https://crates.io/api/v1/crates/revkit): a 404 means it is unclaimed at that moment, not reserved. Stop if another owner registered it.
2. [Sign in to crates.io](https://crates.io/) as the intended owner through GitHub and [verify your email](https://crates.io/settings/profile). At [API Tokens](https://crates.io/settings/tokens), create an expiring token scoped to **Publish New** (`publish-new`) and crate name `revkit`. Keep it out of GitHub Secrets, files in the checkout, shell arguments and chat.
3. In your own interactive terminal, run the following from that reviewed commit and paste the token only when Cargo prompts. The temporary Cargo home keeps this token separate from existing credentials and is removed on shell exit. **A successful publish permanently creates `revkit` at version `0.1.0`; you cannot replace that version.**

   ```sh
   (
     set -eu
     umask 077
     cargo_home=$(mktemp -d)
     trap 'rm -rf -- "$cargo_home"' EXIT
     export CARGO_HOME="$cargo_home"
     unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN
     cargo login --registry crates-io
     cargo publish --locked --registry crates-io
   )
   ```

4. Verify [revkit 0.1.0](https://crates.io/crates/revkit/0.1.0) under the intended owner and run the shipped workflow from a clean install. Revoke the one-time token in API Tokens. If Cargo reports failure after starting upload, check the registry and index before attempting another publish.

   ```sh
   install_root=$(mktemp -d)
   cargo install --locked --registry crates-io --root "$install_root" revkit --version '=0.1.0'
   "$install_root/bin/revkit" --version
   "$install_root/bin/revkit" --help
   ```

[Why the manual first release is required](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/#trusted-publishing) · [Cargo publishing and permanence](https://doc.rust-lang.org/cargo/reference/publishing.html)

## Enable future releases with Trusted Publishing

1. In [GitHub → Settings → Environments](https://github.com/Mathews-Tom/revkit/settings/environments), create `crates-io`. Under **Deployment branches and tags**, choose **Selected branches and tags**. Add a **Tag** rule for `v*`, with no branch rule. Protect `v*` with a [tag ruleset](https://github.com/Mathews-Tom/revkit/settings/rules): restrict creation to release maintainers and prevent updates and deletions. Configure these controls before adding registry trust.
2. As the crate owner, open [New trusted publisher](https://crates.io/crates/revkit/settings/new-trusted-publisher) and use these values. The workflow field is the **filename**, not the repository-relative path or the display name.

   | Field | Value |
   | --- | --- |
   | Provider | GitHub |
   | Repository owner | `Mathews-Tom` |
   | Repository name | `revkit` |
   | Workflow | `publish-crate.yml` |
   | Environment | `crates-io` |

3. For each subsequent version, update the Cargo version, lockfile and changelog on a reviewed release PR. After it lands and checks pass, create and push **one** approved `v<version>` tag on the reviewed `main` commit. [.github/workflows/publish-crate.yml](../.github/workflows/publish-crate.yml) rejects a tag that does not match the manifest version or point to `main` history. It tests and verifies the package without OIDC, exchanges OIDC for a short-lived crates.io token in the separate publish job, and verifies a clean install from the registry after publication. No long-lived CI token. The `v0.1.0` tag does not trigger this workflow.

[GitHub environment controls](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) · [crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing)

## Prebuilt macOS downloads are a separate channel

Do not attach an ad-hoc-signed archive that Gatekeeper rejects. To ship a downloaded binary, use the approved Apple Developer ID Application identity, hardened runtime and secure timestamp, then [notarize it](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) and verify the actual quarantined download on a clean Apple Silicon Mac. Rebuild from the reviewed release commit, freeze the new checksums, then publish only the verified bytes. The crate workflow does not make GitHub Releases or handle Apple credentials.
