# The approve and approve-askpass binaries, without an askpass dialog. approve
# finds `askpass` on PATH, or the system wraps it with APPROVE_ASKPASS set.
{ lib, rustPlatform, expectedSsh ? null }:

rustPlatform.buildRustPackage {
  pname = "approve";
  version = (lib.importTOML ./Cargo.toml).package.version;

  # Only the files cargo reads, so editing the flake or docs reuses the build.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./tests ];
  };
  cargoLock.lockFile = ./Cargo.lock;

  # SSH mode's adapter refuses passphrase prompts from any other parent executable.
  env = lib.optionalAttrs (expectedSsh != null) { APPROVE_SSH = expectedSsh; };

  meta = {
    description = "Review caller explanations and observed facts in a sudo or SSH askpass prompt";
    license = lib.licenses.mit;
    mainProgram = "approve";
  };
}
