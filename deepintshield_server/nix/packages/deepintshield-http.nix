{
  pkgs,
  inputs,
  src,
  version,
  deepintshield-ui,
}:
let
  lib = pkgs.lib;

  # DeepIntShield requires Go 1.26 (go.mod/go.work). Force Go 1.26 for buildGoModule.
  buildGoModule = pkgs.callPackage "${inputs.nixpkgs}/pkgs/build-support/go/module.nix" {
    go = pkgs.go_1_26 or pkgs.go;
  };

  transportsLocalReplaces = ''
    if [ -f transports/go.mod ]; then
      cat >> transports/go.mod <<'EOF'

    replace github.com/deepint-shield/ai-security/core => ../core
    replace github.com/deepint-shield/ai-security/framework => ../framework
    replace github.com/deepint-shield/ai-security/plugins/governance => ../plugins/governance
    replace github.com/deepint-shield/ai-security/plugins/litellmcompat => ../plugins/litellmcompat
    replace github.com/deepint-shield/ai-security/plugins/logging => ../plugins/logging
    replace github.com/deepint-shield/ai-security/plugins/otel => ../plugins/otel
    replace github.com/deepint-shield/ai-security/plugins/semanticcache => ../plugins/semanticcache
    replace github.com/deepint-shield/ai-security/plugins/telemetry => ../plugins/telemetry
    EOF
    fi
  '';
in
buildGoModule {
  pname = "deepintshield-http";
  inherit version;
  inherit src;

  modRoot = "transports";
  subPackages = [ "deepintshield-http" ];
  vendorHash = "sha256-Ck1cwv/DYI9EXmp7U2ZSNXlU+Qok8BFn5bcN1Pv7Nmc=";

  doCheck = false;

  overrideModAttrs = final: prev: {
    postPatch = (prev.postPatch or "") + transportsLocalReplaces;
  };

  env = {
    CGO_ENABLED = "1";
  };

  nativeBuildInputs = with pkgs; [
    pkg-config
    gcc
  ];
  buildInputs = [ pkgs.sqlite ];

  postPatch = transportsLocalReplaces;

  preBuild = ''
    # Provide UI assets for //go:embed all:ui
    rm -rf deepintshield-http/ui
    mkdir -p deepintshield-http/ui
    if [ -d "${deepintshield-ui}/ui" ]; then
      cp -R --no-preserve=mode,ownership,timestamps "${deepintshield-ui}/ui/." deepintshield-http/ui/
    else
      printf '%s\n' '<!doctype html><meta charset="utf-8"><title>DeepIntShield</title>' > deepintshield-http/ui/index.html
    fi
  '';

  ldflags = [
    "-s"
    "-w"
    "-X main.Version=${version}"
  ];

  meta = {
    mainProgram = "deepintshield-http";
    description = "DeepIntShield HTTP gateway";
    homepage = "https://github.com/deepint-shield/ai-security";
    license = lib.licenses.asl20;
  };
}