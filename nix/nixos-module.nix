{mkCraneLib}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkDefault mkEnableOption mkIf mkMerge mkOption optional types;

  craneLib = mkCraneLib pkgs;
  xguard-client = pkgs.callPackage ./package.nix {inherit pkgs craneLib;};

  svcCfg = config.services.xguard-client-daemon;
  clientCfg = config.programs.xguard-client;
in {
  options.services.xguard-client-daemon = {
    enable = mkEnableOption "XGuard VPN client background service (required by both the desktop client and CLI)";

    package = mkOption {
      type = types.package;
      default = xguard-client;
      description = "Package that provides the xguard-service binary.";
    };

    logLevel = mkOption {
      type = types.str;
      default = "info";
      description = "Log level for xguard-service (--log-level)";
    };

    logDir = mkOption {
      type = types.str;
      default = "/var/log/xguard-service";
      description = "Directory for xguard-service logs (--log-dir)";
    };

    statsPeriod = mkOption {
      type = types.int;
      default = 30;
      description = "Interval in seconds for interface statistics updates (--stats-period)";
    };
  };

  options.programs.xguard-client = {
    enable = mkEnableOption "XGuard VPN desktop client";

    package = mkOption {
      type = types.package;
      default = xguard-client;
      description = "xguard-client package to use";
    };
  };

  config = mkMerge [
    # Auto-enable the daemon when the desktop client is enabled.
    # Users can override with services.xguard-client-daemon.enable = false.
    {
      services.xguard-client-daemon.enable = mkDefault clientCfg.enable;
    }

    # Add the relevant packages to the system PATH.
    (mkIf (svcCfg.enable || clientCfg.enable) {
      environment.systemPackages =
        []
        ++ optional svcCfg.enable svcCfg.package
        ++ optional clientCfg.enable clientCfg.package;
    })

    # Daemon-only configuration: systemd service and dedicated group.
    (mkIf svcCfg.enable {
      systemd.services.xguard-service = {
        description = "XGuard VPN Service";
        documentation = ["https://docs.xguard.local"];
        wantedBy = ["multi-user.target"];
        wants = ["network-online.target"];
        after = ["network-online.target"];
        serviceConfig = {
          Group = "xguard";
          ExecStart = "${svcCfg.package}/bin/xguard-service --log-level ${svcCfg.logLevel} --log-dir ${svcCfg.logDir} --stats-period ${toString svcCfg.statsPeriod}";
          ExecReload = "kill -HUP $MAINPID";
          KillMode = "process";
          KillSignal = "SIGINT";
          LimitNOFILE = 65536;
          LimitNPROC = "infinity";
          Restart = "on-failure";
          RestartSec = 2;
          TasksMax = "infinity";
          OOMScoreAdjust = -1000;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          RestrictRealtime = true;
          LockPersonality = true;
        };
      };

      users.groups.xguard = {};
    })
  ];
}
