{
  description = "PANDA: Platform for Architecture-Neutral Dynamic Analysis";

  inputs = {
    # nixpkgs with a Wireshark version that works with the network plugin.
    nixpkgs-wireshark = {
      url = "github:NixOS/nixpkgs?rev=e93823409f9e6b8e878edf060b430a14353a28f9";
    };
    libosi-src = {
      url = "github:panda-re/libosi";
      flake = false;
    };
    nix-filter.url = "github:numtide/nix-filter";
  };

  outputs = { self, nixpkgs, nixpkgs-wireshark, libosi-src, nix-filter }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = pkgs.lib;
      pyPkgs = pkgs.python3Packages;
      filter = nix-filter.lib;

      wireshark = (import nixpkgs-wireshark { inherit system; }).wireshark-cli.overrideAttrs
        (prev: {
          outputs = [ "out" "dev" ];
          postInstall = ''
            ${prev.postInstall}

            cp config.h $dev/include/wireshark
          '';
        });

      libdwarf = pkgs.stdenv.mkDerivation rec {
        pname = "libdwarf";
        version = "20210528";

        src = pkgs.fetchurl {
          url = "https://www.prevanders.net/libdwarf-${version}.tar.gz";
          hash = "sha512-4PnIhVQFPubBsTM5YIkRieeCDEpN3DArfmN1Skzc/CrLG0tgg6ci0SBKdemU//NAHswlG4w7JAkPjLQEbZD4cA==";
        };

        configureFlags = [ "--enable-shared" "--disable-nonshared" ];
        buildInputs = with pkgs; [ zlib libelf ];
        outputs = [ "bin" "lib" "dev" "out" ];
        enableParallelBuilding = true;
      };

      libosi = pkgs.stdenv.mkDerivation {
        name = "libosi";
        src = libosi-src;
        buildInputs = with pkgs; [ cmake pkg-config glib ];
      };

      pkgsWithConfig = {
        configFile ? ./panda/plugins/config.panda,
        targetList ? [
          "x86_64-softmmu"
          "i386-softmmu"
          "arm-softmmu"
          "aarch64-softmmu"
          "ppc-softmmu"
          "mips-softmmu"
          "mipsel-softmmu"
          "mips64-softmmu"
        ],
      }: let
        config = builtins.readFile configFile;

        # Is any plugin in `plugins` enabled in config.panda?
        plugin-enabled = plugins:
          (builtins.match "(^|.*\n)(${builtins.concatStringsSep "|" plugins})(\n.*|$)" config) != null;

        panda = pkgs.stdenv.mkDerivation {
          name = "panda";
          src = filter {
            root = ./.;
            # exclude flake files to prevent unnecessary rebuilds
            exclude = [
              ./flake.nix
              ./flake.lock
            ];
          };
          cargoRoot = "panda/plugins";
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./panda/plugins/Cargo.lock;
          };
          buildInputs = (with pkgs; [
            python3
            zlib
            glib
            libarchive
            openssl
            pixman
            capstone
            protobufc
            protobuf
            cargo
            zip
          ])
            ++ (lib.optionals (plugin-enabled [ "network" ]) [ wireshark ])
            ++ (lib.optionals (plugin-enabled [ "wintrospection" ]) [ libosi ])
            ++ (lib.optionals (plugin-enabled [ "pri_dwarf" ]) [ libdwarf ])
            ++ (lib.optionals (plugin-enabled [ "pri_dwarf" "dwarf2" ]) [ pkgs.libelf ])
            ++ (lib.optionals (plugin-enabled [ "dwarf2" "syscalls_logger" ]) [ pkgs.jsoncpp ])
            ++ (lib.optionals (plugin-enabled [ "osi_linux" ]) [ pkgs.curl ])
            ++ (with pyPkgs; [ pycparser libfdt setuptools ]);
          nativeBuildInputs = [ pkgs.pkg-config pkgs.rustPlatform.cargoSetupHook ];
          propagatedBuildInputs = with pyPkgs; [ cffi colorama ];
          enableParallelBuilding = true;
          patches = [
            (pkgs.writeText "fix-rpath-error.patch" ''
              diff --git a/Makefile b/Makefile
              index cc2064de42..8b357e9a9a 100644
              --- a/Makefile
              +++ b/Makefile
              @@ -653,7 +653,6 @@ newtoobig=$(shell oldrp="$(rppart)" ; oldrplen=`expr $''${$(number_sign)oldrp} - 6
               endif

               install: all $(if $(BUILD_DOCS),install-doc) install-datadir install-localstatedir
              -ifeq ($(newtoobig), false)
               ifneq ($(TOOLS),)
               	$(call install-prog,$(subst qemu-ga,qemu-ga$(EXESUF),$(TOOLS)),$(DESTDIR)$(bindir))
               endif
              @@ -684,9 +683,6 @@ endif
               	for d in $(TARGET_DIRS); do \
               	$(MAKE) $(SUBDIR_MAKEFLAGS) TARGET_DIR=$$d/ -C $$d $@ || exit 1 ; \
                       done
              -else
              -	$(error new RPATH too long - cannot adjust .so files for installation)
              -endif

               # various test targets
               test speed: all
            '')
          ];
          postPatch = ''
            patchShebangs .
            substituteInPlace rules.mak \
              --replace 'std=c++11' 'std=c++17'
            substituteInPlace panda/plugins/pri_dwarf/*.{h,cpp} \
              --replace '<libdwarf/' '<'
            cp "${configFile}" panda/plugins/config.panda
          '' + lib.optionalString (plugin-enabled [ "network" ]) ''
            substituteInPlace panda/plugins/network/Makefile \
              --replace '/usr/include/wireshark' '${wireshark.dev}/include/wireshark'
          '';
          preConfigure = "mkdir build && cd build";
          configureScript = "../configure";
          configureFlags = [
            "--target-list=${builtins.concatStringsSep "," targetList}"
            "--disable-numa"
            # TODO: "--enable-llvm"
          ];
          postInstall = ''
            rm -rf $out/lib/panda/*/{cosi,cosi_strace,gdb,snake_hook,rust_skeleton}
            # Generated files for PyPANDA (built separately)
            (cd ../panda/python/core && python ./create_panda_datatypes.py)
            mkdir "$out/lib/panda/python"
            cp -r ../panda/python/core/pandare/{autogen,include,plog_pb2.py} "$out/lib/panda/python"
            rm -r "$out/lib/python3"
          '';
        };

        pypanda = pyPkgs.buildPythonPackage {
          pname = "pandare";
          version = "1.8";
          format = "setuptools";
          src = ./panda/python/core;

          propagatedBuildInputs = with pyPkgs; [
            cffi
            protobuf
            colorama
          ];

          nativeBuildInputs = [
            pyPkgs.setuptools_scm
          ];

          buildInputs = [ panda ];

          postPatch = ''
            substituteInPlace setup.py \
              --replace 'install_requires=parse_requirements("requirements.txt"),' ""
            substituteInPlace pandare/utils.py \
              --replace '/usr/local/bin/' '${panda}'
            substituteInPlace pandare/panda.py \
              --replace 'self.plugin_path = plugin_path' "self.plugin_path = plugin_path or pjoin('${panda}', 'lib/panda', arch)" \
              --replace 'if libpanda_path:' 'if True:' \
              --replace '= libpanda_path' "= libpanda_path or pjoin('${panda}', 'bin', f'libpanda-{arch}.so')" \
              --replace 'realpath(pjoin(self.get_build_dir(), "pc-bios"))' "pjoin('${panda}', 'share/panda')"

            # Use auto-generated files from separate derivation above.
            rm create_panda_datatypes.py
            rm -r pandare/{include,autogen}
            cp -rt pandare "${panda}"/lib/panda/python/{include,autogen,plog_pb2.py}
          '';
        };
      in {
        inherit panda pypanda;
      };

      pkgsDefaultConfig = pkgsWithConfig {};

    in {
      packages.x86_64-linux = {
        default = pkgsDefaultConfig.panda;
        pypanda = pkgsDefaultConfig.pypanda;
        pkgsWithConfig = pkgsWithConfig;
        wireshark = wireshark;
        libdwarf = libdwarf;
      };
    };
}
