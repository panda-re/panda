{
  description = "PANDA: Platform for Architecture-Neutral Dynamic Analysis";

  inputs = {
    libosi-src = {
      url = "github:panda-re/libosi";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, libosi-src }: {

    packages.x86_64-linux.default = let

      pkgs = import nixpkgs {
        system = "x86_64-linux";
        config.permittedInsecurePackages = [ "libdwarf-20210528" ];
      };

      pyPkgs = pkgs.python3Packages;

      # We need to use an older version of wireshark, since 2.5.1 breaks the network plugin
      wireshark = (import (pkgs.fetchFromGitHub {
        owner = "NixOS";
        repo = "nixpkgs";
        rev = "a7e0fb6ffcae252bdd0c85928f179c74c3492a89";
        hash = "sha256-RdXz/U0JJvsABkGWhF4Cukl4KuZvOJvkci7EuizKid0=";
      }) { localSystem.system = "x86_64-linux"; }).wireshark-cli.overrideAttrs
        (prev: {
          outputs = [ "out" "dev" ];
          postInstall = ''
            ${prev.postInstall}

            # Install headers
            mkdir $dev/include/wireshark/{epan/{wmem,ftypes,dfilter},wsutil,wiretap} -pv
            cp config.h $dev/include/wireshark
            cp ../ws_*.h $dev/include/wireshark
            cp ../epan/*.h $dev/include/wireshark/epan/
            cp ../epan/wmem/*.h $dev/include/wireshark/epan/wmem/
            cp ../epan/ftypes/*.h $dev/include/wireshark/epan/ftypes/
            cp ../epan/dfilter/*.h $dev/include/wireshark/epan/dfilter/
            cp ../wsutil/*.h $dev/include/wireshark/wsutil/
            cp ../wiretap/*.h $dev/include/wireshark/wiretap
          '';
        });

      libosi = pkgs.stdenv.mkDerivation {
        name = "libosi";
        src = libosi-src;
        buildInputs = with pkgs; [ cmake pkg-config glib ];
      };

      default = pkgs.stdenv.mkDerivation {
        name = "panda";
        src = ./.;
        cargoRoot = "panda/plugins";
        cargoDeps = pkgs.rustPlatform.importCargoLock {
          lockFile = ./panda/plugins/Cargo.lock;
        };
        buildInputs = (with pkgs; [
          pkg-config
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
          curl
          libdwarf_20210528
          zip
          libelf
          jsoncpp
        ]) ++ [ wireshark libosi ]
          ++ (with pyPkgs; [ pycparser libfdt setuptools ]);
        nativeBuildInputs = [ pkgs.rustPlatform.cargoSetupHook ];
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
          substituteInPlace panda/plugins/network/Makefile \
            --replace '/usr/include/wireshark' '${wireshark.dev}/include/wireshark'
          substituteInPlace panda/plugins/pri_dwarf/*.{h,cpp} \
            --replace '<libdwarf/' '<'
          substituteInPlace panda/python/core/pandare/utils.py \
            --replace \
            'pjoin(python_package, arch_dir), pjoin(local_build, arch_dir)' \
            'realpath(pjoin(dirname(__file__), "../../../../bin"))'
          substituteInPlace panda/python/core/pandare/panda.py \
            --replace 'self.plugin_path = plugin_path' "self.plugin_path = plugin_path or pjoin('$out', 'lib/panda', arch)" \
            --replace 'if libpanda_path:' 'if True:' \
            --replace '= libpanda_path' "= libpanda_path or pjoin('$out', 'bin', f'libpanda-{arch}.so')" \
            --replace 'realpath(pjoin(self.get_build_dir(), "pc-bios"))' "pjoin('$out', 'share/panda')"
        '';
        preConfigure = "mkdir build && cd build";
        configureScript = "../configure";
        configureFlags = [
          "--target-list=${
            builtins.concatStringsSep "," [
              "x86_64-softmmu"
              "i386-softmmu"
              "arm-softmmu"
              "aarch64-softmmu"
              "ppc-softmmu"
              "mips-softmmu"
              "mipsel-softmmu"
              "mips64-softmmu"
            ]
          }"
          "--disable-numa"
          # TODO: "--enable-llvm"
        ];
        postInstall = ''
          rm -r $out/lib/panda/*/{cosi,cosi_strace,gdb,snake_hook,rust_skeleton}
          (
            cd ../panda/python/core
            python3 setup.py install --prefix "$out"
          )
        '';
      };

    in default;

  };
}
