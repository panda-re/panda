class LlvmAT33 < Formula
  desc "Next-gen compiler infrastructure"
  homepage "http://llvm.org/"
  revision 3

  stable do
    url "http://llvm.org/releases/3.3/llvm-3.3.src.tar.gz"
    sha256 "68766b1e70d05a25e2f502e997a3cb3937187a3296595cf6e0977d5cd6727578"

    resource "clang" do
      url "http://llvm.org/releases/3.3/cfe-3.3.src.tar.gz"
      sha256 "b1b55de4ab3a57d3e0331a83e0284610191c77d924e3446498d9113d08dfb996"
    end

    resource "clang-tools-extra" do
      url "http://llvm.org/releases/3.3/clang-tools-extra-3.3.src.tar.gz"
      sha256 "728210c389dd03b8dd4d7a81c41a973c971d52c25b2f9b8996eb701ee8daf998"
    end

    resource "compiler-rt" do
      url "http://llvm.org/releases/3.3/compiler-rt-3.3.src.tar.gz"
      sha256 "0e2f3180d6316e6c43f064fdd406c5c6515e682c5f31c57c28335b68c7525423"
    end

    resource "polly" do
      url "http://llvm.org/releases/3.3/polly-3.3.src.tar.gz"
      sha256 "89e1f0b510a2cd02c4a0ed447bc68fb93229a7a9dbcd587c882596fc5a09c413"
    end

    resource "libcxx" do
      url "http://llvm.org/releases/3.3/libcxx-3.3.src.tar.gz"
      sha256 "c403ed18d2992719c794cdd760dc87a948b62a7c2a07beb39eb984dfeb1679f1"
    end
  end

  # Fix Makefile bug concerning MacOSX >= 10.10
  # See: http://llvm.org/bugs/show_bug.cgi?id=19951
  patch :DATA

  option :universal
  option "with-asan", "Include support for -faddress-sanitizer (from compiler-rt)"
  option "without-shared", "Don't build LLVM as a shared library"
  option "with-all-targets", "Build all target backends"
  option "with-assertions", "Slows down LLVM, but provides more debug information"
  option "without-build", "Export a tarball of the full source tree without compiling"

  keg_only :versioned_formula
  depends_on "pkg-config" => :build
  depends_on "gmp"
  depends_on "isl@0.11"
  depends_on "libffi" => :recommended
  depends_on "cloog" => :optional

  # LLVM installs its own standard library which confuses stdlib checking.
  cxxstdlib_check :skip

  def install
    ### copy resources to build dir ##################################
    (buildpath/"tools/clang").install resource("clang")
    (buildpath/"projects/libcxx").install resource("libcxx")
    (buildpath/"tools/polly").install resource("polly")
    (buildpath/"tools/clang/tools/extra").install resource("clang-tools-extra")
    (buildpath/"projects/compiler-rt").install resource("compiler-rt") if build.with? "asan"

    if build.universal?
      ENV.permit_arch_flags
      ENV["UNIVERSAL"] = "1"
      ENV["UNIVERSAL_ARCH"] = Hardware::CPU.universal_archs.join(" ")
    end

    ENV["REQUIRES_RTTI"] = "1"
    ENV["PKG_CONFIG_PATH"] = "#{Formula["isl@0.11"].lib}/pkgconfig:#{Formula["cloog"].lib}/pkgconfig:#{Formula["libffi"].lib}/pkgconfig"


    ### configuration script arguments ###############################
    args = [
      "--prefix=#{prefix}",
      "--enable-optimized",
      "--disable-bindings",
      "--enable-libcpp",
      "--enable-cxx11",
      "--with-gmp=#{Formula["gmp"].opt_prefix}",
      "--with-isl=#{Formula["isl@0.11"].opt_prefix}",
      "--enable-libffi",
    ]

    if build.include? "all-targets"
      args << "--enable-targets=all"
    else
      args << "--enable-targets=host"
    end

    args << "--enable-shared" unless build.include? "disable-shared"
    args << "--disable-assertions" unless build.include? "enable-assertions"
    args << "--enable-libffi" if build.with? "libffi"
    args << "--with-cloog=#{Formula["cloog"].opt_prefix}" if build.with? "cloog"


    ### build environment variables ##################################
    pkg_config = [
      "#{Formula["isl@0.11"].lib}/pkgconfig",
    ]

    pkg_config << "#{Formula["cloog"].lib}/pkgconfig" if build.with? "cloog"
    pkg_config << "#{Formula["libffi"].lib}/pkgconfig" if build.with? "libffi"

    if build.universal?
      ENV.permit_arch_flags
      ENV["UNIVERSAL"] = "1"
      ENV["UNIVERSAL_ARCH"] = Hardware::CPU.universal_archs.join(" ")
    end

    ENV["REQUIRES_RTTI"] = "1"
    ENV["PKG_CONFIG_PATH"] = pkg_config.join(":")


    ### build and install ############################################
    # Make a tarball, show configuration and fail.
    if build.include? "without-build"
      ver = "#{version}".split("-")[0]
      srctarball = "#{var}/llvm-#{ver}.src.tar.gz"
      configcmd = "#{var}/llvm-#{ver}-configure.sh"
      system "tar", "-zcf", "#{srctarball}", '-C', (buildpath/".."), "."
      File.open(configcmd, 'w'){ |f|
        f.write("#!/usr/bin/env bash\n")
        ENV.each do |k, v|
          f.write(sprintf("export %s=\"%s\"\n", k, v))
        end
        f.write(sprintf("./configure %s\n", args.join(" \\\n\t")))
        File.chmod(0755, configcmd)
      }
      ohai "Source tarball: #{srctarball}"
      ohai "Configuration script: #{configcmd}"
      ohai "All done. Aborting."
      system "false"
    end

    system "./configure", *args
    system "make", "VERBOSE=1"
    system "make", "VERBOSE=1", "install"
  end

  test do
    system "#{bin}/llvm-config-#{ver}", "--version"
  end
end

__END__
diff --git a/Makefile.rules b/Makefile.rules
index f0c542b..f4da038 100644
--- a/Makefile.rules
+++ b/Makefile.rules
@@ -571,9 +571,9 @@ ifeq ($(HOST_OS),Darwin)
   DARWIN_VERSION := `sw_vers -productVersion`
  endif
   # Strip a number like 10.4.7 to 10.4
-  DARWIN_VERSION := $(shell echo $(DARWIN_VERSION)| sed -E 's/(10.[0-9]).*/\1/')
+  DARWIN_VERSION := $(shell echo $(DARWIN_VERSION)| sed -E 's/(10.[0-9]+).*/\1/')
   # Get "4" out of 10.4 for later pieces in the makefile.
-  DARWIN_MAJVERS := $(shell echo $(DARWIN_VERSION)| sed -E 's/10.([0-9]).*/\1/')
+  DARWIN_MAJVERS := $(shell echo $(DARWIN_VERSION)| sed -E 's/10.([0-9]+).*/\1/')
 
   LoadableModuleOptions := -Wl,-flat_namespace -Wl,-undefined,suppress
   SharedLinkOptions := -dynamiclib
@@ -602,6 +602,17 @@ ifdef SHARED_LIBRARY
 ifneq ($(HOST_OS), $(filter $(HOST_OS), Cygwin MingW))
 ifneq ($(HOST_OS),Darwin)
   LD.Flags += $(RPATH) -Wl,'$$ORIGIN'
+else
+  ifeq ($(DARWIN_MAJVERS),4)
+    LD.Flags += -Wl,-dylib_install_name
+  else
+    LD.Flags += -Wl,-install_name
+  endif
+  ifdef LOADABLE_MODULE
+    LD.Flags += -Wl,"$(PROJ_libdir)/$(LIBRARYNAME)$(SHLIBEXT)"
+  else
+    LD.Flags += -Wl,"$(PROJ_libdir)/$(SharedPrefix)$(LIBRARYNAME)$(SHLIBEXT)"
+  endif
 endif
 endif
 endif
diff --git a/tools/llvm-shlib/Makefile b/tools/llvm-shlib/Makefile
index 6d6c6e9..c3d4d67 100644
--- a/tools/llvm-shlib/Makefile
+++ b/tools/llvm-shlib/Makefile
@@ -53,14 +53,6 @@ ifeq ($(HOST_OS),Darwin)
     LLVMLibsOptions    := $(LLVMLibsOptions)  \
                          -Wl,-dead_strip \
                          -Wl,-seg1addr -Wl,0xE0000000 
-
-    # Mac OS X 10.4 and earlier tools do not allow a second -install_name on command line
-    DARWIN_VERS := $(shell echo $(TARGET_TRIPLE) | sed 's/.*darwin\([0-9]*\).*/\1/')
-    ifneq ($(DARWIN_VERS),8)
-       LLVMLibsOptions    := $(LLVMLibsOptions)  \
-                            -Wl,-install_name \
-                            -Wl,"@executable_path/../lib/lib$(LIBRARYNAME)$(SHLIBEXT)"
-    endif
 endif
 
 ifeq ($(HOST_OS), $(filter $(HOST_OS), Linux FreeBSD OpenBSD GNU Bitrig))
diff --git a/tools/lto/Makefile b/tools/lto/Makefile
index ab2e16e..dd2e13a 100644
--- a/tools/lto/Makefile
+++ b/tools/lto/Makefile
@@ -42,14 +42,6 @@ ifeq ($(HOST_OS),Darwin)
                          -Wl,-dead_strip \
                          -Wl,-seg1addr -Wl,0xE0000000 
 
-    # Mac OS X 10.4 and earlier tools do not allow a second -install_name on command line
-    DARWIN_VERS := $(shell echo $(TARGET_TRIPLE) | sed 's/.*darwin\([0-9]*\).*/\1/')
-    ifneq ($(DARWIN_VERS),8)
-       LLVMLibsOptions    := $(LLVMLibsOptions)  \
-                            -Wl,-install_name \
-                            -Wl,"@executable_path/../lib/lib$(LIBRARYNAME)$(SHLIBEXT)"
-    endif
-
     # If we're doing an Apple-style build, add the LTO object path.
     ifeq ($(RC_XBS),YES)
        TempFile        := $(shell mkdir -p ${OBJROOT}/dSYMs ; mktemp ${OBJROOT}/dSYMs/llvm-lto.XXXXXX)
diff -u a/runtime/libprofile/Makefile b/runtime/libprofile/Makefile
--- a/runtime/libprofile/Makefile	2019-08-18 22:12:09.096468645 +0200
+++ b/runtime/libprofile/Makefile	2019-08-18 22:12:18.403583367 +0200
@@ -38,15 +38,6 @@
                          -Wl,-dead_strip \
                          -Wl,-seg1addr -Wl,0xE0000000 
 
-    # Mac OS X 10.4 and earlier tools do not allow a second -install_name on
-    # command line.
-    DARWIN_VERS := $(shell echo $(TARGET_TRIPLE) | sed 's/.*darwin\([0-9]*\).*/\1/')
-    ifneq ($(DARWIN_VERS),8)
-       LLVMLibsOptions    := $(LLVMLibsOptions) \
-                            -Wl,-install_name \
-                            -Wl,"@executable_path/../lib/lib$(LIBRARYNAME)$(SHLIBEXT)"
-    endif
-
     # If we're doing an Apple-style build, add the LTO object path.
     ifeq ($(RC_XBS),YES)
        TempFile           := $(shell mkdir -p ${OBJROOT}/dSYMs ; mktemp ${OBJROOT}/dSYMs/profile_rt-lto.XXXXXX)
