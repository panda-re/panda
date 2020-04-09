class Libdwarf < Formula
  desc "A library for dealing with DWARF debug information"
  homepage "https://www.prevanders.net/dwarf.html"
  url "https://www.prevanders.net/libdwarf-20161124.tar.gz"
  version "20161124"
  sha256 "bd3d6dc7da0509876fb95b8681f165febd898845dc66714aa58e69b8feca988f"

  depends_on "libelf" => :build # if your formula requires any X11/XQuartz components
  depends_on "autoconf" => :build # if your formula requires any X11/XQuartz components

  patch :p2, :DATA

  def install
    # ENV.deparallelize  # if your formula fails when building in parallel
    system "autoconf"

    Dir.chdir("libdwarf") do
      system "autoconf"
    end

    # Remove unrecognized options if warned by configure
    system "./configure", "--disable-debug",
                          "--enable-shared",
                          "--disable-nonshared",
                          "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}"
    system "make", "install" # if this fails, try separate make/make install steps
  end

  test do
    # `test do` will create, run in and delete a temporary directory.
    #
    # This test will fail and we won't accept that! It's enough to just replace
    # "false" with the main program this formula installs, but it'd be nice if you
    # were more thorough. Run the test with `brew test libdwarf`. Options passed
    # to `brew install` such as `--HEAD` also need to be provided to `brew test`.
    #
    # The installed folder is not in the path, so use the entire path to any
    # executables being tested: `system "#{bin}/program", "do", "something"`.
    system "false"
  end
end

__END__
diff -uNr a/dwarf-20161124/Makefile.in b/dwarf-20161124/Makefile.in
--- a/dwarf-20161124/Makefile.in	2016-06-16 11:47:27.000000000 -0400
+++ b/dwarf-20161124/Makefile.in	2016-12-02 18:08:05.000000000 -0500
@@ -68,7 +68,6 @@
 
 basic:
 	cd libdwarf && make
-	cd dwarfdump && make
 
 # The dd target takes the least space and time
 # to build.
@@ -76,14 +75,12 @@
 	cd libdwarf && make
 	cd dwarfdump && make
 all:    basic
-	cd dwarfgen && make
-	cd dwarfexample && make
 
 clean:
 	sh ./CLEANUP
 
 install: all
-	echo "No install provided, see comments in the README"
+	cd libdwarf && make install
 
 distclean:  clean
 	rm -f dwarfgen/config.status 
diff -uNr a/dwarf-20161124/libdwarf/Makefile.in b/dwarf-20161124/libdwarf/Makefile.in
--- a/dwarf-20161124/libdwarf/Makefile.in	2016-11-24 16:15:02.000000000 -0500
+++ b/dwarf-20161124/libdwarf/Makefile.in	2016-12-03 11:27:22.000000000 -0500
@@ -55,7 +55,7 @@
 dwfwall =       @dwfwall@
 dwfsanitize =   @dwfsanitize@
 dwfzlib =       @dwfzlib@
-SONAME =        libdwarf.so.1
+SONAME =        libdwarf.dylib
 CFLAGS =	$(PREINCS) @CPPFLAGS@ @CFLAGS@ $(INCLUDES) $(dwfpic) $(dwfwall) $(dwfsanitize)  $(POSTINCS)
 LDFLAGS =	$(PRELIBS) @LDFLAGS@ $(dwfsanitize) $(POSTLIBS) 
 HOSTCFLAGS =	$(CFLAGS)
@@ -133,9 +133,8 @@
 libdwarf.a: dwarf_names.h dwarf_names.c  $(OBJS) dwarf_names.o
 	$(AR) $(ARFLAGS) $@ $(OBJS)  dwarf_names.o > ar-output-temp
 
-libdwarf.so: dwarf_names.h dwarf_names.c $(OBJS) dwarf_names.o
-	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJS) -Wl,-soname=$(SONAME)  dwarf_names.o $(dwfzlib) -o $@
-	ln libdwarf.so $(SONAME)
+libdwarf.dylib: dwarf_names.h dwarf_names.c $(OBJS) dwarf_names.o
+	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJS) -Wl,-install_name,$(SONAME)  dwarf_names.o -lelf $(dwfzlib) -o $@
 
 none:
 	echo "do nothing " $@
@@ -222,7 +221,10 @@
 	rm -f *~
 
 install: all
-	echo "No install provided, see comments in the README"
+	mkdir -p $(prefix)/include/libdwarf $(prefix)/lib
+	$(INSTALL) libdwarf.h $(prefix)/include/libdwarf/
+	$(INSTALL) dwarf.h $(prefix)/include/libdwarf/
+	$(INSTALL) libdwarf.dylib $(prefix)/lib/
 
 distclean:	clean
 	rm -f config.status config.log config.cache config.h
diff -uNr a/dwarf-20161124/libdwarf/configure.in b/dwarf-20161124/libdwarf/configure.in
--- a/dwarf-20161124/libdwarf/configure.in	2016-09-30 15:45:48.000000000 -0400
+++ b/dwarf-20161124/libdwarf/configure.in	2016-12-02 17:29:17.000000000 -0500
@@ -139,9 +139,9 @@
 
 AC_MSG_CHECKING(build shared)
 AC_ARG_ENABLE(shared,AC_HELP_STRING([--enable-shared],
-		[build shared library libdwarf.so]))
+		[build shared library libdwarf.dylib]))
 AS_IF([ test "x$enable_shared" = "xyes"], [
-   AC_SUBST(build_shared,[libdwarf.so])
+   AC_SUBST(build_shared,[libdwarf.dylib])
    AC_SUBST(dwfpic,[-fPIC])
    AC_MSG_RESULT(yes)
 ], [
