ODIRS=$(wildcard obj-*)
TARGETS=$(subst obj-,,$(ODIRS))

all: requirements info build

requirements:
	@which xsltproc &>/dev/null || ( echo ; echo "Please install libxslt2"; \
			echo; exit 1 )

info:
	@echo "Building OpenBIOS for $(TARGETS)"

clean:
	@echo "Cleaning up..."
	@for dir in $(ODIRS); do \
		$(MAKE) -C $$dir clean; \
	done

build:
	@printf "Building..."
	@for dir in $(ODIRS); do \
		$(MAKE) -C $$dir > $$dir/build.log 2>&1 && echo "ok." || \
		( echo "error:"; tail -15 $$dir/build.log; exit 1 ) \
	done

build-verbose:
	@echo "Building..."
	@for dir in $(ODIRS); do \
		$(MAKE) -C $$dir || exit 1; \
	done

run:
	@echo "Running..."
	@for dir in $(ODIRS); do \
		$$dir/openbios-unix $$dir/openbios-unix.dict; \
	done


# The following two targets will only work on x86 so far.
# 
$(ODIR)/openbios.iso: $(ODIR)/openbios.multiboot $(ODIR)/openbios-x86.dict
	@mkisofs -input-charset UTF-8 -r -b boot/grub/stage2_eltorito -no-emul-boot \
	-boot-load-size 4 -boot-info-table -o $@ utils/iso $^

runiso: $(ODIR)/openbios.iso
	qemu -cdrom $^
