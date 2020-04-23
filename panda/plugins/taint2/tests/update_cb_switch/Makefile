INCDIR1 = ../../../../../../../install/include
INCDIR2 = ../../../../../include
INCDIR3 = ../../../../../../build-panda
INCDIR4 = /usr/include/glib-2.0
INCDIR5 = /usr/lib/x86_64-linux-gnu/glib-2.0/include
INCDIR6 = ../../

INCDIRS = -I$(INCDIR1) -I$(INCDIR2) -I$(INCDIR3) -I$(INCDIR4) -I$(INCDIR5) -I$(INCDIR6)

#LDFLAGS = -Wl,-L../../../../../../../install/lib -Wl,-lLLVMCore -Wl,-lLLVMSupport -Wl,-ldl -Wl,-lpthread,-lcurses

LLVM_CONFIG = ../../../../../../../install/bin/llvm-config

LDFLAGS = -L$(shell $(LLVM_CONFIG) --libdir) $(shell $(LLVM_CONFIG) --libs) -lcurses -ldl -pthread

update_cb_switch: update_cb_switch.cpp
	$(shell $(LLVM_CONFIG) --bindir)/clang++ -O0 -g update_cb_switch.cpp $(INCDIRS) -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -o update_cb_switch $(LDFLAGS)

clean:
	rm -f update_cb_switch
