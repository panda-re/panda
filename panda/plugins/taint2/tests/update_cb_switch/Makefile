INCDIR1 = ../../../../../../../install/include
INCDIR2 = ../../../../../include
INCDIR3 = ../../../../../../build-panda
INCDIR4 = /usr/include/glib-2.0
INCDIR5 = /usr/lib/x86_64-linux-gnu/glib-2.0/include

INCDIRS = -I$(INCDIR1) -I$(INCDIR2) -I$(INCDIR3) -I$(INCDIR4) -I$(INCDIR5)

LDFLAGS = -Wl,-L../../../../../../../install/lib -Wl,-lLLVMCore -Wl,-lLLVMSupport -Wl,-ldl -Wl,-lpthread

update_cb_switch: update_cb_switch.c
	g++ -O0 -g update_cb_switch.c $(INCDIRS) -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -o update_cb_switch $(LDFLAGS)

clean:
	rm -f update_cb_switch
