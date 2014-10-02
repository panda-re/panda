
#ifndef __PANDA_PLUGIN_PLUGIN_H_
#define __PANDA_PLUGIN_PLUGIN_H_

#include <dlfcn.h>

/*

  Facilities for plugin-architecture to plugins.  
  
  Let's say you are writing plugin B.
  But you really want to use the functionality of plugin A.  If plugin A has been
  written with this sort of thing in mind and employing the facilities herein, 
  you can just write some little function in B and register it to be called at a 
  particular point in plugin A.  

  Consider the interaction between tstringsearch and stringsearch plugins.  
  stringsearch dynamically monitors all tap points (load and store instructions) 
  and determines when the data streaming through any of them matches any of a
  number of search strings.  stringsearch has one pluggable point, upon string match.
  We can register a function to be called when that match occurs.  tstringsearch
  does precisely this, handing stringsearch the function tstringsearch_match
  to be called whenever there is a match.  

*/




/****************************************************************
This stuff gets used in "plugin A", i.e., the plugin inside of which
we want to be able to register callbacks.  Thus, there are facilities
for adding callbacks to an array but also for calling all the callbacks
in the list at the right point.
****************************************************************/




  
#define PPP_MAX_CB 256


// use this in extern "C" { blob at head of A plugin
#define PPP_PROT_REG_CB(cb_name) \
void ppp_add_cb_##cb_name(cb_name##_t fptr) ;				\
void ppp_add_cb_##cb_name##_slot(cb_name##_t fptr, int slot_num) ;     




/*
  employ this somewhere in the plugin near the top.
  1. creates global array of fn pointers for this plugin
  2. creates global int tracking the number of plugins
  3. create fn for registering a callback
  4. creates a fn for registering a callback in a particlular slot.  Since the
  callbacks are in an array and we will call them in order, one may want to
  take advantage of that fact by ordering them carefully.  However, be careful
  as there isnt any attempt, here, to detect if you leave a slot empty
*/

#define PPP_CB_BOILERPLATE(cb_name)		\
cb_name##_t ppp_##cb_name##_cb[PPP_MAX_CB];	\
int ppp_##cb_name##_num_cb = 0;				\
							\
void ppp_add_cb_##cb_name(cb_name##_t fptr) {			\
  assert (ppp_##cb_name##_num_cb < PPP_MAX_CB);				\
  ppp_##cb_name##_cb[ppp_##cb_name##_num_cb] = fptr;			\
  ppp_##cb_name##_num_cb += 1;						\
}									\
									\
void ppp_add_cb_##cb_name##_slot(cb_name##_t fptr, int slot_num) {	\
  assert (slot_num < PPP_MAX_CB);					\
  ppp_##cb_name##_cb[slot_num] = fptr;					\
  ppp_##cb_name##_num_cb = MAX(slot_num, ppp_##cb_name##_num_cb);	\
}									


/*
  And employ this where you want the callback functions to be called 
*/
 
#define PPP_RUN_CB(cb_name, ...)					\
  {									\
    int ppp_cb_ind;							\
    for (ppp_cb_ind = 0; ppp_cb_ind < ppp_##cb_name##_num_cb; ppp_cb_ind++) { \
      if (ppp_##cb_name##_cb[ppp_cb_ind] != NULL) {			\
	ppp_##cb_name##_cb[ppp_cb_ind]( __VA_ARGS__ ) ;			\
      }									\
    }									\
  }



/****************************************************************
This stuff gets used in "plugin B", i.e., the plugin that wants
to add a callback to be run inside of plugin A.
****************************************************************/


// Use this in the very begining of plugin B's init_plugin fn 
// 
#define PPP_REG_CB(other_plugin, cb_name, cb_func)			\
  {									\
    dlerror();								\
    void *op = panda_get_plugin_by_name("panda_" other_plugin ".so");	\
    if (!op) {								\
      printf("In trying to add plugin callback, couldn't load %s plugin\n", other_plugin); \
      assert (op);							\
    }									\
    void (*add_cb)(cb_name##_t fptr) = (void (*)(cb_name##_t)) dlsym(op, "ppp_add_cb_" #cb_name); \
    assert (add_cb != 0); \
    add_cb (cb_func);							\
  }




#endif // __PANDA_PLUGIN_PLUGIN_H_
