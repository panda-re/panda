Plugin: taint_compute_numbers
===========

Summary
-------

Arguments
---------



Dependencies
------------

            PPP_REG_CB("taint", before_execute_taint_ops, taint_compute_numbers_before_execute_taint_ops);
            PPP_REG_CB("taint", after_execute_taint_ops, taint_compute_numbers_after_execute_taint_ops);
            PPP_REG_CB("taint", on_load, taint_compute_numbers_on_load);    
  bool x = init_taint_api();  

APIs and Callbacks
------------------





Example
-------

