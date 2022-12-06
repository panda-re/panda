t = []
foreach i : ['qpp_srv', 'qpp_client']
  t += shared_module(i, files(i + '.c'),
                     include_directories: '../../include/qemu',
                     dependencies: glib)
endforeach
alias_target('test-plugins-qpp', t)
