# generates c protobuf ode
pproto=./panda/src/plog.proto

# assembles pandalog.proto file
panda/scripts/pp.py $pproto

echo "generating protobuf code with protoc-c"
protoc-c --c_out=. $pproto
protoc --python_out=. $pproto

sed -i 's/#include "panda\/src\/plog.pb-c.h"/#include "..\/include\/panda\/plog.pb-c.h"/g' panda/src/plog.pb-c.c

mv panda/src/plog.pb-c.h panda/include/panda
