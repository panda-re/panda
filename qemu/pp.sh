
# assembles pandalog.proto file
./pp.py

# generates c protobuf ode
pproto=./panda/pandalog.proto
echo "generating protobuf code with protoc-c"
protoc-c --c_out=. $pproto
protoc --python_out=. $pproto

