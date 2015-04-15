
# assembles pandalog.proto file
./pp.py

# generates pandalog c protobuf code
pandalog_proto=./panda/pandalog.proto
echo "generating pandalog protobuf code"
protoc-c --c_out=. $pandalog_proto

# generates python and c volatility interface code
vol_int_proto_dir=../volatility
vol_int_proto=$vol_int_proto_dir/panda_vol_int.proto
echo "generating volatility_interface protobuf code"
protoc-c -I=$vol_int_proto_dir --c_out=./panda $vol_int_proto
protoc -I=$vol_int_proto_dir --python_out=../volatility $vol_int_proto
protoc -I=$vol_int_proto_dir --cpp_out=./panda $vol_int_proto
