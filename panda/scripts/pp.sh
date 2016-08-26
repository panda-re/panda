# generates c protobuf code

# assembles pandalog.proto file
$(dirname $0)/pp.py "$1" "$2"

echo "generating protobuf code with protoc-c"
echo protoc-c --proto_path=$(dirname $1) --c_out=. "$1"
protoc-c --proto_path=$(dirname $1) --c_out=. "$1"
echo protoc --proto_path=$(dirname $1) --python_out=. "$1"
protoc --proto_path=$(dirname $1) --python_out=. "$1"
