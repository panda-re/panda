
# creates pandalog code
pproto=./panda/pandalog.proto
cat > $pproto  <<EOF
syntax = "proto2";
package panda;
message LogEntry {
required uint64 pc = 1;    
required uint64 instr = 2;
EOF
for d in `cat panda_plugins/config.panda`   
do
    ppf=panda_plugins/$d/$d.proto
    if [ -f $ppf ]
    then
        echo "adding pandalog spec for $d"
        cat $ppf >> $pproto
    fi
done
echo "}" >> $pproto

echo "generating protobuf code with protoc-c"
protoc-c --c_out=. $pproto
