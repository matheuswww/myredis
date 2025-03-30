
OUTPUT="./bin/server"
gcc -o $OUTPUT server.c vector.c hashtable.c avl.c zset.c heap.c

if [ $? -eq 0 ]; then
    ./$OUTPUT
fi