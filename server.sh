
OUTPUT="./bin/server"
gcc -o $OUTPUT server.c vector.c map.c hashtable.c avl.c zset.c

if [ $? -eq 0 ]; then
    ./$OUTPUT
fi