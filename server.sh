
OUTPUT="./bin/server"
gcc -o $OUTPUT server.c vector.c map.c hashtable.c

if [ $? -eq 0 ]; then
    ./$OUTPUT
fi