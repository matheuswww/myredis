OUTPUT="./bin/client"

gcc -o $OUTPUT client.c vector.c

if [ $? -eq 0 ]; then
    ./$OUTPUT "$@"
fi