beamer
======

Automatically transfer a file over a network connection every time it
is re-written.

Usage
-----

    target$ ./beamer 3000 file &
    build$ ./beamer . file target 3000 &

I can then run `make` repeatedly and the file will be copied each time
make changes file.
