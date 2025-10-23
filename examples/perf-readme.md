## Quickstart

from the root:


```
cmake -B build
```

Server:
```
cd build/
make examples-perf && ./examples-perf -k ../t/assets/server.key -c ../t/assets/server.crt -p 4444
```

Client:
```
cd build/
make examples-perf && ./examples-perf -p 4444 -T 0 -R 65536
```
