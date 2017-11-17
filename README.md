# cscan

#### NOTE: It was written in 2008

### Usage

```
Simple TCP Port Scanner
Compilation Time: Nov 17 2017 10:30:52

Options:
  -h <n>   Host/s [e.g. 192.168.1.0/24]
  -o <n>   Output file
  -p <n>   Port/s to scan.
  -t <n>   Timeout seconds [default 5]
  -s <n>   Parallel sockets [default 256]
  -m <n>   Internal sleep time [default 500ms]
  -v       Verbose.

Examples:
  ./cscan -p 1-1000 -v -s 512 -t 2 -h 192.168.0.2
  ./cscan -p 22 -o ip.log -u 500 -h 192.168.0.0/16
```

### Compile

`gcc -Wall -std=gnu11 cscan.c -o cscan`