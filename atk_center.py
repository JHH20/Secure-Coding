#!/usr/bin/env python3
import subprocess
import sys

def launch():
    return subprocess.Popen("./build/center", 0, stdin=subprocess.PIPE, text=True)


# MAX SIGNED INT32 = 2 147 483 647
p = launch()
p.stdin.write("2\n")
p.stdin.write("2147483647 2147483645\n")
p.stdin.write("2147483645 2147483647\n")
p.wait()
