#!/usr/bin/env python3
import subprocess
import sys

def launch():
    return subprocess.Popen("./build/bank", 0, stdin=subprocess.PIPE, text=True)


def lossy_float():
    p = launch()

    input() # Let user see initial value before attacking

    for _ in range(100):
        p.stdin.write("1\n")

    p.stdin.write("0\n")
    p.wait()


def negative():
    p = launch()
    p.communicate("-1000\n")


def help(this):
    print(f"{this} f = Attack floating point precision")
    print(f"{this} n = Attack negative value")


argToFunc = {"f": lossy_float, "n": negative}
if len(sys.argv) >=2 and sys.argv[1] in argToFunc:
    argToFunc[sys.argv[1]]()
else:
    help(sys.argv[0])
