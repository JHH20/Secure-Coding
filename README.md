# Secure-Coding
PoolC 시큐어 세미나 자료  
Sample programs and exploits for a basic introduction to system security

## Environment
Language: C++  
Developed in WSL2 Ubuntu 22.04  
Ubuntu GLIBC 2.35

## Guide
Main branch has initial version  
Step through each branch history to see the program (and exploit) evolve

## Scope
| Program | Description | Topics |
| --- | --- | --- |
| center | A program that calculates the average position of (x,y) co-ord | Integer overflow |
| bank | A program that simulates bank account transfer between two users | Floating point precision, Number parsing |
| game | A betting game that supports 1 or more players connected over TCP | Buffer overflow, Stack canary, ROP, global data overwrite, Reverse/Bind shell |
| profile | A program that prettifies your profile username according to your format | Format string attack |
