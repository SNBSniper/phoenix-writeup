# Solution to Stack-Zero

## Ragg2 For pattern creation

Create a random pattern file using the *De Bruijn Sequence and save it to a file

```
λ ragg2 -P 200 -r >> pattern.txt
```

## Set up R2 Profile

Create a file called `profile.rr2` that will store our profile configurations.

```
#!/usr/bin/rarun2
stdin=./pattern.txt
```

## Radare2 Analyze

Let's first anaylize the binary 

```
arch     x86            (1)
baddr    0x400000
binsz    6087
bintype  elf
bits     64
canary   false          (2)
sanitiz  false
class    ELF64
crypto   false
endian   little
havecode true
intrp    /opt/phoenix/x86_64-linux-musl/lib/ld-musl-x86_64.so.1
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1               
nx       false          (3)
os       linux
pcalign  0
pic      false          (4)
relocs   true
relro    partial        
rpath    /opt/phoenix/x86_64-linux-musl/lib
static   false
stripped false
subsys   linux
va       true


```

The arch (1) let's us know which architecture this binary belongs to, in this case it is a intel x86 instruction set 64bit architecture.

The canary protection (2)  named for their analogy to a canary in a coal mine, are used to detect a stack buffer overflow before execution of malicious code can occur. This method works by placing a small integer, the value of which is randomly chosen at program start, in memory just before the stack return pointer. Most buffer overflows overwrite memory from lower to higher memory addresses, so in order to overwrite the return pointer (and thus take control of the process) the canary value must also be overwritten. This value is checked to make sure it has not changed before a routine uses the return pointer on the stack.[2] This technique can greatly increase the difficulty of exploiting a stack buffer overflow because it forces the attacker to gain control of the instruction pointer by some non-traditional means such as corrupting other important variables on the stack.

The nx (3) flag let us known if the stack is executable, if this value is set to false, then it means that code can be executed from the stack, most of the time this value is enabled to prevent code execution from the stack.

The pic flag (4) stands for Position Independent Code and it tell us if the code will be placed at random locations in memory if the value is true.


### Run the program 

Executing the program in debug mode with radare

```
λ r2 -r profile.rr2 -d ../../stack-zero
```
