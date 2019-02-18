# Solution to Stack-Zero

## Ragg2 For pattern creation

Create a random pattern file using the **De Bruijn Sequence** and save it to a file

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

- [1]: The arch let's us know which architecture this binary belongs to, in this case it is a intel x86 instruction set 64bit architecture.

- [2]: The canary protection  named for their analogy to a canary in a coal mine, are used to detect a stack buffer overflow before execution of malicious code can occur. This method works by placing a small integer, the value of which is randomly chosen at program start, in memory just before the stack return pointer. Most buffer overflows overwrite memory from lower to higher memory addresses, so in order to overwrite the return pointer (and thus take control of the process) the canary value must also be overwritten. This value is checked to make sure it has not changed before a routine uses the return pointer on the stack.[2] This technique can greatly increase the difficulty of exploiting a stack buffer overflow because it forces the attacker to gain control of the instruction pointer by some non-traditional means such as corrupting other important variables on the stack.

- [3]: The nx flag let us known if the stack is executable, if this value is set to false, then it means that code can be executed from the stack, most of the time this value is enabled to prevent code execution from the stack.

- [4]: The pic flag stands for Position Independent Code and it tell us if the code will be placed at random locations in memory if the value is true.


### Run the program 

Executing the program in debug mode with radare

```
λ r2 -r profile.rr2 -d ../../stack-zero
```

- **-d**: debug mode.
- **-r**: specify rarun2 profile to load 

Once the binary has been loaded we analyze for symbols, functions etc.

```
[0x7ffff7dc5d34]> aas

```

Now that the binary has been analyzed we can execute commands while referencing the symbols instead of the hexadecimal address numbers.

```
[0x7ffff7dc5d34]> dcu?
Usage: dcu   Continue until address
| dcu.             Alias for dcu $$ (continue until current address
| dcu address      Continue until address
| dcu [..tail]     Continue until the range
| dcu [from] [to]  Continue until the range

[0x7ffff7dc5d34]> dcu main
Continue until 0x0040060d using 1 bpsize
hit breakpoint at: 40060d

```

- **dcu**: **d**ebug **c**ontinue **u**ntil.

This command will execute the code until it hits the main function, leaving us in the begging of the code instructions.

### Solution
Visual mode gives you a block view of the code, this is helpful to view all the branching paths the execution could take. Pressing **VV** while seeking to the main function, this will output the following 
![alt text](images/r2-graph.png "VV command inside r2")
This shows a block of normal execution with a branching path, depending if true or false then joins back to exit.
The code that makes the decision is
```
test eax, eax 
je 0x40064c
```
The `test eax,eax` instructions basically means that if eax is zero then do something since test is esentially mapped to a binary AND bit operation. There are two scenarios that can make the variable take different paths `eax = 0 ` and `eax != 0`.

If `eax = 0011`

| 0 | 0 | 1 | 1 |
|---|---|---|---|
| 0 | 0 | 1 | 1 |
| - | - | - | - |
| 0 | 0 | 1 | 1 |

If `eax = 0000`


| 0 | 0 | 0 | 0 |
|---|---|---|---|
| 0 | 0 | 0 | 0 |
| - | - | - | - |
| 0 | 0 | 0 | 0 |

This means that `test eax eax` will result in 0 if `eax = 0` and set the `ZF` flag (Zero Flag) and if `eax != 0` then `test eax eax` will not set the `ZF` flag and thus the conditions for branching have been discovered.

So lets take a look at what sets `eax` and figure out how to manipulate it.
```
call sym.imp.gets
mov eax, dword [local_4h]
```
So these instructions manipulate the data that is stored in `eax`, the `imp.gets` allows the user to input data, and that data is stored in `eax`

## Stack

Lets view the stack and figure out what is there and how to modify the contents before and after executing the gets instruction:

- Before:
    ```
    .----------------------------------------------------------------------------------.----------------------------------------------------------------------------------..------------------------------------------------------------------------------.
|[x] Disassembly                                                                   |   Stack                                                                          ||   StackRefs                                                                  |
|             ;-- main:                                                            | - offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF        || 0x7fffffffc240  0x00007fffffffc2f8   ........ @rsp rbx stack R W X 'call 0x7f|
|             ;-- r13:                                                             | 0x7fffffffc240  f8c2 ffff ff7f 0000 0000 0000 0100 0000  ................        || 0x7fffffffc248  0x0000000100000000   ........                                |
|             0x0040060d      55             push rbp                              | 0x7fffffffc250  0000 0000 0000 0000 0000 0000 0000 0000  ................        || 0x7fffffffc250  0x0000000000000000   ........ @rdi rdx                       |
|             0x0040060e      4889e5         mov rbp, rsp                          | 0x7fffffffc260  0000 0000 0000 0000 0000 0000 0000 0000  ................        || 0x7fffffffc258  0x0000000000000000   ........ rdx                            |
|             0x00400611      4883ec60       sub rsp, 0x60               ; '`'     | 0x7fffffffc270  0000 0000 0000 0000 f8c2 ffff ff7f 0000  ................        || 0x7fffffffc260  0x0000000000000000   ........ rdx                            |
|             0x00400615      897dac         mov dword [rbp - 0x54], edi           | 0x7fffffffc280  0100 0000 0000 0000 08c3 ffff ff7f 0000  ................        || 0x7fffffffc268  0x0000000000000000   ........ rdx                            |
|             0x00400618      488975a0       mov qword [rbp - 0x60], rsi           | 0x7fffffffc290  0d06 4000 0000 0000 0000 0000 0000 0000  ..@.............        || 0x7fffffffc270  0x0000000000000000   ........ rdx                            |
|             0x0040061c      bfb0064000     mov edi, str.Welcome_to_phoenix_stack_| 0x7fffffffc2a0  0100 0000 0000 0000 62fd d8f7 ff7f 0000  ........b.......        || 0x7fffffffc278  0x00007fffffffc2f8   ........ rbx stack R W X 'call 0x7ffffff|
|             0x00400621      e84afeffff     call sym.imp.puts           ;[1]      | 0x7fffffffc2b0  0000 0000 0000 0000 f0c2 ffff ff7f 0000  ................        |.------------------------------------------------------------------------------.
|             0x00400626      c745fc000000.  mov dword [rbp - 4], 0                | 0x7fffffffc2c0  0000 0000 0000 0000 c8db fff7 ff7f 0000  ................        ||   Registers                                                                  |
|             0x0040062d      488d45b0       lea rax, [rbp - 0x50]                 | 0x7fffffffc2d0  003e 0000 0100 0004 d904 4000 0000 0000  .>........@.....        ||  rax 0x7fffffffc250       rbx 0x7fffffffc2f8       rcx 0x7ffff7db6d07        |
|             0x00400631      4889c7         mov rdi, rax                          | 0x7fffffffc2e0  0000 0000 0000 0000 b604 4000 0000 0000  ..........@.....        ||  rdx 0x00000000            r8 0x7ffff7ffb300        r9 0x7fffffffc20f        |
|             ;-- rip:                                                             | 0x7fffffffc2f0  0100 0000 0000 0000 e8c9 ffff ff7f 0000  ................        ||  r10 0x00000001           r11 0x00000206           r12 0x7fffffffc308        |
|             0x00400634      e827feffff     call sym.imp.gets           ;[2]      | 0x7fffffffc300  0000 0000 0000 0000 f9c9 ffff ff7f 0000  ................        ||  r13 0x0040060d           r14 0x00000000           r15 0x00000000            |
|             0x00400639      8b45fc         mov eax, dword [rbp - 4]              | 0x7fffffffc310  0fca ffff ff7f 0000 23ca ffff ff7f 0000  ........#.......        ||  rsi 0x7fffffffc180       rdi 0x7fffffffc250       rsp 0x7fffffffc240        |
|             0x0040063c      85c0           test eax, eax                         | 0x7fffffffc320  59ca ffff ff7f 0000 8cca ffff ff7f 0000  Y...............        ||  rbp 0x7fffffffc2a0       rip 0x00400634           rflags 1PZI               |
|         ,=< 0x0040063e      740c           je 0x40064c                 ;[3]      | 0x7fffffffc330  d2ca ffff ff7f 0000 e9ca ffff ff7f 0000  ................        || orax 0xffffffffffffffff                                                      |
|         |   0x00400640      bf00074000     mov edi, str.Well_done__the__changeme_|                                                                                  ||                                                                              |
|         |   0x00400645      e826feffff     call sym.imp.puts           ;[1]      |                                                                                  |.------------------------------------------------------------------------------.
|        ,==< 0x0040064a      eb0a           jmp 0x400656                ;[4]      |                                                                                  ||   RegisterRefs                                                               |
|        |`-> 0x0040064c      bf38074000     mov edi, str.Uh_oh___changeme__has_not|                                                                                  ||  R0   rax 0x7fffffffc250      rdi stack R W X 'add byte [rax], al' '[stack]' |
|        |    0x00400651      e81afeffff     call sym.imp.puts           ;[1]      |                                                                                  ||       rbx 0x7fffffffc2f8      rbx stack R W X 'call 0x7fffffffc2c6' '[stack]'|
|        `--> 0x00400656      bf00000000     mov edi, 0                            |                                                                                  ||  A3   rcx 0x7ffff7db6d07      (/opt/phoenix/x86_64-linux-musl/lib/libc.so) rc|
|             0x0040065b      e820feffff     call sym.imp.exit           ;[5]      |                                                                                  ||  A2   rdx 0x0                 rdx                                            |
|             ;-- __do_global_ctors_aux:                                           |                                                                                  ||  A4    r8 0x7ffff7ffb300      (/opt/phoenix/x86_64-linux-musl/lib/libc.so) r8|
|             0x00400660      488b05390820.  mov rax, qword obj.__CTOR_LIST    ; [0|                                                                                  ||  A5    r9 0x7fffffffc20f      r9 stack R W X 'or al, byte [rax]' '[stack]'   |
|             0x00400667      4883f8ff       cmp rax, 0xffffffffffffffff           |                                                                                  ||       r10 0x1                 (.comment) r10                                 |
|         ,=< 0x0040066b      7433           je 0x4006a0                 ;[6]      |                                                                                  ||       r11 0x206               (.symtab) r11                                  |
`----------------------------------------------------------------------------------'----------------------------------------------------------------------------------'`------------------------------------------------------------------------------'
    ```





