Hello, today we will be exploring the use of ROP (Return Oriented Programming) to exploit computer software and bypass an increasingly common integrity / anti-tamper technique engineers are employing to protect 'critical' or 'high-value' methods inside of software programs.

Let's set up some definitions first.

**ROP**: Return-oriented programming (ROP) is a technique used in computer security exploits where an attacker leverages existing code in a program to execute malicious instructions. ROP attacks rely on finding small pieces of code within a program, called "gadgets", that end with a return instruction. The attacker chains together these gadgets by manipulating the program's stack in a way that causes the program to execute the gadgets in sequence. By combining these gadgets, the attacker can construct arbitrary code that the program will execute.

**Gadget**: A gadget is a small piece of code within a program that performs a specific function and ends with a return instruction. Gadget code is typically less than 15 instructions long and is often found within shared libraries or executable files. In a ROP attack, an attacker identifies useful gadgets and chains them together to construct arbitrary code. Gadgets can perform a variety of functions, such as loading data from memory, writing data to memory, performing arithmetic operations, and calling functions. The usefulness of a gadget depends on its location in memory, the values on the stack, and the values in registers at the time the gadget is executed.

It's important to mention briefly that ROP is only part of the puzzle when it comes to common integrity validation techniques used in production software. These types of approaches are easily mitigated by patching the program to not execute the control flow in place to validate return addresses and callee assembly. This method is usually paired with integrity checks such as program-wide hashing validation (CRC32/FNV1A) to protect the software from inline patching.

Keeping this in mind, we will be writing example software assuming these integrity checks are in place and that there may be other malicious actor detections in place to prevent us from directly manipulating the software.

Let's examine how a high-value method may be implemented to validate return address memory bounds and callee assembly enforcement (typically checking that the method was not invoked from a jmp, but expressly a 0xE8 (call)).

```cpp
void call_me()
{
    uint64_t BaseAddress = (uint64_t)GetModuleHandle(NULL);

    uint64_t returnaddr;
    asm("mov 8(%%rbp),%0"
        : "=r"(returnaddr)
        :
        :);

    printf("Return address %p\n", returnaddr - BaseAddress);

    if (isAddressWithinMemory((void *)returnaddr))
    {
        printf("Return address is within our memory\n");
    }
    else
    {
        printf("Return address is outside of our memory\n");
    }

    uint8_t gadget = *(uint8_t *)(returnaddr - 0x5);
    printf("Gadget instruction: %x\n", gadget); // we expect the gadget to be 0xE8 because it's from a call

    if (gadget != 0xE8)
    {
        printf("This call doesn't look right, are you hacking me?\n");
    }

    // Perform high value operations now that we're assuming 'safety'. 
}
```

We see here that the engineer would be checking the return address from the stack, as well as reading 5 bytes above it to ensure that the method was invoked by a 0xE8 (call) instruction. \`E8 ? ? ? ?\`

Defeating the return address check is simple: we can find a ROP Gadget that's explicitly a 0xC3 (retn) call and push it to the stack before invoking the target method.

Let's take a closer look at potential disassembly for a vulnerable gadget, since we're only looking for explicitly a 0xC3 (retn) call, we can really just grab any retn call address from the program at random, with the assumption the range check is the entire software and not some more restrictive boundaries.

Here's a small bit of disassembly we can inspect for this demonstration.

```cpp
.text:0000000140001626 ; void __cdecl _tcf_0()
.text:0000000140001626 __tcf_0         proc near               ; DATA XREF: __static_initialization_and_destruction_0(int,int)+2C↓o
.text:0000000140001626                                         ; .pdata:000000014000B090↓o ...
.text:0000000140001626                 push    rbp
.text:0000000140001627                 mov     rbp, rsp
.text:000000014000162A                 sub     rsp, 20h
.text:000000014000162E                 lea     rax, _ZStL8__ioinit ; std::__ioinit
.text:0000000140001635                 mov     rcx, rax        ; this
.text:0000000140001638                 call    _ZNSt8ios_base4InitD1Ev ; std::ios_base::Init::~Init()
.text:000000014000163D                 nop
.text:000000014000163E                 add     rsp, 20h
.text:0000000140001642                 pop     rbp
.text:0000000140001643                 retn
.text:0000000140001643 __tcf_0         endp
```

From this example, our vulnerable gadget will be 0x1643

The next few steps may require a bit of finesse to achieve, as we will need to write our payload assembly, in this example I'm just going to return code flow under payload in the main() method, so retrieval of the control flow target address will be a 2 step process (writing the payload and compiling/disassembling the example binary)

To save time, all that is required is retrival of the address immediately after the jmp instruction in our payload as such.

```cpp
.text:0000000140001606                 jmp     rcx
.text:0000000140001608 ; ---------------------------------------------------------------------------
.text:0000000140001608                 sub     rsp, 30h
```

Now let's explore and explain a potential payload.

```cpp
int main()
{
    uintptr_t base = (uint64_t)GetModuleHandle(NULL);

    __asm__ __volatile__(
        "add $48, %%rsp\n\t" // remove prologue rsp changes from the stack
        "push %0\n\t"        // our control flow target (this is printf("Hello"))
        "push %1\n\t"        // this is our rop gadget
        "jmp %2\n\t"         // call_me() call
        :
        : "r"((uintptr_t)base + 0x1608), "r"((uintptr_t)base + 0x1643), "r"((uintptr_t)&call_me)
        :);

    __asm__ __volatile__(
        "sub $48, %%rsp\n\t" // repair the stack for main()'s prologue
        :
        :
        :);

    printf("Execution successful");

    return 0;
}
```

Upon executing the program, we will see that our return address is within memory (obvious in this example, but the implication is that the payload is not being invoked from the immediate process's memory).

```markdown
Return address 0000000000001643
Return address is within our memory
Gadget instruction: 48
This call doesn't look right, are you hacking me?
Execution successful
```

We see that the return address was successfully spoofed and execution was properly handed back off to our payload method. However, since our gadget was not valid, our attempt to invoke the method was detected. In a production piece of software, this would likely result in the program crashing or telemetry being fed back to a server.

Since we know that we require a Gadget that is 5 bytes away from an 0xE8 (call) instruction, we can search in IDA for \`E8 ? ? ? ?\`, it may take quite some time to click through potential gadgets however, for this example I found a valid gadget inside of the \`pformat\_cvt\` method, let's take a look.

```cpp
.text:000000014000280C 89 08                                                        mov     [rax], ecx
.text:000000014000280E 48 8D 44 24 48                                               lea     rax, [rsp+68h+ep]
.text:0000000140002813 48 8D 0D 36 58 00 00                                         lea     rcx, fpi_0      ; fpi
.text:000000014000281A 4C 89 4C 24 30                                               mov     [rsp+68h+dp], r9 ; decpt
.text:000000014000281F 4C 8D 4C 24 44                                               lea     r9, [rsp+68h+k] ; kindp
.text:0000000140002824 44 89 44 24 28                                               mov     [rsp+68h+nd], r8d ; ndigits
.text:0000000140002829 4C 8D 44 24 50                                               lea     r8, [rsp+68h+x] ; bits
.text:000000014000282E 48 89 44 24 38                                               mov     [rsp+68h+rve], rax ; rve
.text:0000000140002833 44 89 5C 24 20                                               mov     [rsp+68h+mode], r11d ; mode
.text:0000000140002838 E8 B3 27 00 00                                               call    __gdtoa
.text:000000014000283D 48 83 C4 68                                                  add     rsp, 68h ; Our vulnerable gadget
.text:0000000140002841 C3                                                           retn
.text:0000000140002841                                              ; ---------------------------------------------------------------------------
.text:0000000140002842 66 0F 1F 44 00 00                                            align 8
.text:0000000140002848
```

In the above assembly we can see our vulnerable gadget (add rsp, 68h;retn) Let's explore the implications of this gadget, so that we can alter our payload accordingly. Since we have to execute the entire gadget to be within the 5 byte constraint of an 0xE8 (call) instruction, we must note that we will have to repair the stack by performing the prologue of the function in our payload (sub rsp, 68h) so that the stack is aligned when the epilogue here is called. With this new gadget in mind, let's modify our payload accordingly.

```cpp
int main()
{
    uintptr_t base = (uint64_t)GetModuleHandle(NULL);

    __asm__ __volatile__(
        "add $48, %%rsp\n\t"  // remove prologue rsp changes from the stack
        "push %0\n\t"         // our control flow target (this is printf("Hello"))
        "sub $104, %%rsp\n\t" // repair rsp for gadget prologue since we're invoking the epilogue
        "push %1\n\t"         // this is our rop gadget
        "jmp %2\n\t"          // call_me() call
        :
        : "r"((uintptr_t)base + 0x160C), "r"((uintptr_t)base + 0x283D), "r"((uintptr_t)&call_me)
        :);

    __asm__ __volatile__(
        "sub $48, %%rsp\n\t" // repair the stack for main()'s prologue
        :
        :
        :);

    printf("Execution successful");

    return 0;
}
```

With the above payload we see the programs output successfully bypasses both checks in place.

```markdown
Return address 000000000000283d
Return address is within our memory
Gadget instruction: e8
Execution successful
```
