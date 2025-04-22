# Why though?

An interesting approach to hardening natively compiled software is run time self-modifying binaries. Specifically where encryption is deployed. This approach allows engineers to raise the bar in terms of knowledge required to reverse engineer the software, as well as hide any methods used to further harden the software, such as integrity checks and anti-debugging measures.

For example, a developer may want to employ encryption so that they can initiate integrity checks, and remove the code used to do so from the runtime memory, making it much more complicated to reverse engineer, of course, this still has its drawbacks, as with most software hardening techniques, they work best when deployed together.

# The Concept

The simple breakdown of the problem and its solution are as follows.

* Compile code to an executable format
    
* With a helper encrypter program consume the binary file and modify its code section (\_\_text)
    
    * We don't want to encrypt the file header as DYLD uses this to understand how to execute the entry point functions and set up exit points.
        
    * We don't want to encrypt any constant data after the text section because it may cause issues with the initialization of the binary or the decryption phase (the imported methods will need to not be encrypted, handling this at encryption time would be too complicated for this example)
        
    * Omit the main function
        
        * For sanity's sake, I would encourage the use of inline functions to make code more understandable and remove complications from worrying about encrypting multiple functions.
            
* At runtime, the executable should be able to decrypt itself
    
    * The general process would be to
        
        * Get the base address of the executable's memory
            
        * Get the size of the executable's memory
            
        * Allocate a memory region of the same size
            
        * Copy the memory to the buffer
            
        * Set the buffers memory region to executable
            
        * Jump to the memory region and execute a decryption method which...
            
            * Allocates a buffer the size of the ".text" region of the program
                
            * Allocates a clone buffer to serve as "original bytes"
                
            * Copies the memory over, decrypting the "clean bytes" (main entry point and decrypt function)
                
            * Sets the main executables memory to writable
                
            * Copies the decrypted buffer into that region
                
            * Sets the memory back to executable
                
            * Jumps back to the main entry point to continue execution (most likely executing previously encrypted code)
                

Simple, right?

# The Code

#### If you'd like to skip the rest you can find the code [here](https://github.com/ItsJustMeChris/Dylatte)

We're going to be injecting our dylib into a basic dummy program that just prints "Hello, world!" on a timer.

```cpp
// test_app -> main.cpp
#include <iostream>
#include <unistd.h>

int main()
{
    while (1)
    {
        std::cout << "Hello, world!" << std::endl;
        sleep(2);
    }

    return 0;
}
```

Some code will be shared between the encrypter and dylib for finding the size of different regions inside the Mach-O binary from the header information. I'll explain the general concept in lamens terms, but the code for these functions is fundamentally the same so I'll only show one here.

```cpp
uintptr_t GetTextSize(uint8_t *fBuffer)
{
    unsigned int size = 0;
    struct mach_header_64 *header = (struct mach_header_64 *)fBuffer;
    struct load_command *cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));

    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segment = (struct segment_command_64 *)cmd;

            struct section_64 *section = (struct section_64 *)((uintptr_t)segment + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < segment->nsects; j++)
            {
                if (strcmp(segment->segname, "__TEXT") == 0 && strcmp(section->sectname, "__text") == 0)
                {
                    return section->size;
                }

                section = (struct section_64 *)((uintptr_t)section + sizeof(struct section_64));
            }
        }
        cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
    }

    return size;
}
```

Simply put, we're reading the header of the [Mach-O](https://en.wikipedia.org/wiki/Mach-O) binary assuming it's a 64-bit program, enumerating the [commands](https://en.wikipedia.org/wiki/Mach-O#Load_commands), finding those of which are [segment commands](https://en.wikipedia.org/wiki/Mach-O#Segment_load_command), enumerating the segments sections until we find the "\_\_text" section inside of the "\_\_TEXT" segment. We will use this concept to find the text region, which is where the majority of executable code lives inside of the binary.

We will use simple xor encryption to encrypt and decrypt the contents.

```cpp
buffer[i] = original[i] ^ 0x12345;
```

Now let's break down the entry point and decrypt methods, the general concept was explained above so I'll assume it was read and to avoid repeating myself I'll just share the commented code here and summerize after.

```cpp
void Decrypt(uintptr_t baseAddress)
{
    uintptr_t textSize = GetTextSize();
    uintptr_t textStart = GetTextStart();
    uintptr_t textStartAddr = (uintptr_t)baseAddress + (uintptr_t)textStart;

    uint8_t *buffer = (uint8_t *)mmap(NULL, textSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    uint8_t *original = (uint8_t *)mmap(NULL, textSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    // clone the memory
    mach_vm_protect(mach_task_self(), (uintptr_t)buffer, textSize, 0, VM_PROT_READ | VM_PROT_WRITE);

    // create buffers
    memcpy(buffer, (void *)textStartAddr, textSize);
    memcpy(original, (void *)textStartAddr, textSize);

    // decrypt
    for (size_t i = 0; i <= textSize; i++)
    {
        if (i >= 0xFC && i <= 0xFC + 0x714)
        {
            buffer[i] = original[i];
            continue;
        }

        buffer[i] = original[i] ^ 0x12345;
    }

    // protect the memory to be executable
    mach_vm_protect(mach_task_self(), (uintptr_t)buffer, textSize, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    // protect the main memory to be writable
    kern_return_t k1 = mach_vm_protect(mach_task_self(), textStartAddr, textSize, 0, VM_PROT_READ | VM_PROT_WRITE);
    if (k1 != KERN_SUCCESS)
    {
        return;
    }

    // copy the decrypted memory back
    memcpy((void *)(uintptr_t)textStartAddr, (void *)buffer, textSize);

    // protect the main memory to be executable
    kern_return_t r2 = mach_vm_protect(mach_task_self(), textStartAddr, textSize, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (r2 != KERN_SUCCESS)
    {
        return;
    }

    // unmap the memory
    munmap(buffer, textSize);
    munmap(original, textSize);

    return;
}

void entry_point(void)
{
    Dl_info info;
    dladdr((void *)entry_point, &info);
    uintptr_t baseAddress = (uintptr_t)info.dli_fbase;

    mach_vm_size_t size = SizeOfMachO();

    uint8_t *buffer = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    // clone the memory
    mach_vm_protect(mach_task_self(), (uintptr_t)buffer, size, 0, VM_PROT_READ | VM_PROT_WRITE);
    memcpy(buffer, (void *)baseAddress, size);
    mach_vm_protect(mach_task_self(), (uintptr_t)buffer, size, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    uintptr_t decrypt = (uintptr_t)Decrypt + (uintptr_t)buffer - baseAddress;

    // call the decrypt function
    ((void (*)(uintptr_t))decrypt)(baseAddress);

    munmap(buffer, size);

    std::cout << "Did decrypt" << std::endl;

    real_entry();

    std::cout << "Did real entry" << std::endl;
}
```

To summarize, we're cloning the original memory, handing off execution to a different memory region to avoid any conflicts when rewriting the decrypted memory, reading the original bytes and decrypting them, writing back to the main memory region for the binary, and continuing execution inside of a previously encrypted function.

As you can see there are hard-coded offsets in this code, which is something I wish to remove the requirement of in the future, but for this example I didn't see it worth coming up with some concept to tell the encrypter what code to encrypt and not encrypt.

I believe that is the most interesting code in the project, the rest of which (encrypter program) can be found on my GitHub here. [https://github.com/ItsJustMeChris/Dylatte](https://github.com/ItsJustMeChris/Dylatte)

I hope you learned something, and I hope I sparked some interest in software security as I find the field extremely interesting.

[I've since made a more complete Proof of Concept / general macos self decryption system](https://github.com/ItsJustMeChris/macrypt)
