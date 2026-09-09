+++
title = "DOOM in the kernel, or fibers in eBPF"
date = 2026-09-09
description = "How a hand-ported DOOM, verifier tricks, and a slow virtual machine led to a compiler built around regions and fibers."
draft = false
+++

DOOM is not supposed to run inside eBPF. Linux should reject a program like
that before executing its first instruction.

BPF has a tiny stack, five argument registers, and limited call depth.
Recursion is forbidden. A loop must be finite not merely because the programmer
says so, but in terms the verifier can prove. You cannot simply store a pointer
in memory, load it later, and dereference it: the kernel must remember where it
came from and what it is allowed to address.

And yet an unmodified Linux kernel accepts my BPF object, checks it with the
stock verifier, and runs it through the stock JIT. DOOM initialization, game
logic, and rendering all execute in the kernel. One game tick, including the
complete frame, finishes in a single BPF invocation. Userspace supplies the WAD
and keyboard input and gets back a pointer to the finished framebuffer.

A word on the machine all of this happens in. eBPF runs user-supplied code
inside the Linux kernel without kernel modules: a program is compiled to the
bytecode of a small register machine, loaded with the `bpf(2)` system call, and
attached to one of the kernel's own points — the arrival of a network packet
(XDP), the entry of a kernel function, a system call. From then on the kernel
runs it through its own JIT on every such event, as ordinary machine code. The
price of that freedom is the static check before loading that those constraints
come from: anything the verifier cannot prove is forbidden. That check, rather
than the bytecode, is what makes DOOM inside eBPF look impossible.

The project is called [BPF Capsule](https://github.com/ayles/bpf-capsule). It
is a compiler and runtime for large C programs inside ordinary BPF, with no
kernel patches and no separate virtual machine in userspace. The oldest
supported target is Linux 5.15. I have loaded and run the programs on both
x86-64 and arm64.

Nobody needs games in the kernel, of course. But complex application logic is
useful there: parsing packets, for example, or keeping statistics about them.
When such a program does not fit eBPF's constraints, it has to be simplified
and rewritten by hand until the verifier is satisfied. Capsule explores another
path: it takes C, C++, or `no_std` Rust code and transforms it into a shape
that stock Linux accepts.

DOOM is not the application here but a stress test for that approach. Lua,
QuickJS, SQLite, zlib, wasm3, llama2.c, `no_std` Rust, and CPython 3.14 run on
the same scheme today, and Lua and Python inspect live packets straight from
XDP. This article follows the road from a hand-trimmed port through a slow
interpreter to the machine that runs them today, and what that machine costs at
run time.

You can try it with one command on any supported kernel. You need Nix and a WAD
file — for obvious reasons the WAD is not in the repository — and the rest of
the requirements are in the
[README](https://github.com/ayles/bpf-capsule/blob/6733c4531f06f95a32a35c2084b3dcf1a4263746/README.md#build):

```console
$ sudo nix run github:ayles/bpf-capsule#doom -- /path/to/doom1.wad tty
```

The trick is the shape of the program presented to the verifier. First I got
DOOM to compile to BPF and run without a verifier at all. Then I cut out
everything the kernel disliked, lied to it about pointers, and forced loops
into one special form. When even that stopped scaling, I wrote a virtual
machine inside eBPF. The current machine of regions, fibers, and a software
stack grew out of it.

These approaches broke one after another, and every failure suggested what had
to be built next.

<video controls preload="none" playsinline loop width="960" height="560"
       poster="/doom-in-kernel/doom-capsule.webp"
       aria-label="DOOM executing in the kernel; the panel on the right shows live samples from BPF Capsule JIT functions">
  <source src="/doom-in-kernel/doom-capsule.mp4" type="video/mp4">
  <a href="/doom-in-kernel/doom-capsule.mp4">Open the recording.</a>
</video>

*The game looks especially pixelated because the frame is rendered with
terminal characters over SSH. DOOM runs inside the kernel BPF JIT on the left.
On the right are samples from real `bpf_dispatch_output_scalar_*` functions:
physical functions into which Capsule packed the regions.*

## Why this should be impossible

On paper, eBPF is a small register architecture with an LLVM backend. It sounds
simple: write C, run `clang -target bpf`, and get an object the kernel can
load.

In practice, “write C” means writing in two rather different languages at once.
LLVM understands one. The Linux verifier understands the other.

I became intimately familiar with that boundary while working on
[Perforator](https://github.com/yandex/perforator). That is where I accumulated
enough frustration with the current BPF stack to go this far.

Before loading a program, the verifier symbolically executes it. For every
register it tracks not only a value or range, but a meaning: an ordinary number
(`SCALAR_VALUE`), a pointer to the stack, packet data, a map value, or a
`bpf_arena`. It explores branches, merges states, and proves two things: every
memory access is allowed, and every execution path eventually terminates.

That creates constraints an ordinary program barely notices:

- `r1` through `r5` are all the argument registers in the classic ABI;
- the call graph must be acyclic, and call depth is limited;
- only 512 bytes of stack are available along a call chain;
- one loaded program may contain no more than 256 BPF functions;
- after processing roughly a million instructions, the verifier gives up.

That last limit is not an execution-time limit. The analyzer can walk a
ten-instruction loop a thousand times with distinct states and exhaust the
budget. A finite loop is legal in itself; the problem starts when the kernel
cannot prove its bound or has to enumerate too many possibilities.

Memory is more entertaining still. To the CPU, a pointer is ultimately just a
number. To the verifier, it is a number with a biography. It may know that
`r10 - 8` points into a valid BPF stack slot, or that `data + n` remains within
a packet after a check against `data_end`. Store that pointer as ordinary 64
bits in a map and load it back, and the CPU gets the same address while the
verifier gets a number with no right to be dereferenced.

Normal C programs constantly put pointers in structures, pass those structures
through several functions, and load the pointers much later. Somewhere along
that route, the verifier loses the proof.

### A recent LLVM example

Writing a valid bounds check in C is not enough: the kernel sees the code after
optimization. Here is a real fragment of [packet-processing BPF
code](https://github.com/ayles/bpf-capsule/blob/6733c4531f06f95a32a35c2084b3dcf1a4263746/examples/lua-xdp/lua_xdp_runtime.c):

```c
size_t at = offset + index;
asm volatile("" : "+r"(at));
at &= PACKET_CAPACITY - 1;

if (data + at + 1 > data_end)
    return -1;
byte = data[at];
```

The mask bounds `at`, and the following comparison proves the packet boundary.
Late in the pipeline, however, LLVM can express the index again in terms of the
original `offset` and `index` loaded from a resumable loop frame. Both forms
mean the same thing to the CPU. In one form, the old verifier in the supported
Linux 5.15 profile sees a bounded index next to the access; in the other, it
loses the proof it needs. The empty inline assembly is not needed by the CPU
and emits no BPF instruction. It exists to make LLVM preserve the exact data
dependency the kernel understands.

This is the unpleasant third language between C and the machine: sometimes a
program must not only be safe, but carry its safety proof through the optimizer
in a recognizable shape.

## First, produce any BPF at all

Before involving the kernel, there is an intermediate step: compile DOOM to BPF
and run the object in a userspace virtual machine. With no verifier, code
generation bugs can be separated from failures to prove safety.

I based the experiment on [PureDOOM](https://github.com/Daivuk/PureDOOM), a
port that packages the whole engine into one C header and exposes a short
embedding interface. It is convenient for an experiment like this while leaving
DOOM itself almost entirely ordinary C.

Even without the verifier, arbitrary C does not become BPF by itself. The
classic ABI has nowhere to put a sixth argument, and BPF has neither
floating-point operations nor indirect calls. Large structure returns,
variable-size `memcpy`, and some 128-bit arithmetic need lowering as well. I
also had to extend uBPF's program counter and add missing instructions,
sections, and ELF relocations.

BPF globals do not become ordinary process memory: `.data` and `.bss` become
map values, while ELF relocations tell the loader which map and which offset
each address in the code refers to.

After those changes, DOOM ran in uBPF. The stack was not a fundamental obstacle
there: the VM's frame size and total memory reserve can simply be increased.
This proved LLVM could emit working BPF code, but said nothing about whether a
real kernel would accept it.

DOOM had been run in a userspace BPF machine before. One example is [Flying the
nest — a BPF port of Doom](https://lpc.events/event/18/contributions/1936/),
which used its own νBPF VM. Inside a VM, you can change the machine's rules. My
goal was different: an object accepted by the ordinary Linux verifier and
executed by the ordinary in-kernel BPF JIT.

## Porting with scissors

The next step was loading the program into a real kernel. The freedom of uBPF
ended there: I could not increase the 512-byte frame, call depth, or verifier
budget. The first attempt was as direct as possible—take PureDOOM and delete
everything that did not fit. A native build remained the reference so frames
could later be compared byte for byte.

The Git history from that period reads like an amputation log:

- `Removed sound`;
- `Remove args parsing and demo playback`;
- `Remove networking`;
- `Remove file I/O`;
- `Remove internal gettime call`;
- `Remove dynamic memory allocation`;
- `Fixup some functions to take 5 arguments or less`;
- `Remove indirect calls`;
- `Get rid of recursion; inline the hell out of this code`.

Function pointers are everywhere in DOOM: action tables, thinker functions,
renderer callbacks. I replaced them with one `indirect_call.c` containing a
chain of comparisons against every known destination. An unknown target ended
the game, while recursive BSP traversal became an array and a manual stack.

Functions then had to be inlined to fit the real BPF stack and call-depth
limits. That quickly became a dead end. Inlining reduces depth but increases
the number of values live at once and the number of register spills. Prevent
inlining and the individual functions fit, but the graph remains too deep and
occasionally recursive. One more level of inlining merely changes which limit
the program hits first.

At some point it became clear that I was no longer porting DOOM. I was doing a
compiler's job by hand. The useful result was less a working binary than a list
of mechanical transformations.

The first LLVM pass contained two hacks. One tried to make arbitrary memory
access acceptable to the verifier. The other forced every loop into one form
the kernel could prove. Almost the whole project eventually grew out of those
two hacks. By then this was clearly a project rather than an amusement: it got
a repository, and I named the whole construction BPF Capsule.

## Hack one: launder a pointer

The problem looked like this. DOOM stores a real pointer in a heap or global
structure, then loads and dereferences it several calls later. The CPU gets the
same 64 bits. After the load, the verifier sees an ordinary number: the
pointer's origin and permitted bounds are gone. The special treatment of the
real BPF stack does not help; DOOM's arbitrary heap will not fit in 512 bytes.

Before an access, that number has to be tied again to an object known by the
kernel. It sounds as if subtracting the start of `.data` or `.bss` should be
enough. But to the verifier the first value is a scalar and the second is a
`PTR_TO_MAP_VALUE` obtained from an ELF relocation. The kernel forbids
`scalar - pointer`.

Reversing the subtraction does not help. To the CPU, `end_ptr - x` would be a
small distance to the section's end. But the verifier does not know that `x`
contains an address from the same map: it sees an enormous or unknown pointer
offset, outside the range allowed by `BPF_MAX_VAR_OFF` (`2^29`). Reducing the
two bases afterwards is too late; the first operation is already forbidden.

The same section base therefore had to exist in two forms—double-entry
bookkeeping. A laundered copy could be subtracted from the unknown address,
while the original copy, still carrying its verifier biography, could be used
after checking the result:

```text
x, loaded from memory              start of .data (PTR_TO_MAP_VALUE)
        |                                 |          |
        |            launder              |          |
        |         scalar base <-----------+          |
        |             |                              |
        +--> offset = x - base                       |
                      |                              |
             check 0 <= offset <= size - width       |
                      |                              |
                      +--> base + offset <-----------+
                                |
                                v
                       valid address in .data
```

The first working version laundered a base rather crudely. The pass created a
`volatile` cell called `globalConv` in a map and a function roughly like this:

```c
void *bpf_ptr_to_scalar(void *ptr)
{
    globalConv = ptr;
    return globalConv;
}
```

A BTF type table shipped alongside the program. It deliberately told the kernel
that this function took no arguments and returned `u64`, even though the
machine code used `r1`. The store into the map consequently looked like a store
of an ordinary number, and the caller received a scalar as well. The comment
was honest: `Fool the verifier into thinking that there are no args`.

The section base needed another ugly trick. The pass inserted one synthetic
global at the beginning of both `.data` and `.bss`; a reference to it became
the real base of the corresponding map after load. At first, section size was
computed as the sum of LLVM globals, but the final layout and alignment do not
exist until ELF emission. In the last surviving version of this experiment, the
computed result was simply overwritten by two hard-coded constants.

Comparisons then bounded the scalar `offset`, and adding it to the untouched
base produced a `PTR_TO_MAP_VALUE` again. Every uncertain read or write grew a
router:

```text
unknown address
      |
      +-- inside .data? --> known base + checked offset
      +-- inside .bss?  --> known base + checked offset
      `-- elsewhere    --> fault
```

That was enough for individual sections, but not for all memory. A pointer to
the BPF stack cannot make the same round trip through a map: the kernel either
sees a pointer leak or returns a useless scalar. Address-taken locals that
survive a call therefore still need separate storage.

Once memory accesses began to pass, the verifier reached the loops and spent
its million-instruction budget there instead.

## Hack two: one counter to rule them all

The first loop pass wrapped every loop in `bpf_iter_num_new`/`next`/`destroy`
with a large emergency bound. It then grew more aggressive: every counter and
pointer advanced by the loop was expressed through a single iteration number,
`n`.

If the source loop advanced `i`, `j`, and `p` together, the transformed loop
reconstructed them:

```text
i = i0 + n * i_step
j = j0 + n * j_step
p = p0 + n * p_step
```

The verifier saw one bounded iterator instead of a knot of related loop
variables—PHI nodes in LLVM IR. On a clean example this looked great. After
`-O2`, however, the IR contained subtractions, narrow counters, several exits,
and a rewritten control-flow graph. Every new shape needed another rule.

This also revealed a funny paradox: sometimes the verifier is faster when it
knows less. An exact initial counter value makes it walk each iteration as a
distinct state. An unknown value lets similar states merge.

Before entering the canonical loop, the counters were stored in `volatile`
memory and loaded back. The verifier then saw a range rather than an exact
constant, allowing states from different iterations to merge.

This carried most loops through the verifier. But a compiler can spend forever
learning every new LLVM IR shape. I needed a way to execute arbitrary control
flow without making the kernel see all of it at once.

## The simplest complete solution

If program code is stored as data, the verifier does not need to analyze its
control-flow graph. It checks one small interpreter. The next instruction
number, registers, stack, and guest call frames live in maps. Each BPF
invocation interprets a fixed number of instructions and then returns.
Termination is obvious.

I tested this literally: first an interpreter for real eBPF inside eBPF, then
an RV64IM interpreter and loader for ordinary RISC-V ELF files. A checksum and
zlib produced correct results, but an archived single-core zlib measurement was
roughly **60×** slower than native code. Most of the time, the kernel was not
running zlib at all. It was running `switch (opcode)`: the virtual machine
returned to the dispatcher after every guest instruction.

The unit of interpretation had to be much larger than one instruction. The
virtual machine state, however, was worth keeping.

## What if one instruction is a piece of the program?

Instead of an `add`, `load`, or `jump`, one operation in the new machine
contains a whole piece of already compiled code. Ordinary BPF runs inside that
piece, then saves its state and returns to a small dispatcher. I call such a
piece a **region**.

A region is bounded: it ends at a complex call, a return, a `yield`, an
inconvenient loop backedge, or wherever the compiler decides to cut an
oversized graph. It runs in full, saves live values, and returns to the
dispatcher. Capsule can suspend the computation only at that boundary; this
does not prevent other fibers from running concurrently. The dispatcher invokes
the next region. To the verifier this is an ordinary caller–callee boundary,
not another part of DOOM's
enormous control-flow graph.

The verifier therefore never analyzes the whole path through the source
program. It sees a small region and a bounded dispatcher. A normal call is
split roughly like this:

```text
render_frame:   [ 17 ] ---call---> R_DrawPlanes: [ 42 ] ---> [ 43 ]
                                                               |
                [ 18 ] <--------------- return ----------------'
                continuation of render_frame

at every arrow the region saves its live values and the number of the next
region, returns to the dispatcher, and the dispatcher calls that region
```

A region does not have to become a separate BPF function. LLVM generates code
and allocates registers for a whole group of regions at once, and that group is
normally every region of one source function; a source function too large for
the verifier is cut into several groups first. Capsule then places the groups
whole, largest first, each into the physical function holding the least code so
far, so one physical function usually owns the regions of several source
functions.

One BPF function per region would quickly hit the 256-function limit. One
function for the whole program is bad as well: the kernel repeatedly performs
live-value analysis across the entire monster and load time explodes. Instead,
the object contains several physical functions of roughly equal size:

```text
groups of regions, one per             physical BPF functions
source function

render: 17, 18     ----+               function 0: 42, 43, 44
planes: 42, 43, 44 ----+-- packing --> function 1: 17, 18, 61
things: 61         ----+

packed region number: [ 16 bits: region inside the function | 8 bits: function ]
                        selected by a compare tree            selected by a mask
```

A region's number is packed accordingly. Its low byte names the physical
function that owns the region, so the entry code selects that function with a
mask and a switch; a balanced compare tree inside the function then selects the
exact region. The principle is simple: a number in fiber state selects a large
piece of ordinary JIT code. Source C function boundaries define the software
stack; physical BPF function boundaries keep the object digestible for the
verifier.

Sometimes even that is not enough. The verifier gives one loaded program a
single exploration budget of about a million instructions, and the CPython
interpreter does not fit into it. For such programs, `bpf-capsule-ld
--freplace` moves physical functions into BPF extensions that live in the same
ELF. A stub that fails when called stays behind for each of them in the base
program, and the host attaches the extensions with `freplace` before
initialization. Each extension is a separately loaded program with a budget of
its own, while fibers, memory, and continuations keep working through them
unchanged. This needs BPF trampolines: any supported kernel on x86-64, and
Linux 6.0 or newer on arm64.

With or without extensions, this remains BPF compiled by the stock JIT, not
interpreted LLVM IR or another ISA. The verifier checks every instruction
inside a region, and the kernel JIT compiles it. What remains of the virtual
machine is an explicit next-operation number, stack, and state, but dispatch
happens at the boundary of a large piece of work rather than after every `add`.

## Where the fibers and second stack came from

Once a function call is split by a region boundary, the ordinary BPF call stack
is no longer enough. Arguments, locals, and the return address need somewhere
to survive the transition. That became a software stack in Capsule memory.

The caller places everything that must cross the boundary there, creates a
callee frame, records the callee's first region, and returns to the dispatcher.

Later, the callee writes its result into the caller-owned part of that frame,
restores the continuation number, and returns through the dispatcher too.

This has a small ABI of its own. A frame looks roughly like this:

```text
             higher addresses
        +--------------------------------+
        | variadic arguments             |  layout known at the call site
        | fixed arguments                |
        | optional result area           |  written by the callee
fp+16 --+--------------------------------+
        | region to run after return     |
 fp+8 --+--------------------------------+
        | caller's fp                    |
   fp --+--------------------------------+
        | callee locals and saved values |
   sp --+--------------------------------+  allocated-stack frontier
             lower addresses
```

The stack grows toward lower addresses: `fp` marks the current frame boundary,
while `sp` marks the lower edge of allocated space. A call changes only `fp`,
`sp`, and the next region number. Each call site already knows how LLVM lowered
its arguments, so it allocates exactly the outgoing area that call needs.
Values, including structures passed by value, live directly in that area: a
field is read at a constant offset from `fp`, without first loading a pointer
to a separate copy. Variadic arguments follow the fixed prefix, and `va_list`
is simply a cursor through that tail. A return performs the three state changes
in reverse. A sixth argument, deep call chain, or recursion therefore consumes
no additional registers or frames in the real BPF ABI: as far as the kernel is
concerned, each region still returns normally.

Recursion does not turn into recursive calls between BPF functions. Every
source call merely pushes another software frame. A function pointer becomes an
ordinary 64-bit value in the code range just above the data window: `window + 4
GiB + the number of its entry region`. An indirect call recovers the region
number by truncating that value to its low word, and the dispatcher enters
the region it names. This is a representation of C function pointers, not a
check that a forged pointer is a valid call target.

The real BPF stack does not disappear. Its 512 bytes serve as scratch space for
the current region. Values that must outlive a region are moved into the
software frame.

The current region, the stack and frame pointers, the saved state, and one
slice of software stack together make a **fiber**. There may be several fibers:
each has separate state and stack storage, while globals and the heap are
shared. A `_Thread_local` variable gets one instance per fiber: the compiler
collects all such variables into one block and indexes it by fiber number, so a
library written for threads sees a thread where Capsule has a fiber.

The control record calls this field `resume_region_id`: an integer identifying
the next region, not a processor instruction address or a counter to increment.

`capsule_yield()` deliberately uses the same boundary. State remains in the
fiber, while the caller receives a number that can resume the work in a later
BPF invocation. The number includes the fiber generation, so a stale value
cannot accidentally resume a different task that has reused the same slot.

Loops no longer have to be normalized into one exact IR pattern after
optimization. A small loop with a proven bound remains an ordinary BPF loop. A
hot dynamic loop may execute several iterations inside one region. In the worst
case, a backedge saves the next iteration's live values and returns to the
dispatcher.

### Why the verifier accepts this dispatcher

The dispatcher is three bounded loops. The innermost one, the step, runs up to
thirty-two regions and returns; the level above calls the step up to 2,048
times; the entry program calls that level up to 64 times. The two inner loops
are global functions of their own, and the verifier checks a global function
once without descending into it from a call site, so analysis complexity adds
up while the number of transitions at runtime multiplies: 32 × 2,048 × 64 is
about 4.2 million regions in one invocation, even though the graph proved by
the kernel stays small.

Batching regions inside the step also buys speed: every region after the first
reuses one function call instead of paying for its own.

When the computation finishes, `capsule_call()` returns `CAPSULE_OK`. If it
uses the entire transition budget, the BPF invocation still terminates and
returns `CAPSULE_PENDING` with a continuation number. A later invocation may
pass that number to `capsule_continue()`.

For DOOM, I expect initialization and every frame to fit in one invocation.
Capsule knows nothing about that expectation and has no game-specific behavior.
The example integration simply never calls `capsule_continue()` and treats any
`PENDING` as a regression.

## What pointer laundering became

The old `globalConv` was enough for the first prototype, but an entire memory
model built on lies in BTF was not viable. The current design starts with one
4-GiB-aligned virtual window containing globals, the heap, and software stacks.

```text
                 the in-kernel BPF code
   v v v v v v v v v v v v v v v v v v v v v v v v v
   +-----------------+-----------+-----------------+
   |     globals     |    heap   |   fiber stacks  |
   +-----------------+-----------+-----------------+
   ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^
                 the userspace process

   window base, 4-GiB aligned                + 4 GiB
   one range of addresses, the same on both sides
```

A Capsule pointer is an ordinary `window_base + displacement` address. It has
the same 64-bit value inside BPF and in the userspace process. Its low 32 bits
are the displacement within the window.

Ordinary globals move into this window: `static` variables, strings, tables,
and zero-filled buffers. Their initial values must arrive there too; how that
happens depends on the memory backend.

Explicitly sectioned objects stay outside this transformation. Maps in
`SEC(".maps")` and control blocks such as DOOM's `SEC(".data.ctrl")` remain
ordinary BPF maps loaded by libbpf. The control block carries pointers, sizes,
and input; the WAD and framebuffer themselves live in the shared window.

On Linux 6.9 and newer (6.10 on arm64, where JIT support for the arena landed
later), the window is backed by `bpf_arena`: libbpf loads globals with non-zero
initial contents from ELF, and Capsule initialization allocates zero pages for
the remaining globals, heap, and stacks. A full pointer can be stored,
compared, and returned as an ordinary number—a scalar to the verifier. Before
dereferencing it, the compiler runs it through the special BPF
`addr_space_cast` instruction. The verifier marks the temporary result as
`PTR_TO_ARENA`, and only that result touches memory:

```text
full window + offset pointer
   |
   +-- store / compare / return --> the same 64 bits, a scalar
   `-- addr_space_cast --> PTR_TO_ARENA --> memory access
```

On kernels without a usable arena, the same four gigabytes are assembled from
4-MiB pieces. The compiler lays globals out consecutively, serializes their
initial values into a flat byte image, and cuts the first pieces of that image
into separate global-data maps. How many is up to the linker, which takes
whatever is left of the map budget — usually 32. A piece containing any
non-zero byte becomes `.data.heapN`; an entirely zero-filled piece becomes
`.bss.heapN`. Only one of the two maps exists for any index. All later pieces,
including software stacks, become 4-MiB values in one `ARRAY` map.

```text
full pointer p
   offset = low 32 bits of p
   piece  = offset >> 22         within = offset & (4 MiB - 1)
   |
   +-- piece known at compile time --> its .data.heapN / .bss.heapN + within
   `-- unknown --> switch over direct maps
                   `-- beyond them --> ARRAY lookup for the tail
```

The general router is expensive, so not every access uses it. If the compiler
can see that `p` derives from a particular global, it selects that map
immediately and leaves only a mask and addition. On the arena tier, one
`addr_space_cast` result is similarly reused for several accesses from the same
base.

A boundary between two pieces needs care. A map value cannot be read past its
end, and an access lying across two pieces would need two map lookups. Pieces
are 4-MiB aligned, so an access aligned to its own width cannot cross one: a
naturally aligned `uint64_t` lies entirely inside a single piece. The compiler
therefore trusts LLVM's alignment information. Before routing, it splits every
load or store whose alignment is smaller than its width into naturally aligned
fragments, each selecting its own map: an eight-byte load through a
four-aligned pointer becomes two four-byte loads, and a one-aligned one becomes
eight single-byte loads. Claiming an alignment that is not there is undefined
behavior, exactly as on any other platform.

The userspace process maps the same pages at the same addresses. BPF can
therefore return an `unsigned char *` to the framebuffer, and the process can
check its bounds, read it directly, and follow pointers stored in shared
memory. No handles, object serialization, or copying through a special map API
are required.

### The heap and non-suspending operations

The shared window provides an address space, but `malloc()` still needs an
implementation. Capsule uses TLSF: its metadata and blocks live in the shared
heap, while `malloc()` and `free()` execute inside BPF with the rest of the
program. Fibers share one heap, but each keeps its own software stack.
Userspace allocates from the same heap through `bpf_capsule_malloc()`, which
runs the guest allocator in the kernel through `BPF_PROG_TEST_RUN`.

While TLSF holds a lock and edits free lists, the computation must not return
to the dispatcher. `CAPSULE_NOSUSPEND` marks allocator functions: the compiler
must prove that each function and everything it calls finish without
suspension. An unprovable loop or suspendable call becomes a build error. A
short TLSF operation therefore stays in one ordinary BPF call with no
dispatcher boundary: it cannot suspend between acquiring and releasing its
lock. If the lock is busy, ordinary `malloc()` retries outside that operation.

### Where the transformation stops

Not every pointer can or should be transformed. Globals explicitly placed in a
BPF section remain ordinary maps. A local whose address is passed to a BPF
helper remains on the real 512-byte BPF stack. A pointer returned by a helper
or kfunc keeps its verifier type as well. If the kernel can already prove an
access, the compiler does not route it through the shared window.

XDP makes the boundary especially clear. An ordinary entry program starts
Capsule code like this:

```c
SEC("xdp")
int observe(struct xdp_md *ctx)
{
    size_t output_size;
    struct capsule_result r =
        capsule_call_ctx(ctx, &output_size, run_lua);
    if (r.status == CAPSULE_PENDING)
        (void)capsule_reset(r.continuation);
    return XDP_PASS;
}
```

`observe` remains an ordinary BPF program, while `ctx` is a special pointer
whose history is tracked by the verifier. It is not an argument of `run_lua`:
the `_ctx` suffix explicitly selects a separate channel between ordinary BPF
and Capsule. This pointer cannot be stored in a software frame; after a reload
from a map or arena it would be only a scalar. The compiler therefore splits
regions into two classes:

```text
capsule_call(...)               --> scalar dispatcher --> scalar regions only
capsule_continue(...)           --> scalar dispatcher --> scalar regions only
capsule_call_ctx(ctx, ...)      --> ctx dispatcher    --> both region classes
capsule_continue_ctx(ctx, ...)  --> ctx dispatcher    --> both region classes
```

A scalar region needs only a fiber number and saved state. A context region
also receives the real `struct xdp_md *` as its first BPF-function argument.
That keeps `ctx` in registers and on the real BPF stack throughout the call
chain, never in fiber memory. Deep inside Capsule code, it can be obtained once
through `capsule_borrowed_ctx()` and then used as an ordinary variable; the
compiler carries the hidden argument across region boundaries.

On continuation, the context is not restored from the fiber. The calling BPF
program supplies it again through `capsule_continue_ctx()`. If a yield resumes
immediately within the same XDP invocation, it will be the same `ctx`. If
continuation happens later, the current `ctx` may describe another packet:
Capsule promises no identity between them. Lua-XDP expects packet parsing to
finish in the original invocation and resets the fiber on any `PENDING`. A
long-running computation that needs packet bytes must copy them into the shared
window first.

Even within the original invocation, a packet pointer obtained from `ctx`
cannot be stored in a software frame or carried into the next region. The
compiler can reinsert the root `ctx`, but `data` and `data_end` must be loaded
and checked again. Attempting to preserve a packet pointer stops the build.

## What else the compiler has to do

Regions solve control flow, but do not add the missing pieces of the BPF ABI.
The compiler also:

- packs calls with many or variable numbers of arguments;
- lowers large structure returns;
- replaces floating-point and 128-bit arithmetic with the software
  implementations from compiler-rt, compiled into the same object;
- expands dynamic `memcpy`, `memmove`, and `memset`;
- turns function pointers into packed region IDs;
- repairs BTF names and types;
- moves excess temporary values out of the BPF stack after register allocation,
  while leaving pointers whose types the verifier must see on that stack.

Exactly one computation involving `double` survives into PureDOOM's executable
code. It would be easy to rewrite, but I left it alone: this path goes through
the same soft-float lowering as any other program.

LLVM itself remains unpatched. `bpf-capsule-cc` emits bitcode; `bpf-capsule-ld`
links the whole program with the runtime, runs Capsule's passes, and only then
gives the result to LLVM's ordinary BPF backend for ELF and BTF emission. The C
library is Picolibc, linked as a bitcode archive from which the linker extracts
only the members the program reaches. A small platform layer supplies what the
C library expects from a system: a fiber-local `errno`, the TLSF heap, and OS
functions that fail until the application replaces them.

## What remains of the DOOM integration

After all this work, the integration is almost boring. PureDOOM is designed to
be embedded: the surrounding program supplies a small set of C functions for
memory, WAD reads, time, input, and exit. In Capsule these are not calls into
userspace: `malloc()`/`free()`, WAD reads, and the engine itself are compiled
into one BPF object and execute in the kernel.

Userspace participates only at the outer boundary. At load time it reserves
exactly enough Capsule memory for the WAD, copies the file once, and gives the
engine an ordinary `unsigned char *` and size. From then on, BPF code reads the
WAD in place.

Initialization is one BPF entry point. Each game tick, including complete
rendering, is another. After rendering, BPF publishes a pointer to the
framebuffer inside the shared window. Userspace checks the `320 * 200 * 4`
range and reads the pixels directly for terminal or PPM output.

A deterministic test supplies one input sequence, hashes the frames, and
compares them across kernel profiles. It catches both a wrong image and an
unexpected `PENDING` during frame processing.

## The price of getting large code into the kernel

There is no single honest number for "Capsule is N times slower." The cost
depends on how often execution crosses a region boundary, how much memory the
program touches, and how much floating point it does. So every example measures
itself: the in-kernel figure comes from BPF's own accounting, the native one
from the CPU time of the same workload in userspace. Loading and verification
are outside these timings. CPython's native mode uses the flake's host Python
3.14; both Python timings include interpreter startup.

All numbers below come from two machines with the governor set to
`performance`, each run pinned to one core. The first is an Intel i7-12700K on
Linux 7.1.3, measured on a performance core at 4.9 GHz, with the examples built
for the 6.9 profile:

| Example | Native | In kernel | Ratio |
|---|---:|---:|---:|
| DOOM, one frame | 0.105 ms | 0.367 ms | **3.5×** |
| SQLite | 43.8 ms | 289.4 ms | **6.6×** |
| Lua | 70.1 ms | 524.0 ms | **7.5×** |
| QuickJS | 116.6 ms | 1068.0 ms | **9.2×** |
| CPython | 120.9 ms | 1889.2 ms | **15.6×** |
| llama2.c, Q8 | 14.6 ms | 274.8 ms | **18.8×** |
| llama2.c, FP32 | 7.5 ms | 471.2 ms | **62.9×** |

The second is an ARM64 machine on Linux 7.0.12, measured on one of its big
Cortex-A720 cores at 2.6 GHz — the same idea as the Intel P-core, next to
smaller Cortex-A520 cores that would give quite different numbers. There the
examples are built for the 6.10 profile, the first one with an arena on arm64:

| Example | Native | In kernel | Ratio |
|---|---:|---:|---:|
| DOOM, one frame | 0.227 ms | 0.913 ms | **4.0×** |
| SQLite | 81.4 ms | 639.2 ms | **7.9×** |
| Lua | 127.6 ms | 1090.4 ms | **8.5×** |
| QuickJS | 224.0 ms | 2313.1 ms | **10.3×** |
| CPython | 242.3 ms | 4487.9 ms | **18.5×** |
| llama2.c, Q8 | 23.2 ms | 539.3 ms | **23.2×** |
| llama2.c, FP32 | 13.0 ms | 775.2 ms | **59.6×** |

Every row is a median of three runs. The
[workloads and build recipes](https://github.com/ayles/bpf-capsule/tree/6733c4531f06f95a32a35c2084b3dcf1a4263746/examples)
are in the repository; the flake pins the toolchain, including LLVM 23. From a
checkout, a pair looks like this (`-610` on arm64):

```console
$ sudo taskset -c 0 nix run .#lua-69 -- examples/lua/benchmark.lua
$ taskset -c 0 nix run .#lua-69 -- --native examples/lua/benchmark.lua
```

These are comparisons within each example, not a race between interpreters:
their benchmark scripts differ. The shape of the table matters more than any
single number. Integer and pointer code — DOOM, SQLite — runs a few times
slower than native userspace; the
interpreter from the first attempt cost about sixty times native on exactly
that kind of code. Interpreters land around an order of magnitude, because
their own dispatch loops also cross region boundaries. CPython sits at the
far end of that group on both machines. Reference counting, allocation, and
helper calls all add work in the places Capsule makes expensive; the table
does not isolate their individual contributions.
Floating point is the outlier: llama2.c's FP32 model is sixty times slower
because the target has no FPU and every operation becomes a call into software
floating point. Q8 replaces much of that arithmetic with integer work, and the
penalty falls to about nineteen to twenty-three times.

Compatibility costs too. The same example without a suffix — `nix run .#lua` —
is built for Linux 5.15, where there is no arena and dynamic heap accesses go
through the map router. The Lua benchmark then takes 983.6 ms on the Intel
machine instead of 524.0. Old kernels are supported, not free.

Every number so far comes from a program that runs to completion in its own
time. A packet observer does not get that luxury. The ready-to-run [Lua-XDP
example](https://github.com/ayles/bpf-capsule/tree/6733c4531f06f95a32a35c2084b3dcf1a4263746/examples/lua-xdp)
attaches Lua 5.5.1 to a real XDP hook, and its CPython twin does the same with
an interpreter that has a standard library. A script supplied at startup sees
every received packet and emits results through a ring buffer:

```console
$ sudo nix run .#lua-xdp-69 -- examples/lua-xdp/packet_observer.lua eth0
```

The natural question is what that costs a real link. Both machines have a
gigabit interface, so I measured a download with and without an observer,
using the same arena profiles as above (`-610` on arm64). Per-packet time is
the XDP program's accumulated kernel run time divided by its invocation count.
For these runs the receive queue's interrupt was pinned to a performance core
through `/proc/irq/N/smp_affinity_list`:

| Observer | Intel, download | per packet | ARM64, download | per packet |
|---|---:|---:|---:|---:|
| none | 995.9 Mbit/s | — | 994.5 Mbit/s | — |
| Lua | 643.3 Mbit/s | 16.7 µs | 295.5 Mbit/s | 35.4 µs |
| CPython | 368.2 Mbit/s | 30.8 µs | 76.3 Mbit/s | 131.1 µs |

XDP runs on receive, but an upload still produces incoming ACKs for the
observer to process; it is not exempt from the cost. Both example observers
format one line per packet and ship it to userspace; a script that parses the same headers and
returns silently costs 5.8 µs per packet in Lua and 25.1 µs in CPython on the
ARM64 machine, and the Lua one leaves the gigabit almost intact, at 964.6
Mbit/s. These link measurements include the effects of packet sizes, network
conditions, and draining the output ring buffer. They are workload results,
not a universal throughput limit for either interpreter.

## LLVM and the verifier still do not agree

The verifier solves the right problem: a bug in a loaded program must not crash
the kernel. LLVM is equally entitled to replace a program with a semantically
equivalent one. The trouble is at the boundary. Two forms can be identical to
the CPU while only one lets the verifier recognize the required proof.

Today this contract depends on `volatile`, inline assembly, control-flow shape,
and BTF. An LLVM update can remove a necessary instruction; a verifier change
can break an old proof. The log usually identifies the final forbidden access,
not the earlier point where a pointer bound was lost.

This is not merely archaeology from my project: at the time of writing, LLVM
carries two bugs with small reproducers. The first is [a BPF code-generation
bug where a conditional branch through an empty block lands on the wrong
instruction](https://github.com/llvm/llvm-project/issues/208984): the compiler
silently emits a plausible but incorrect object. The second is that adding `-g`
can [change a C++ function prototype and drop an
argument](https://github.com/llvm/llvm-project/issues/208141): a program with
debug information differs from the same program without it.

The answer to that gap is not to weaken the verifier but to write an explicit
contract between it and the compiler: operations whose meaning is guaranteed to
survive optimization, diagnostics that track pointer provenance, and end-to-end
tests across LLVM IR, BPF, BTF, and several kernel versions. Physical ABI
limits should likewise be transformed by a shared layer rather than worked
around anew in every large BPF project.

BPF Capsule ships its own passes because that layer does not exist yet. A good
outcome for the project would be deleting those passes in favor of shared
infrastructure, not maintaining a private LLVM pipeline forever.

## What Capsule does not do

A few limits are worth stating plainly before anyone builds on this.

- This is research software, not a security boundary between guest components.
  The kernel's BPF checks still apply, but Capsule does not protect one part
  of a program from another.
- There is no operating system inside: no files, sockets, processes, or
  threads. There is a C library, an allocator, and fibers; anything resembling
  a system call is implemented by the application or supplied by the host.
- Every capacity is finite and fixed at build or load time: the number of
  fibers, the size of the stack and heap, the budget of a single call.
- The proofs the verifier accepts depend on LLVM and kernel versions. CI checks
  the supported profiles, but a new version of either may require changes.

## What the kernel ultimately sees

The tests go beyond successful loading: they compare llama2.c's generated
tokens with a native run, check DOOM's frames, and exercise CPython imports and
packet processing from two CPUs. CI builds each supported capability profile
and runs it on a compatible packaged kernel, not necessarily the exact version
named by the profile. CPython is tested only on profiles with arena memory and
the other features its port requires; it is not a Linux 5.15 example.

One more port has already run end to end: the `scx_rustland` scheduler, moved
into the kernel on Capsule, schedules real tasks with numbers comparable to its
userspace original. A good scheduler on Capsule is a different project, and a
different article.

LLM tools sped the work up considerably. Alongside a day job, I probably would
not have brought the project this far without them.

The verifier never proves that DOOM terminates. It proves that the next region
and the bounded dispatcher terminate. At runtime, Capsule assembles the
complete game out of those finite pieces.

## Further reading

- [BPF Capsule](https://github.com/ayles/bpf-capsule) — source, examples, and
  instructions for running them.
- [Linux verifier](https://docs.kernel.org/bpf/verifier.html) — register types,
  value ranges, stack behavior, and state merging.
- [BPF Design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html) — calling
  convention and verifier constraints.
- [RFC 9669: BPF ISA](https://www.rfc-editor.org/rfc/rfc9669.html).
- [The commit that introduced `bpf_arena`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=317460317a02a1af512697e6e964298dedd8a163).
- [Flying the nest — a BPF port of Doom](https://lpc.events/event/18/contributions/1936/).
