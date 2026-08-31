+++
title = "DOOM in the kernel, or fibers in eBPF"
date = 2026-08-31
description = "How a hand-ported DOOM, verifier tricks, and a slow virtual machine led to a compiler built around regions and fibers."
draft = false
+++

DOOM is not supposed to run inside eBPF. Linux should reject a program like
that before executing its first instruction.

BPF has a tiny stack, five argument registers, and limited call depth.
Recursion is forbidden. A loop must be finite not merely because the
programmer says so, but in terms the verifier can prove. You cannot simply
store a pointer in memory, load it later, and dereference it: the kernel must
remember where it came from and what it is allowed to address.

And yet an unmodified Linux kernel accepts my BPF object, checks it with the
stock verifier, and runs it through the stock JIT. DOOM initialization, game
logic, and rendering all execute in the kernel. One game tick, including the
complete frame, finishes in a single BPF invocation. Userspace supplies the WAD
and keyboard input and gets back a pointer to the finished framebuffer.

The project is called [BPF Capsule](https://github.com/ayles/bpf-capsule). It
is a compiler and runtime for large C programs inside ordinary BPF, with no
kernel patches and no separate virtual machine in userspace.
The oldest supported target is Linux 5.15; I have loaded and run the programs
on both x86-64 and arm64.

On Linux 6.9 or newer, it can be tried immediately after cloning the repository
(the WAD is naturally not included):

```console
$ git clone https://github.com/ayles/bpf-capsule.git
$ cd bpf-capsule
$ sudo nix run .#doom -- /path/to/doom1.wad tty
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

In practice, “write C” means writing in two rather different languages at
once. LLVM understands one. The Linux verifier understands the other.

I became intimately familiar with that boundary while working on
[Perforator](https://github.com/yandex/perforator). That is where I accumulated
enough frustration with the current BPF stack to go this far.

Before loading a program, the verifier symbolically executes it. For every
register it tracks not only a value or range, but a meaning: an ordinary
number (`SCALAR_VALUE`), a pointer to the stack, packet data, a map value, or a
`bpf_arena`. It explores branches, merges states, and proves two things: every
memory access is allowed, and every execution path eventually terminates.

That creates constraints an ordinary program barely notices:

- `r1` through `r5` are all the argument registers in the classic ABI;
- the call graph must be acyclic, and call depth is limited;
- only 512 bytes of stack are available along a call chain;
- one object may contain no more than 256 BPF functions;
- after processing roughly a million instructions, the verifier gives up.

That last limit is not an execution-time limit. The analyzer can walk a
ten-instruction loop a thousand times with distinct states and exhaust the
budget. A finite loop is legal; the problem starts when the kernel cannot prove
its bound or has to enumerate too many possibilities.

Memory is more entertaining still. To the CPU, a pointer is ultimately just a
number. To the verifier, it is a number with a biography. It may know that
`r10 - 8` points into a valid BPF stack slot, or that `data + n` remains within
a packet after a check against `data_end`. Store that pointer as ordinary 64
bits and load it back, and the CPU gets the same address while the verifier
gets a number with no right to be dereferenced.

Normal C programs constantly put pointers in structures, pass those structures
through several functions, and load the pointers much later. Somewhere along
that route, the verifier loses the proof.

### A current LLVM example

It is not enough to write a valid bounds check in C: the kernel sees the code
after optimization. Here is a real fragment of
[packet-processing BPF code](https://github.com/ayles/bpf-capsule/blob/e6ac4118411d5c5100186f3878e11f1e483b3f31/examples/lua-xdp/lua_xdp_runtime.c):

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

Before involving the kernel, there is an intermediate step: compile DOOM to
BPF and run the object in a userspace virtual machine. With no verifier, code
generation bugs can be separated from failures to prove safety.

I based the experiment on [PureDOOM](https://github.com/Daivuk/PureDOOM), a port
that packages the whole engine into one C header and exposes a short embedding
interface. It is convenient for an experiment like this while leaving DOOM
itself almost entirely ordinary C.

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

DOOM had been run in a userspace BPF machine before. One example is
[Flying the nest — a BPF port of Doom](https://lpc.events/event/18/contributions/1936/),
which used its own νBPF VM. Inside a VM, you can change the machine's rules. My
goal was different: an object accepted by the ordinary Linux verifier and
executed by the ordinary in-kernel BPF JIT.

## Porting with scissors

The next step was loading the program into a real kernel. The freedom of uBPF
ended there: I could not increase the 512-byte frame, call depth, or verifier
budget. The first attempt was as direct as possible—take PureDOOM and remove
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
two hacks.

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

Reversing the subtraction looks like a ready-made escape hatch. Take a real
pointer to the right boundary of a section: on the CPU, `end_ptr - x` would
produce a small distance to its end. Starting from the left boundary could
similarly produce a small negative displacement. Such an operation on a map
pointer is legal only when its second operand is already bounded. The verifier
does not know that scalar `x` contains an address from the same map, so it sees
an enormous or completely unknown pointer offset. The allowed arithmetic range
is limited by `BPF_MAX_VAR_OFF`, or `2^29`, and this check happens before any
later subtraction. Reducing the two bases afterwards is too late: the program
is rejected at the first operation.

The same section base therefore had to exist in two forms—double-entry
bookkeeping. A laundered copy could be subtracted from the unknown address,
while the original copy, still carrying its verifier biography, could be used
after checking the result:

```text
address loaded from memory x ────────────────────┐
                                                 v
start of .data ── launder ──> scalar base ──> x - base = offset
      |                                          |
      |                             0 <= offset <= size - width
      |                                          |
      `── PTR_TO_MAP_VALUE ─────────────────────>+ offset
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

BTF—the type table shipped alongside BPF code—deliberately told the kernel
that this function took no arguments and returned `u64`, even though the
machine code used `r1`. The store into the map consequently looked like a
store of an ordinary number, and the caller received a scalar as well. The
comment was honest: `Fool the verifier into thinking that there are no args`.

The section base needed another ugly trick. The pass inserted one synthetic
global at the beginning of both `.data` and `.bss`; a reference to it became
the real base of the corresponding map after load. At first, section size was
computed as the sum of LLVM globals, but the final layout and alignment do not
exist until ELF emission. In the last surviving version of this experiment,
the computed result was simply overwritten by two hard-coded constants.

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

The first loop pass wrapped every loop in
`bpf_iter_num_new`/`next`/`destroy` with a large emergency bound. It then grew
more aggressive: every counter and pointer advanced by the loop was expressed
through a single iteration number, `n`.

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

## The dumbest complete solution

If program code is stored as data, the verifier does not need to analyze its
control-flow graph. It checks one small interpreter. The next instruction
number, registers, stack, and guest call frames live in maps. Each BPF
invocation interprets a fixed number of instructions and then returns.
Termination is obvious.

I tested this literally: first an interpreter for real eBPF inside eBPF, then
an RV64IM interpreter and loader for ordinary RISC-V ELF files. A checksum and
zlib produced correct results, but an archived single-core zlib measurement
was roughly **60×** slower than native code. Most of the time, the kernel was
not running zlib at all. It was running `switch (opcode)`: the virtual machine
returned to the dispatcher after every guest instruction.

The unit of interpretation had to be much larger than one instruction. The
virtual machine state, however, was worth keeping.

## What if one instruction is a piece of the program?

Instead of an `add`, `load`, or `jump`, one operation in the new machine
contains a whole piece of already compiled code. Ordinary BPF runs inside that
piece, then saves its state and returns to a small dispatcher.

I call such a piece a **region**. A region is bounded: it ends at a complex
call, a return, a `yield`, an inconvenient loop backedge, or wherever the
compiler decides to cut an oversized graph. It runs in full, saves live
values, and returns to the dispatcher. The source program may suspend only at
that boundary; in this sense, a region is atomic. The dispatcher invokes the
next region. To the verifier this is an ordinary caller–callee boundary, not
another part of DOOM's enormous control-flow graph.

The verifier therefore never analyzes the whole path through the source
program. It sees a small region and a bounded dispatcher. A normal call is
split roughly like this:

```text
render_frame:   [ region 17 ] -- call --> [ region 18: continuation ]
                                      \
                                       `-> R_DrawPlanes:
                                           [ region 42 ] -> [ region 43 ]

region boundary:
       save live values and continuation number
                         |
                         v
                return to dispatcher
                         |
                         v
                run selected region
```

A region does not have to become a separate BPF function. LLVM first generates
code and allocates registers for small independent groups of regions—usually
one group per source function, with very large functions split again. Capsule
then packs several completed groups, including groups from different source
functions, into one real BPF function.

One BPF function per region would quickly hit the 256-function limit. One
function for the whole program is bad as well: the kernel repeatedly performs
live-value analysis across the entire monster and load time explodes. Instead,
the object contains several physical functions of roughly equal size:

```text
regions from source functions       physical BPF object

render:  17, 18  ┐                  BPF function 0: 17, 42, 61
planes:  42, 43  ├─ packing ------> BPF function 1: 18, 43
things:  61      ┘

next region number
        |
        +-- upper tree selects a BPF function
        `-- local tree selects a region inside it
```

In the Linux 7.1 profile, address tables and `gotox` replace those trees. The
instruction can jump only within the current BPF function. At the upper level
it therefore selects a tiny block with a direct call to the required physical
function; inside that function, the same mechanism selects the region. Linux
does not support an indirect `callx`. The principle is unchanged: a number in
fiber state selects a large piece of ordinary JIT code. Source C function
boundaries define the software stack; physical BPF function boundaries keep
the object digestible for the verifier.

This remains BPF compiled by the stock JIT, not interpreted LLVM IR or another
ISA. The verifier checks every instruction inside a region, and the kernel JIT
compiles it. What remains of the virtual machine is an explicit next-operation
number, stack, and state—but dispatch happens at the boundary of a large piece
of work rather than after every `add`.

## Where the fibers and second stack came from

Once a function call is split by a region boundary, the ordinary BPF call
stack is no longer enough. Arguments, locals, and the return address need
somewhere to survive the transition. That became a software stack in Capsule
memory.

The caller places everything that must cross the boundary there, creates a
callee frame, records the callee's first region, and returns to the dispatcher.
Later, the callee writes its result into the caller's frame, restores the
continuation number, and returns through the dispatcher too.

This has a small ABI of its own. A frame looks roughly like this:

```text
                    higher addresses
        +--------------------------------+
fp ---> | result area                    |  written by the callee
        +--------------------------------+
 fp-8   | region to run after return     |
 fp-16  | caller's fp                    |
        +--------------------------------+
        | argument 0                     |  one common stride for arguments
        | argument 1                     |
        | local values                   |
sp ---> +--------------------------------+  allocated-stack frontier
                    lower addresses
```

The stack grows toward lower addresses: `fp` marks the current frame boundary,
while `sp` marks the lower edge of allocated space. A call changes only `fp`,
`sp`, and the next region number. A return performs the three operations in
reverse. A sixth argument, deep call chain, or recursion therefore consumes no
additional registers or frames in the real BPF ABI: as far as the kernel is
concerned, each region still returns normally.

Recursion does not turn into recursive calls between BPF functions. Every
source call merely pushes another software frame. A function pointer becomes a
checked number identifying its entry region.

The real BPF stack does not disappear. Its 512 bytes serve as scratch space for
the current region. Values that must outlive a region are moved into the
software frame.

One set consisting of the current region, stack and frame pointers, state, and
its own software-stack slice forms a **fiber**. There may be several fibers:
each has separate state and stack storage, while globals and the heap are
shared.

The runtime field named `PC` is not a processor instruction address. It is
simply the compiler-assigned number of the next region—closer to a region
counter than a real program counter. The name survived from the virtual
machine.

`capsule_yield()` deliberately uses the same boundary. State remains in the
fiber, while the caller receives a number that can resume the work in a later
BPF invocation. The number includes the fiber generation, so a stale value
cannot accidentally resume a different task that has reused the same slot.

Loops no longer have to be normalized into one exact IR pattern after
optimization. A small loop with a proven bound remains an ordinary BPF loop. A
hot dynamic loop may execute several iterations inside one region. In the
worst case, a backedge saves the next iteration's live values and returns to
the dispatcher.

### Why the verifier considers this finite

The dispatcher contains two separate functions with loops of 2,048 iterations.
The verifier checks those functions independently: analysis complexity adds,
while the number of transitions at runtime multiplies. One invocation can
execute roughly 4.2 million regions even though the graph proved by the kernel
remains small.

When the computation finishes, `capsule_call()` returns `CAPSULE_OK`. If it
uses the entire transition budget, the BPF invocation still terminates and
returns `CAPSULE_PENDING` with a continuation number. A later invocation may
pass that number to `capsule_continue()`.

For DOOM, I expect initialization and every frame to fit in one invocation.
Capsule knows nothing about that expectation and has no game-specific behavior.
The example integration simply never calls `capsule_continue()` and treats any
`PENDING` as a regression; tests confirm this on the supported profiles.

## What pointer laundering became

The old `globalConv` was enough for the first prototype, but an entire memory
model built on lies in BTF was not viable. The current design starts with one
4-GiB-aligned virtual window containing globals, the heap, and software stacks.

```text
                         one 4-GiB virtual window
BPF code <----> [ globals | heap | fiber stacks ] <----> userspace process
                         same pages and addresses
```

A Capsule pointer is an ordinary `window_base + displacement` address. It has
the same 64-bit value inside BPF and in the userspace process. Its low 32 bits
are the displacement within the window.

The pass first moves ordinary globals used by Capsule code into this window:
`static` variables, strings, tables, and zero-filled buffers without an
explicit BPF section. Every use becomes an address in the window. C
initializers still matter: `static int x = 7`, strings, and ready-made tables
must be loaded with the program, while a large zero-filled array only needs an
address range. The way this initial state is represented depends on the kernel
version.

Explicitly sectioned objects are left alone. Maps in `SEC(".maps")` and control
blocks such as DOOM's `SEC(".data.ctrl")` remain ordinary BPF maps loaded by
libbpf. Through this small block the process gives DOOM a WAD pointer, its
size, and input; BPF returns the frame pointer and call result. The WAD and
framebuffer themselves live in the shared window and do not need to be copied
through the control map.

On Linux 6.9 and newer, the window is backed by `bpf_arena`: libbpf loads
globals with non-zero initial contents from ELF, and Capsule initialization
allocates zero pages for the remaining globals, heap, and stacks. A full
pointer can be stored, compared, and returned as an ordinary number—a scalar
to the verifier. Before dereferencing it, the compiler runs it through the
special BPF `addr_space_cast` instruction. The verifier marks the temporary
result as `PTR_TO_ARENA`, and only that result touches memory:

```text
full window + offset pointer
        |
        +-- store / compare / return --> the same 64 bits
        |
        `-- addr_space_cast --> PTR_TO_ARENA --> memory
```

Linux 5.15 through 6.8 have no arena, so the same four gigabytes are assembled
from 2-MiB pieces. The compiler lays globals out consecutively, serializes
their initial values into a flat byte image, and cuts its first 32 pieces into
separate global-data maps. A piece containing any non-zero byte becomes
`.data.heapN`; an entirely zero-filled piece becomes `.bss.heapN`. Only one of
the two maps exists for any index. All later pieces, including software stacks,
become 2-MiB values in one `ARRAY` map.

```text
full pointer p
        |
        v
 offset = low 32 bits of p
 region = offset >> 21          within = offset & (2 MiB - 1)
        |
        +-- region known at compile time --> its .data.heapN or .bss.heapN + within
        |
        `-- unknown --> switch over direct maps
                              `--> ARRAY lookup for the tail
```

The general router is expensive, so not every access uses it. If the compiler
can see that `p` derives from a particular global, it selects that map
immediately and leaves only a mask and addition. On the arena tier, one
`addr_space_cast` result is similarly reused for several accesses from the same
base.

There is an odd detail at a boundary between two pieces. The verifier permits
an eight-byte load only within one map value, while C permits an unaligned
`uint64_t` beginning four bytes before the end of a region. Every physical
piece is therefore eight bytes longer than its logical size:

```text
region N:     [----------- 2 MiB -----------][shadow 8 B]
region N + 1:                                  [first 8 B][--------- ...
                                                ^       ^
                                                `-- copy --'
```

Writing the first eight bytes of the next region also updates the previous
region's shadow. A cross-boundary write synchronizes the real prefix of the
next region. One unaligned instruction consequently stays within a single map
value while observing continuous memory. Userspace maps these pieces next to
one another in the same window.

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

While TLSF holds a lock and edits free lists, the computation must not return to
the dispatcher. `CAPSULE_NOSUSPEND` marks allocator functions: the compiler
must prove that each function and everything it calls finish without
suspension. An unprovable loop or suspendable call becomes a build error. A
short TLSF operation therefore stays in one ordinary BPF call with no
dispatcher boundary: it cannot suspend between acquiring and releasing its
lock. If the lock is busy, ordinary `malloc()` retries outside that operation.

### Where Capsule ends

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
capsule_call(...)              -> scalar dispatcher -> scalar regions
capsule_call_ctx(ctx, ...)     -> ctx dispatcher    -> both region classes
capsule_continue(...)          -> scalar dispatcher -> scalar regions
capsule_continue_ctx(ctx, ...) -> ctx dispatcher    -> both region classes
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
- lowers large structure returns and some i128 operations;
- replaces floating-point operations with integer implementations;
- expands dynamic `memcpy`, `memmove`, and `memset`;
- turns function pointers into checked numbers;
- repairs BTF names and types;
- moves excess temporary values out of the BPF stack after register allocation,
  while leaving pointers whose types the verifier must see on that stack.

Exactly one computation involving `double` survives into PureDOOM's executable
code. It would be easy to rewrite, but I left it alone: this path goes through
the same soft-float lowering as any other program.

LLVM itself remains unpatched. `bpf-capsule-cc` emits bitcode;
`bpf-capsule-ld` links the whole program with the runtime, runs Capsule's
passes, and only then gives the result to LLVM's ordinary BPF backend for ELF
and BTF emission.

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

## What it costs

There is no honest single number for “Capsule is N times slower.” DOOM cannot
be built as direct BPF for a neighboring column, and Capsule's cost depends on
region transitions, memory access, and software floating-point arithmetic.

Four execution modes can only be compared on a synthetic task they share. I
used the checksum from the eBPF interpreter: one thousand repetitions of a
short `xor`, `mul`, and `add` sequence. The guest version also makes an
internal call and uses its own stack, for a total of 5,008 guest instructions.
All four produce the same result:

| Execution | Time relative to native code |
|---|---:|
| native AArch64 | **1.00×** |
| direct eBPF through the kernel JIT | **1.67×** |
| BPF Capsule regions through the kernel JIT | **3.87×** |
| eBPF interpreter inside eBPF | **61.4×** |

The empty `BPF_PROG_TEST_RUN` cost is subtracted from the BPF variants. The
table contains medians from seven interleaved runs on one CPU. Absolute
nanoseconds say little here: they describe one ARM64 machine, while the ratios
describe only this particular experiment.

This is an intentionally favorable case for Capsule: its main loop fits in one
large region. The interpreter returns to its dispatcher after every guest
instruction; Capsule returns after the whole loop. Regions are therefore
**15.8 times faster** than the interpreter here. The 3.87× figure is not an
estimate for arbitrary Capsule programs. The experiment answers a narrower
question: how much is gained by dispatching large pieces of JIT code instead
of individual instructions?

I measured real programs separately. With one WAD and an identical sequence of
100 frames, DOOM inside Capsule was roughly **four to five times slower** than
a native build of the same PureDOOM. That ratio is not only region dispatch:
even direct eBPF through the kernel JIT trails native code in the common
synthetic test above. Memory routing, the software stack, and the other Capsule
transformations add their costs on top. DOOM cannot be built as direct BPF, so
there is no honest extra column that would separate those parts.

There is a less playful workload too. The ready-to-run
[Lua-XDP example](https://github.com/ayles/bpf-capsule/tree/e6ac4118411d5c5100186f3878e11f1e483b3f31/examples/lua-xdp)
attaches Lua 5.4 to a real XDP hook: a script supplied at startup can inspect
arbitrary packets and emit results through a ring buffer. On the particular
ARM64 machine I tested, a hot sequence of identical packets took tens of
microseconds per packet—roughly twenty thousand packets per second on one core.
A custom script can be started with:

```console
$ sudo nix run .#lua-xdp -- examples/lua-xdp/packet_observer.lua eth0
```

The DOOM ratio is hardware-specific as well. Both numbers show the order of
magnitude, not a promise of identical results on another processor.

## LLVM and the verifier still do not agree

The verifier solves the right problem: a bug in a loaded program must not
crash the kernel. LLVM is equally entitled to replace a program with a
semantically equivalent one. The trouble is at the boundary. Two forms can be
identical to the CPU while only one lets the verifier recognize the required
proof.

Today this contract depends on `volatile`, inline assembly, control-flow shape,
and BTF. An LLVM update can remove a necessary instruction; a verifier change
can break an old proof. The log usually identifies the final forbidden access,
not the earlier point where a pointer bound was lost.

This is not merely archaeology from my project. At the time of writing, LLVM
still has [a BPF code-generation bug where a conditional branch through an
empty block lands on the wrong
instruction](https://github.com/llvm/llvm-project/issues/208984). In another
case, adding `-g` can [change a C++ function prototype and drop an
argument](https://github.com/llvm/llvm-project/issues/208141). Both have small
reproducers; the first silently emits a plausible but incorrect object.

The answer is not to weaken the verifier. What is missing is an explicit
contract between it and the compiler: operations whose meaning is guaranteed
to survive optimization, diagnostics that track pointer provenance, and
end-to-end tests across LLVM IR, BPF, BTF, and several kernel versions.
Physical ABI limits should likewise be transformed by a shared layer rather
than worked around anew in every large BPF project.

BPF Capsule ships its own passes because that layer does not exist yet. A good
outcome for the project would be deleting those passes in favor of shared
infrastructure, not maintaining a private LLVM pipeline forever.

## What the kernel ultimately sees

At first I fought each constraint separately. Recursion became an array.
Function pointers became chains of `if` statements. Wide calls became manual
structures. Memory became numbers and a router. Loops became one
`bpf_iter_num`. A deep call graph was inlined until the next stack overflow.

Put those hacks next to one another, and they already resemble a small machine
the verifier can check.

The virtual machine was its simplest complete form: the entire program became
data, but every instruction paid the interpreter tax. Regions made one
operation a large piece of compiled code. A software stack restored calls and
recursion. Fibers gave every computation separate state. A shared memory
window replaced the attempt to preserve the biography of every C pointer.

DOOM was the first large test of this design. Lua, QuickJS, SQLite, zlib,
wasm3, llama2.c, and `no_std` Rust now run on it as well.

LLM tools accelerated the work considerably; alongside my day job, I probably
would not have brought the project this far without them.

The verifier never proves that DOOM terminates. It proves that the next region
and the bounded dispatcher terminate. At runtime, the complete game emerges
from those finite pieces.

## References

- [BPF Capsule](https://github.com/ayles/bpf-capsule) — source, examples, and
  instructions for running them.
- [Linux verifier](https://docs.kernel.org/bpf/verifier.html) — register types,
  value ranges, stack behavior, and state merging.
- [BPF Design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html) — calling
  convention and verifier constraints.
- [RFC 9669: BPF ISA](https://www.rfc-editor.org/rfc/rfc9669.html).
- [The commit that introduced `bpf_arena`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=317460317a02a1af512697e6e964298dedd8a163).
- [Flying the nest — a BPF port of Doom](https://lpc.events/event/18/contributions/1936/).
