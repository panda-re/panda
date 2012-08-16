// Code for manipulating stack locations.
//
// Copyright (C) 2009-2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // get_ebda_seg
#include "util.h" // dprintf
#include "bregs.h" // CR0_PE

// Thread info - stored at bottom of each thread stack - don't change
// without also updating the inline assembler below.
struct thread_info {
    struct thread_info *next;
    void *stackpos;
    struct thread_info **pprev;
};
struct thread_info VAR32FLATVISIBLE MainThread = {
    &MainThread, NULL, &MainThread.next
};


/****************************************************************
 * Low level helpers
 ****************************************************************/

static inline void sgdt(struct descloc_s *desc) {
    asm("sgdtl %0" : "=m"(*desc));
}
static inline void lgdt(struct descloc_s *desc) {
    asm("lgdtl %0" : : "m"(*desc) : "memory");
}

// Call a 32bit SeaBIOS function from a 16bit SeaBIOS function.
u32 VISIBLE16
call32(void *func, u32 eax, u32 errret)
{
    ASSERT16();
    u32 cr0 = getcr0();
    if (cr0 & CR0_PE)
        // Called in 16bit protected mode?!
        return errret;

    // Backup cmos index register and disable nmi
    u8 cmosindex = inb(PORT_CMOS_INDEX);
    outb(cmosindex | NMI_DISABLE_BIT, PORT_CMOS_INDEX);
    inb(PORT_CMOS_DATA);

    // Backup fs/gs and gdt
    u16 fs = GET_SEG(FS), gs = GET_SEG(GS);
    struct descloc_s gdt;
    sgdt(&gdt);

    u32 bkup_ss, bkup_esp;
    asm volatile(
        // Backup ss/esp / set esp to flat stack location
        "  movl %%ss, %0\n"
        "  movl %%esp, %1\n"
        "  shll $4, %0\n"
        "  addl %0, %%esp\n"
        "  shrl $4, %0\n"

        // Transition to 32bit mode, call func, return to 16bit
        "  movl $(" __stringify(BUILD_BIOS_ADDR) " + 1f), %%edx\n"
        "  jmp transition32\n"
        "  .code32\n"
        "1:calll *%3\n"
        "  movl $2f, %%edx\n"
        "  jmp transition16big\n"

        // Restore ds/ss/esp
        "  .code16gcc\n"
        "2:movl %0, %%ds\n"
        "  movl %0, %%ss\n"
        "  movl %1, %%esp\n"
        : "=&r" (bkup_ss), "=&r" (bkup_esp), "+a" (eax)
        : "r" (func)
        : "ecx", "edx", "cc", "memory");

    // Restore gdt and fs/gs
    lgdt(&gdt);
    SET_SEG(FS, fs);
    SET_SEG(GS, gs);

    // Restore cmos index register
    outb(cmosindex, PORT_CMOS_INDEX);
    inb(PORT_CMOS_DATA);
    return eax;
}

// 16bit trampoline for enabling irqs from 32bit mode.
ASM16(
    "  .global trampoline_checkirqs\n"
    "trampoline_checkirqs:\n"
    "  rep ; nop\n"
    "  lretw"
    );

static void
check_irqs(void)
{
    if (MODESEGMENT) {
        asm volatile(
            "sti\n"
            "nop\n"
            "rep ; nop\n"
            "cli\n"
            "cld\n"
            : : :"memory");
        return;
    }
    extern void trampoline_checkirqs();
    struct bregs br;
    br.flags = F_IF;
    br.code.seg = SEG_BIOS;
    br.code.offset = (u32)&trampoline_checkirqs;
    call16big(&br);
}

// 16bit trampoline for waiting for an irq from 32bit mode.
ASM16(
    "  .global trampoline_waitirq\n"
    "trampoline_waitirq:\n"
    "  sti\n"
    "  hlt\n"
    "  lretw"
    );

// Wait for next irq to occur.
void
wait_irq(void)
{
    if (MODESEGMENT) {
        asm volatile("sti ; hlt ; cli ; cld": : :"memory");
        return;
    }
    if (CONFIG_THREADS && MainThread.next != &MainThread) {
        // Threads still active - do a yield instead.
        yield();
        return;
    }
    extern void trampoline_waitirq();
    struct bregs br;
    br.flags = 0;
    br.code.seg = SEG_BIOS;
    br.code.offset = (u32)&trampoline_waitirq;
    call16big(&br);
}


/****************************************************************
 * Stack in EBDA
 ****************************************************************/

// Switch to the extra stack in ebda and call a function.
inline u32
stack_hop(u32 eax, u32 edx, void *func)
{
    ASSERT16();
    u16 ebda_seg = get_ebda_seg(), bkup_ss;
    u32 bkup_esp;
    asm volatile(
        // Backup current %ss/%esp values.
        "movw %%ss, %w3\n"
        "movl %%esp, %4\n"
        // Copy ebda seg to %ds/%ss and set %esp
        "movw %w6, %%ds\n"
        "movw %w6, %%ss\n"
        "movl %5, %%esp\n"
        // Call func
        "calll *%2\n"
        // Restore segments and stack
        "movw %w3, %%ds\n"
        "movw %w3, %%ss\n"
        "movl %4, %%esp"
        : "+a" (eax), "+d" (edx), "+c" (func), "=&r" (bkup_ss), "=&r" (bkup_esp)
        : "i" (EBDA_OFFSET_TOP_STACK), "r" (ebda_seg)
        : "cc", "memory");
    return eax;
}


/****************************************************************
 * Threads
 ****************************************************************/

#define THREADSTACKSIZE 4096
int VAR16VISIBLE CanPreempt;

// Return the 'struct thread_info' for the currently running thread.
struct thread_info *
getCurThread(void)
{
    u32 esp = getesp();
    if (esp <= BUILD_STACK_ADDR)
        return &MainThread;
    return (void*)ALIGN_DOWN(esp, THREADSTACKSIZE);
}

// Switch to next thread stack.
static void
switch_next(struct thread_info *cur)
{
    struct thread_info *next = cur->next;
    if (cur == next)
        // Nothing to do.
        return;
    asm volatile(
        "  pushl $1f\n"                 // store return pc
        "  pushl %%ebp\n"               // backup %ebp
        "  movl %%esp, 4(%%eax)\n"      // cur->stackpos = %esp
        "  movl 4(%%ecx), %%esp\n"      // %esp = next->stackpos
        "  popl %%ebp\n"                // restore %ebp
        "  retl\n"                      // restore pc
        "1:\n"
        : "+a"(cur), "+c"(next)
        :
        : "ebx", "edx", "esi", "edi", "cc", "memory");
}

// Briefly permit irqs to occur.
void
yield(void)
{
    if (MODESEGMENT || !CONFIG_THREADS) {
        // Just directly check irqs.
        check_irqs();
        return;
    }
    struct thread_info *cur = getCurThread();
    if (cur == &MainThread)
        // Permit irqs to fire
        check_irqs();

    // Switch to the next thread
    switch_next(cur);
}

// Last thing called from a thread (called on "next" stack).
static void
__end_thread(struct thread_info *old)
{
    old->next->pprev = old->pprev;
    *old->pprev = old->next;
    free(old);
    dprintf(DEBUG_thread, "\\%08x/ End thread\n", (u32)old);
    if (MainThread.next == &MainThread)
        dprintf(1, "All threads complete.\n");
}

// Create a new thread and start executing 'func' in it.
void
run_thread(void (*func)(void*), void *data)
{
    ASSERT32FLAT();
    if (! CONFIG_THREADS)
        goto fail;
    struct thread_info *thread;
    thread = memalign_tmphigh(THREADSTACKSIZE, THREADSTACKSIZE);
    if (!thread)
        goto fail;

    thread->stackpos = (void*)thread + THREADSTACKSIZE;
    struct thread_info *cur = getCurThread();
    thread->next = cur;
    thread->pprev = cur->pprev;
    cur->pprev = &thread->next;
    *thread->pprev = thread;

    dprintf(DEBUG_thread, "/%08x\\ Start thread\n", (u32)thread);
    asm volatile(
        // Start thread
        "  pushl $1f\n"                 // store return pc
        "  pushl %%ebp\n"               // backup %ebp
        "  movl %%esp, 4(%%edx)\n"      // cur->stackpos = %esp
        "  movl 4(%%ebx), %%esp\n"      // %esp = thread->stackpos
        "  calll *%%ecx\n"              // Call func

        // End thread
        "  movl (%%ebx), %%ecx\n"       // %ecx = thread->next
        "  movl 4(%%ecx), %%esp\n"      // %esp = next->stackpos
        "  movl %%ebx, %%eax\n"
        "  calll %4\n"                  // call __end_thread(thread)
        "  popl %%ebp\n"                // restore %ebp
        "  retl\n"                      // restore pc
        "1:\n"
        : "+a"(data), "+c"(func), "+b"(thread), "+d"(cur)
        : "m"(*(u8*)__end_thread)
        : "esi", "edi", "cc", "memory");
    return;

fail:
    func(data);
}

// Wait for all threads (other than the main thread) to complete.
void
wait_threads(void)
{
    ASSERT32FLAT();
    if (! CONFIG_THREADS)
        return;
    while (MainThread.next != &MainThread)
        yield();
}

void
mutex_lock(struct mutex_s *mutex)
{
    ASSERT32FLAT();
    if (! CONFIG_THREADS)
        return;
    while (mutex->isLocked)
        yield();
    mutex->isLocked = 1;
}

void
mutex_unlock(struct mutex_s *mutex)
{
    ASSERT32FLAT();
    if (! CONFIG_THREADS)
        return;
    mutex->isLocked = 0;
}


/****************************************************************
 * Thread preemption
 ****************************************************************/

static u32 PreemptCount;

// Turn on RTC irqs and arrange for them to check the 32bit threads.
void
start_preempt(void)
{
    if (! CONFIG_THREADS || ! CONFIG_THREAD_OPTIONROMS)
        return;
    CanPreempt = 1;
    PreemptCount = 0;
    useRTC();
}

// Turn off RTC irqs / stop checking for thread execution.
void
finish_preempt(void)
{
    if (! CONFIG_THREADS || ! CONFIG_THREAD_OPTIONROMS) {
        yield();
        return;
    }
    CanPreempt = 0;
    releaseRTC();
    dprintf(9, "Done preempt - %d checks\n", PreemptCount);
    yield();
}

// Check if preemption is on, and wait for it to complete if so.
int
wait_preempt(void)
{
    if (MODESEGMENT || !CONFIG_THREADS || !CONFIG_THREAD_OPTIONROMS
        || !CanPreempt)
        return 0;
    while (CanPreempt)
        yield();
    return 1;
}

// Try to execute 32bit threads.
void VISIBLE32INIT
yield_preempt(void)
{
    PreemptCount++;
    switch_next(&MainThread);
}

// 16bit code that checks if threads are pending and executes them if so.
void
check_preempt(void)
{
    if (! CONFIG_THREADS || ! CONFIG_THREAD_OPTIONROMS
        || !GET_GLOBAL(CanPreempt)
        || GET_FLATPTR(MainThread.next) == &MainThread)
        return;

    extern void _cfunc32flat_yield_preempt(void);
    call32(_cfunc32flat_yield_preempt, 0, 0);
}
