#ifndef COVERAGE_HOOKFILTER_H
#define COVERAGE_HOOKFILTER_H

#include <memory>

#include "panda/tcg-utils.h"

#include "InstrumentationDelegate.h"
#include "OsiObserver.h"
#include "RecordProcessor.h"

namespace coverage
{

static void pass_hook_cb(bool *pass_ptr, target_pid_t *current_tid_ptr,
                         target_pid_t *target_tid_ptr)
{
    *pass_ptr = true;
    *target_tid_ptr = *current_tid_ptr;
}

static void block_hook_cb(bool *pass_ptr)
{
    *pass_ptr = false;
}

/**
 * HookFilter acts as a gate in the coverage processing pipline, passing or
 * rejecting the records depending on whether or not the filter is on or off.
 * The filter is turned on or off by hooking two user provided addresses. The
 * "pass" hook disables the filter and allows records to pass to the delegate.
 * The "block" hook turns on the filter and stops the records from passing to
 * the delegate. An internal variable that keeps track of which thread is
 * currently active is also used so that only the coverage from the thread at
 * the time the pass hook is executed is reported.
 */
template<typename RecordType>
class HookFilter : public RecordProcessor<RecordType>,
                   public InstrumentationDelegate,
                   public OsiObserver
{
public:
    HookFilter(target_ulong ph, target_ulong bh,
               std::shared_ptr<RecordProcessor<RecordType>> d)
        : pass_hook(ph), block_hook(bh), pass(false), delegate(std::move(d))
    {
    }

    ~HookFilter() override { }

    void instrument(CPUState *cpu, TranslationBlock *tb) override
    {
        // Check if we need to instrument the "pass" instruction.
        if (tb->pc <= pass_hook && pass_hook < tb->pc + tb->size) {
            TCGOp *op = find_guest_insn_by_addr(pass_hook);
            assert(op);
            insert_call(&op, &pass_hook_cb, &pass, &current_tid, &target_tid);
        }
        // Check if we need to instrument the "block" instruction.
        if (tb->pc <= block_hook && block_hook < tb->pc + tb->size) {
            TCGOp *op = find_guest_insn_by_addr(block_hook);
            assert(op);
            insert_call(&op, &block_hook_cb, &pass);
        }
    }

    void handle(RecordType record) override
    {
        // Check if the internal variable is set or not. If set, pass the
        // record to the delegate.
        if ((pass) && (current_tid == target_tid)) {
            delegate->handle(record);
        }
    }

    void task_changed(const std::string& process_name, target_pid_t pid,
                      target_pid_t tid) override
    {
        current_tid = tid;
    }

private:
    target_ulong pass_hook;
    target_ulong block_hook;
    bool pass;
    target_pid_t current_tid;
    target_pid_t target_tid;
    std::shared_ptr<RecordProcessor<RecordType>> delegate;
};

}

#endif
