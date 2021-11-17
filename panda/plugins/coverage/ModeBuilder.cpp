#include <stdexcept>
#include <sstream>

#include "AsidBlockCsvWriter.h"
#include "AsidBlockGenerator.h"
#include "OsiBlockCsvWriter.h"
#include "OsiBlockGenerator.h"
#include "EdgeCsvWriter.h"
#include "BlockInstrumentationDelegate.h"
#include "EdgeInstrumentationDelegate.h"
#include "UniqueFilter.h"
#include "ModeBuilder.h"
#include "HookFilter.h"
#include "osi_subject.h"

#include "ProcessNameFilter.h"

namespace coverage
{

ModeBuilder::ModeBuilder(std::vector<CoverageMonitorDelegate *>& mds) :
    monitor_delegates(mds), mode(""), process_name(""),
    filename("coverage.csv"), unique(false), start_disabled(false), summarize_results(false),
    pass_hook(0), block_hook(0)
{
}

ModeBuilder& ModeBuilder::with_mode(const std::string& m)
{
    mode = m;
    return *this;
}

ModeBuilder& ModeBuilder::with_process_name_filter(const std::string& pname)
{
    process_name = pname;
    return *this;
}

ModeBuilder& ModeBuilder::with_filename(const std::string& f)
{
    filename = f;
    return *this;
}

ModeBuilder& ModeBuilder::with_unique_filter()
{
    unique = true;
    return *this;
}

ModeBuilder& ModeBuilder::with_start_disabled()
{
    start_disabled = true;
    return *this;
}

ModeBuilder& ModeBuilder::with_summarize_results()
{
    summarize_results = true;
    return *this;
}

ModeBuilder& ModeBuilder::with_hook_filter(target_ulong ph, target_ulong bh)
{
    pass_hook = ph;
    block_hook = bh;
    return *this;
}

std::vector<std::shared_ptr<InstrumentationDelegate>> ModeBuilder::build()
{
    std::vector<std::shared_ptr<InstrumentationDelegate>> result;

    monitor_delegates.clear();
    if ("edge" == mode) {
        std::shared_ptr<RecordProcessor<Edge>> rp;
        std::shared_ptr<EdgeCsvWriter> writer(new EdgeCsvWriter(filename, start_disabled));
        monitor_delegates.push_back(writer.get());
        rp = writer;
        if (unique) {
            std::shared_ptr<UniqueFilter<Edge>> uf(new UniqueFilter<Edge>(rp));
            monitor_delegates.push_back(uf.get());
            rp = uf;
        }

        if ("" != process_name) {
            std::shared_ptr<ProcessNameFilter<Edge>> pnf(new ProcessNameFilter<Edge>(process_name, rp));
            register_osi_observer(pnf.get());
            rp = pnf;
        }

        if (0x0 != pass_hook && 0x0 != block_hook) {
            std::shared_ptr<HookFilter<Edge>> hf(new HookFilter<Edge>(pass_hook, block_hook, rp));
            register_osi_observer(hf.get());
            rp = hf;
            result.push_back(hf);
        }

        std::shared_ptr<EdgeInstrumentationDelegate> inst_del(new EdgeInstrumentationDelegate(rp));
        monitor_delegates.push_back(inst_del.get());
        register_osi_observer(inst_del.get());
        result.push_back(inst_del);
    } else if ("asid-block" == mode) {
        std::shared_ptr<RecordProcessor<AsidBlock>> rp;
        std::shared_ptr<AsidBlockCsvWriter> writer(new AsidBlockCsvWriter(filename, start_disabled));
        monitor_delegates.push_back(writer.get());
        rp = writer;
        if (unique) {
            std::shared_ptr<UniqueFilter<AsidBlock>> uf(new UniqueFilter<AsidBlock>(rp));
            monitor_delegates.push_back(uf.get());
            rp = uf;
        }

        if (0x0 != pass_hook && 0x0 != block_hook) {
            std::shared_ptr<HookFilter<AsidBlock>> hf(new HookFilter<AsidBlock>(pass_hook, block_hook, rp));
            rp = hf;
            register_osi_observer(hf.get());
            result.push_back(hf);
        }

        std::shared_ptr<RecordProcessor<Block>> block_processor(new AsidBlockGenerator(first_cpu, rp));
        result.push_back(std::shared_ptr<InstrumentationDelegate>(new BlockInstrumentationDelegate(block_processor)));
    } else if ("osi-block" == mode) {

        std::shared_ptr<RecordProcessor<OsiBlock>> rp;
        std::shared_ptr<OsiBlockCsvWriter> writer(new OsiBlockCsvWriter(filename, summarize_results, start_disabled));


        monitor_delegates.push_back(writer.get());
        rp = writer;
        if (unique) {
            std::shared_ptr<UniqueFilter<OsiBlock>> uf(new UniqueFilter<OsiBlock>(writer));
            monitor_delegates.push_back(uf.get());
            rp = uf;
        }
        std::shared_ptr<OsiBlockGenerator> osi_blk_gen(new OsiBlockGenerator(rp));
        register_osi_observer(osi_blk_gen.get());

        if (0x0 != pass_hook && 0x0 != block_hook) {
            std::shared_ptr<HookFilter<OsiBlock>> hf(new HookFilter<OsiBlock>(pass_hook, block_hook, rp));
            rp = hf;
            register_osi_observer(hf.get());
            result.push_back(hf);
        }

        std::shared_ptr<RecordProcessor<Block>> bp = osi_blk_gen;
        if ("" != process_name) {
            std::shared_ptr<ProcessNameFilter<Block>> pnf(new ProcessNameFilter<Block>(process_name, osi_blk_gen));
            register_osi_observer(pnf.get());
            bp = pnf;
        }

        result.push_back(std::shared_ptr<InstrumentationDelegate>(new BlockInstrumentationDelegate(bp)));
    } else {
        std::stringstream ss;
        ss << "\"" << mode << "\" is not a valid mode.";
        throw std::runtime_error(ss.str());
    }

    return result;
}

}
