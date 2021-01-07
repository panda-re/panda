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
#include "osi_subject.h"

#include "ProcessNameFilter.h"

namespace coverage
{

ModeBuilder::ModeBuilder(std::vector<CoverageMonitorDelegate *>& mds) :
    monitor_delegates(mds), mode(""), process_name(""),
    filename("coverage.csv"), unique(false), start_disabled(false)
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

std::unique_ptr<InstrumentationDelegate> ModeBuilder::build()
{
    std::unique_ptr<InstrumentationDelegate> result;

    monitor_delegates.clear();
    if ("edge" == mode) {
        auto tmp = new EdgeCsvWriter(filename, start_disabled);
        monitor_delegates.push_back(tmp);
        std::unique_ptr<RecordProcessor<Edge>> writer(tmp);
        if (unique) {
            auto filt = new UniqueFilter<Edge>(std::move(writer));
            monitor_delegates.push_back(filt);
            writer.reset(filt);
        }

        if ("" != process_name) {
            auto pnf = new ProcessNameFilter<Edge>(process_name, std::move(writer));
            register_osi_observer(pnf);
            writer.reset(pnf);
        }

        auto inst_del = new EdgeInstrumentationDelegate(std::move(writer));
        monitor_delegates.push_back(inst_del);
        register_osi_observer(inst_del);
        result.reset(inst_del);
    } else if ("asid-block" == mode) {
        auto tmp = new AsidBlockCsvWriter(filename, start_disabled);
        monitor_delegates.push_back(tmp);
        std::unique_ptr<RecordProcessor<AsidBlock>> writer(tmp);
        if (unique) {
            auto uf = new UniqueFilter<AsidBlock>(std::move(writer));
            monitor_delegates.push_back(uf);
            writer.reset(uf);
        }
        std::unique_ptr<RecordProcessor<Block>> block_processor(new AsidBlockGenerator(first_cpu, std::move(writer)));
        result.reset(new BlockInstrumentationDelegate(std::move(block_processor)));
    } else if ("osi-block" == mode) {
        auto tmp = new OsiBlockCsvWriter(filename, start_disabled);
        monitor_delegates.push_back(tmp);
        std::unique_ptr<RecordProcessor<OsiBlock>> writer(tmp);
        if (unique) {
            auto uf = new UniqueFilter<OsiBlock>(std::move(writer));
            monitor_delegates.push_back(uf);
            writer.reset(uf);
        }
        auto osi_blk_gen = new OsiBlockGenerator(std::move(writer));
        register_osi_observer(osi_blk_gen);
        std::unique_ptr<RecordProcessor<Block>> block_processor(osi_blk_gen);

        if ("" != process_name) {
            auto pnf = new ProcessNameFilter<Block>(process_name, std::move(block_processor));
            register_osi_observer(pnf);
            block_processor.reset(pnf);
        }

        result.reset(new BlockInstrumentationDelegate(std::move(block_processor)));
    } else {
        std::stringstream ss;
        ss << "\"" << mode << "\" is not a valid mode.";
        throw std::runtime_error(ss.str());
    }

    return result;
}

}
