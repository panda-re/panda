#include <stdexcept>
#include <sstream>

#include "AsidBlockGenerator.h"
#include "OsiBlockGenerator.h"
#include "EdgeGenerator.h"

#include "AsidBlockCsvWriter.h"
#include "OsiBlockCsvWriter.h"
#include "EdgeCsvWriter.h"

#include "UniqueFilter.h"

#include "BlockProcessorBuilder.h"

namespace coverage
{

BlockProcessorBuilder::BlockProcessorBuilder() :
    mode(""), filename(""), unique(false)
{
}

BlockProcessorBuilder& BlockProcessorBuilder::with_output_mode(const std::string& m)
{
    mode = m;
    return *this;
}

BlockProcessorBuilder& BlockProcessorBuilder::with_unique_filter()
{
    unique = true;
    return *this;
}

BlockProcessorBuilder& BlockProcessorBuilder::with_filename(const std::string& f)
{
    filename = f;
    return *this;
}

std::unique_ptr<RecordProcessor<Block>> BlockProcessorBuilder::build()
{
    std::unique_ptr<RecordProcessor<Block>> result;

    if ("" == filename) {
        throw std::runtime_error("No filename specified.");
    }

    if ("asid-block" == mode) {
        std::unique_ptr<RecordProcessor<AsidBlock>> writer(new AsidBlockCsvWriter(filename));
        if (unique) {
            writer.reset(new UniqueFilter<AsidBlock>(std::move(writer)));
        }
        result.reset(new AsidBlockGenerator(first_cpu, std::move(writer)));
    } else if ("osi-block" == mode) {
        std::unique_ptr<RecordProcessor<OsiBlock>> writer(new OsiBlockCsvWriter(filename));
        if (unique) {
            writer.reset(new UniqueFilter<OsiBlock>(std::move(writer)));
        }
        result.reset(new OsiBlockGenerator(first_cpu, std::move(writer)));
    } else if ("edge" == mode) {
        std::unique_ptr<RecordProcessor<Edge>> writer(new EdgeCsvWriter(filename));
        if (unique) {
            writer.reset(new UniqueFilter<Edge>(std::move(writer)));
        }
        result.reset(new EdgeGenerator(std::move(writer)));
    } else {
        std::stringstream ss;
        ss << "\"" << mode << "\" is not a valid mode.";
        throw std::runtime_error(ss.str());
    }

    return std::move(result);
}

}
