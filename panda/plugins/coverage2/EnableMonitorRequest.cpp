#include "EnableMonitorRequest.h"

#include "AsidBlockCoverageMode.h"
#include "OsiBlockCoverageMode.h"
#include "EdgeCoverageMode.h"

namespace coverage2
{

EnableMonitorRequest::EnableMonitorRequest(std::unique_ptr<CoverageMode>& m, const std::string& fn)
    : mode(m), filename(fn)
{
}

void EnableMonitorRequest::handle()
{
    std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(panda_get_args("coverage2"), panda_free_args);
    std::string mode_arg = panda_parse_string_opt(args.get(), "mode", "asid-block", "coverage mode");
    if ("asid-block" == mode_arg) {
        mode.reset(new AsidBlockCoverageMode(filename));
    } else if ("osi-block" == mode_arg) {
        mode.reset(new OsiBlockCoverageMode(filename));
    } else if ("edge" == mode_arg) {
        mode.reset(new EdgeCoverageMode(filename));
    }
}

}
