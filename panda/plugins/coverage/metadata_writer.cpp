#include <iostream>
#include <cstring>

#include "metadata_writer.h"

namespace coverage
{

void write_metadata(std::ofstream &os)
{
    if (!os.is_open()) {
        return;
    }

    // construct the PANDA build datestring, in ISO 8601 format
    struct tm build_tm;
    memset(&build_tm, 0, sizeof(struct tm));
    strptime(__DATE__, "%b %d %Y", &build_tm);
    char build_date[16];
    strftime(build_date, 16, "%Y-%m-%d", &build_tm);
    
    // construct current time as the execution time, in ISO 8601 format
    time_t s_since_epoch = time(NULL);
    struct tm exec_tm;
    gmtime_r(&s_since_epoch, &exec_tm);
    char time_string[64];
    strftime(time_string, 64, "%FT%TZ", &exec_tm);
    
    os << "PANDA Build Date," << build_date << "\n";
    os << "Execution Time," << time_string << "\n";
}

}
