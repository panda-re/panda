#ifndef COVERAGE_METADATA_WRITER_H
#define COVERAGE_METADATA_WRITER_H

#include <fstream>
#include <string>

namespace coverage
{

/**
 * Utility class to write metadata to a CSV file.
 */
class MetadataWriter
{
public:
    MetadataWriter();
    void write_metadata(std::ofstream &os);
    
private:
    char build_date[16];
};

}

#endif
