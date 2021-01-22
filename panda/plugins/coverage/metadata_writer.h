#ifndef COVERAGE_METADATA_WRITER_H
#define COVERAGE_METADATA_WRITER_H

#include <fstream>
#include <string>

namespace coverage
{

/**
 * Utility function to write metadata to a CSV file.
 */
void write_metadata(std::ofstream &os);

}

#endif
