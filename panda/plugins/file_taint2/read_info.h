#ifndef FILE_TAINT_READ_INFO_H
#define FILE_TAINT_READ_INFO_H

#include <cstdint>

#include "panda/plugin.h"

struct ReadKey
{
    uint64_t process_id;
    uint64_t thread_id;
    uint64_t file_id;
};

template <class T> inline void hash_combine(std::size_t &seed, const T &v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std
{
template <> struct hash<ReadKey> {
    size_t operator()(ReadKey const &key) const noexcept
    {
        size_t result = 0x0;
        hash_combine(result, key.process_id);
        hash_combine(result, key.thread_id);
        hash_combine(result, key.file_id);
        return result;
    }
};
} // namespace std

bool operator==(const ReadKey &lhs, const ReadKey &rhs)
{
    return lhs.process_id == rhs.process_id && lhs.thread_id == rhs.thread_id &&
           lhs.file_id == rhs.file_id;
}

#endif
