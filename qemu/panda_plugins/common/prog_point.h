struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
#ifdef __cplusplus
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
    bool operator ==(const prog_point &p) const {
        return (this->pc == p.pc && this->caller == p.caller && this->cr3 == p.cr3);
    }
#endif
};

#ifdef __GXX_EXPERIMENTAL_CXX0X__
struct hash_prog_point{
    size_t operator()(const prog_point &p) const
    {
        size_t h1 = std::hash<target_ulong>()(p.caller);
        size_t h2 = std::hash<target_ulong>()(p.pc);
        size_t h3 = std::hash<target_ulong>()(p.cr3);
        return h1 ^ h2 ^ h3;
    }
};
#endif
