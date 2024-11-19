#ifndef OHTTP_INTERNAL_H
#define OHTTP_INTERNAL_H

#include <vector>
#include <cstdint>

namespace ohttp {
    // Internal functions exposed for testing or internal use
    std::vector<uint8_t> get_quic_integer_as_bytes(uint64_t in);
    uint64_t get_quic_integer_from_bytes(std::vector<uint8_t>& in);
}  // namespace ohttp

#endif  // OHTTP_INTERNAL_H