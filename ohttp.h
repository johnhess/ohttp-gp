// Sketch of OHTTP implementation

#ifndef OHTTP_H
#define OHTTP_H

#include <cassert>
#include <string>
#include <vector>

#include "openssl/hpke.h"


namespace ohttp {
    enum class DecapsulationErrorCode {
        SUCCESS = 0,
        ERR_NO_ENCAPSULATED_HEADER,
        ERR_NO_PUBLIC_KEY,
        ERR_NO_CIPHER_TEXT,
        ERR_NO_CONTEXT_CREATED,
        ERR_UNABLE_TO_OPEN,
    };
    enum class OhttpParseErrorCode {
        SUCCESS = 0,
        ERR_BAD_OFFSET,
    };

    // A function that simply returns the string "foo"
    const char* GetFoo();

    std::vector<uint8_t> generate_key_config(EVP_HPKE_KEY *keypair);

    std::vector<uint8_t> get_public_key(std::vector<uint8_t> key_config);

    std::vector<uint8_t> encode_string(const std::string& str);

    OhttpParseErrorCode get_next_encoded_string(std::vector<uint8_t>& input, int offset, std::vector<uint8_t>& out, int& bytes_used);

    std::vector<uint8_t> get_binary_request(const std::string& path, const std::string& host, const std::string& body);
    
    std::string get_url_from_binary_request(const std::vector<uint8_t>& binary_request);

    std::string get_method_from_binary_request(const std::vector<uint8_t>& binary_request);

    std::string get_body_from_binary_request(const std::vector<uint8_t>& binary_request);
    
    std::vector<uint8_t> get_encapsulated_request(const std::string& path, const std::string& host, const std::string& body, uint8_t* pkR, size_t pkR_len);

    DecapsulationErrorCode decapsulate_request(std::vector<uint8_t> erequest, uint8_t* drequest, size_t* drequest_len, size_t max_drequest_len, EVP_HPKE_KEY recipient_keypair);

} // namespace ohttp

#endif  // OHTTP_H