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
        ERR_NO_AEAD_NONCE,
        ERR_NO_BUFFER_SPACE,
        ERR_NO_SECRET,
        ERR_NO_PRK,
        ERR_NO_AEAD_KEY,
        ERR_UNABLE_TO_OPEN_RESPONSE
    };
    inline std::string DecapsulationErrorCodeToString(DecapsulationErrorCode code) {
        switch (code) {
            case DecapsulationErrorCode::SUCCESS: return "SUCCESS";
            case DecapsulationErrorCode::ERR_NO_ENCAPSULATED_HEADER: return "ERR_NO_ENCAPSULATED_HEADER";
            case DecapsulationErrorCode::ERR_NO_PUBLIC_KEY: return "ERR_NO_PUBLIC_KEY";
            case DecapsulationErrorCode::ERR_NO_CIPHER_TEXT: return "ERR_NO_CIPHER_TEXT";
            case DecapsulationErrorCode::ERR_NO_CONTEXT_CREATED: return "ERR_NO_CONTEXT_CREATED";
            case DecapsulationErrorCode::ERR_UNABLE_TO_OPEN: return "ERR_UNABLE_TO_OPEN";
            case DecapsulationErrorCode::ERR_NO_AEAD_NONCE: return "ERR_NO_AEAD_NONCE";
            case DecapsulationErrorCode::ERR_NO_BUFFER_SPACE: return "ERR_NO_BUFFER_SPACE";
            case DecapsulationErrorCode::ERR_NO_SECRET: return "ERR_NO_SECRET";
            case DecapsulationErrorCode::ERR_NO_PRK: return "ERR_NO_PRK";
            case DecapsulationErrorCode::ERR_NO_AEAD_KEY: return "ERR_NO_AEAD_KEY";
            case DecapsulationErrorCode::ERR_UNABLE_TO_OPEN_RESPONSE: return "ERR_UNABLE_TO_OPEN_RESPONSE";
            default: return "Unknown error code";
        }
    }
    enum class OhttpParseErrorCode {
        SUCCESS = 0,
        ERR_BAD_OFFSET,
    };
    inline std::string OhttpParseErrorCodeToString(OhttpParseErrorCode code) {
        switch (code) {
            case OhttpParseErrorCode::SUCCESS: return "SUCCESS";
            case OhttpParseErrorCode::ERR_BAD_OFFSET: return "ERR_BAD_OFFSET";
            default: return "Unknown error code";
        }
    }

    // A function that simply returns the string "foo"
    const char* GetFoo();

    std::vector<uint8_t> generate_key_config(EVP_HPKE_KEY *keypair);

    std::vector<uint8_t> get_public_key(std::vector<uint8_t> key_config);

    std::vector<uint8_t> encode_string(const std::string& str);

    OhttpParseErrorCode get_next_encoded_string(std::vector<uint8_t>& input, int offset, std::vector<uint8_t>& out, int& bytes_used);

    std::vector<uint8_t> get_binary_request(const std::string& path, const std::string& host, const std::string& body);

    std::vector<uint8_t> get_binary_response(const std::vector<uint8_t>& content);
    
    std::string get_url_from_binary_request(const std::vector<uint8_t>& binary_request);

    std::string get_method_from_binary_request(const std::vector<uint8_t>& binary_request);

    std::string get_body_from_binary_request(const std::vector<uint8_t>& binary_request);

    std::vector<uint8_t> get_encapsulated_request(EVP_HPKE_CTX* sender_context, const std::string& path, const std::string& host, const std::string& body, uint8_t* pkR, size_t pkR_len);

    std::vector<uint8_t> encapsulate_response(EVP_HPKE_CTX* reciever_context, uint8_t* enc, size_t enc_len, const std::string& response_body);

    DecapsulationErrorCode decapsulate_request(EVP_HPKE_CTX* receiver_context, std::vector<uint8_t> erequest, uint8_t* drequest, size_t* drequest_len, uint8_t* enc, size_t enc_len, size_t max_drequest_len, EVP_HPKE_KEY recipient_keypair);
    
    DecapsulationErrorCode decapsulate_response(EVP_HPKE_CTX* sender_context, uint8_t* enc, size_t enc_len, std::vector<uint8_t> eresponse, uint8_t* dresponse, size_t* dresponse_len, size_t max_drequest_len);

} // namespace ohttp

#endif  // OHTTP_H