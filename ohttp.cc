#include <vector>
#include <iostream>
#include <stdexcept>

#include "ohttp.h"
#include "openssl/hpke.h"

namespace ohttp {

    const char* GetFoo() {
        return "foo";
    }

    // Helper to encode a string as a binary vector (length-prefixed)
    std::vector<uint8_t> encode_string(const std::string& str) {
        std::vector<uint8_t> result;

        // WARNING: Cloudflare/Wood implementation uses just one byte
        // where we would expect to see 2 per RFC 9292.

        uint16_t length = str.size();
        // TODO: Support QUIC-style multi-byte length encoding.
        // see https://www.rfc-editor.org/rfc/rfc9000#section-16
        // for now, just support short 6-bit lengths.
        assert(length < 64);  // 2^6
        result.push_back(length & 0xFF);
        result.insert(result.end(), str.begin(), str.end());
        return result;
    }

    OhttpParseErrorCode get_next_encoded_string(std::vector<uint8_t>& input, int offset, std::vector<uint8_t>& out, int& bytes_used) {
        // Assume length is the first byte.
        // TODO: Deal with QUIQ-style multi-byte length encoding.
        int len_bytes = 1;
        int start_content = offset + len_bytes;
        int end_offset = start_content + input[offset];
        if (end_offset > int(input.size())) {
            return OhttpParseErrorCode::ERR_BAD_OFFSET;
        }
        bytes_used = end_offset - start_content + len_bytes;
        for (int i = start_content; i < end_offset; i++) {
            out.push_back(input[i]);
        }
        return OhttpParseErrorCode::SUCCESS;
    }

    // Function to encode the POST request in binary format per RFC 9292
    std::vector<uint8_t> get_binary_request(const std::string& path, const std::string& host, const std::string& body) {
        std::vector<uint8_t> binary_request;

        // Known-Length Request {
        //   Framing Indicator (i) = 0,
        //   Request Control Data (..),
        //   Known-Length Field Section (..),
        //   Known-Length Content (..),
        //   Known-Length Field Section (..),
        //   Padding (..),
        // }

        // Framing indicator.  0 for fixed length request.
        std::vector<uint8_t> framing_indicator = {0};
        binary_request.insert(binary_request.end(), framing_indicator.begin(), framing_indicator.end());

        // Control Data
        // Request Control Data {
        //   Method Length (i),
        //   Method (..),
        //   Scheme Length (i),
        //   Scheme (..),
        //   Authority Length (i),
        //   Authority (..),
        //   Path Length (i),
        //   Path (..),
        // }

        // Method Length & Method
        std::string method_value = "POST";
        std::vector<uint8_t> method_value_field = encode_string(method_value);
        // std::cout << "Method value field size: " << method_value_field.size() << std::endl;
        // std::cout << "Method value field: ";
        // for (uint8_t byte : method_value_field) {
        //     std::cout << (int)byte << " ";
        // }
        binary_request.insert(binary_request.end(), method_value_field.begin(), method_value_field.end());

        // Scheme Length & Scheme
        std::string scheme_value = "https";
        std::vector<uint8_t> scheme_value_field = encode_string(scheme_value);
        binary_request.insert(binary_request.end(), scheme_value_field.begin(), scheme_value_field.end());
        
        // Authority Length & Authority
        std::string authority_value = host;
        std::vector<uint8_t> authority_value_field = encode_string(authority_value);
        binary_request.insert(binary_request.end(), authority_value_field.begin(), authority_value_field.end());

        // Path Length & Path
        std::vector<uint8_t> path_value_field = encode_string(path);
        binary_request.insert(binary_request.end(), path_value_field.begin(), path_value_field.end());

        // Header section.
        // Known-Length Field Section {
        //   Length (i),
        //   Field Line (..) ...,
        // }

        // Length & Field Line
        std::vector<uint8_t> no_fields = encode_string("");
        binary_request.insert(binary_request.end(), no_fields.begin(), no_fields.end());

        // Known-Length Content {
        //   Content Length (i),
        //   Content (..),
        // }

        // Content Length & Content
        std::vector<uint8_t> body_field = encode_string(body);
        binary_request.insert(binary_request.end(), body_field.begin(), body_field.end());

        // Trailer section
        // Known-Length Field Section {
        //   Length (i),
        //   Field Line (..) ...,
        // }

        // WARNING: Another deviation from cloudflare implementation

        // Length & Field Line
        binary_request.insert(binary_request.end(), no_fields.begin(), no_fields.end());

        // No zero bytes.
        return binary_request;
    }

    // TODO: Support configurable relay/gateway/keys.
    std::vector<uint8_t> get_encapsulated_request(const std::string& path, const std::string& host, const std::string& body, uint8_t* pkR, size_t pkR_len) {
        // Hard coded key config matching ohttp-gateway.jthess.com's
        // public key.

        // Key ID (8 bit)                 80
        // HPKE KEM ID (16)               0020 	DHKEM(X25519, HKDF-SHA256)
        // HPKE Public Key (8*Npk=8*32)   7a04f3070f2fc4c52c06eb373060b415dbd8e82effe4088965a2602c27b91646
        // HPKE Symmetric Algos Len (16)  0004
        // HPKE Symmetric algorithms (32) 
        //   HPKE KDF ID                  0001 // HKDF-SHA256	
        //   HPKE AEAD ID                 0001 // AES-128-GCM	

        // Plaintext:
        std::vector<uint8_t> binary_request = get_binary_request(path, host, body);

        // Info
        // Build a sequence of bytes (info) by concatenating the ASCII-encoded
        // string "message/bhttp request", a zero byte, and the header.
        std::string infos = "message/bhttp request";
        std::vector<uint8_t> info;
        for (size_t i = 0; i < infos.size(); i++) {
            info.push_back(uint8_t(infos[i]));
        }
        info.push_back(0);  // Zero byte
        // Header
        info.push_back(0x80); // Key ID
        info.push_back(0x00); info.push_back(0x20); // HPKE KEM ID
        info.push_back(0x00); info.push_back(0x01); // KDF ID
        info.push_back(0x00); info.push_back(0x01); // AEAD ID

        // Ciphertext & Friends:
        std::vector<uint8_t> encapsulated_request;  // will be aad + enc + ct

        // Create a context
        bssl::ScopedEVP_HPKE_CTX sender_context;

        // Ephemeral public key
        uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
        size_t enc_len;

        std::cout << "PK is " << std::endl;
        for (size_t i = 0; i < pkR_len; i++) {
            std::cout << std::hex << (int)pkR[i] << " ";
        }
        std::cout << std::endl;

        int rv = EVP_HPKE_CTX_setup_sender(
            /* *ctx */ sender_context.get(),
            /* *out_enc */ enc,
            /* *out_enc_len */ &enc_len,
            /*  max_enc */ sizeof(enc),
            /* *kem */ EVP_hpke_x25519_hkdf_sha256(),  // We want 0x0020, DHKEM(X25519, HKDF-SHA256);	see: https://www.iana.org/assignments/hpke/hpke.xhtml
            /* *kdf */ EVP_hpke_hkdf_sha256(),         // 0x0001, HKDF-SHA256
            /* *aead */ EVP_hpke_aes_128_gcm(),        // 0x0001, AES-128-GCM
            /* *peer_public_key */ pkR,
            /*  peer_public_key_len */ pkR_len,
            /* *info */ info.data(),
            /*  info_len */ info.size()
        );
        if (rv != 1) {
            return {};
        }

        // Have sender encrypt message for the recipient.
        int ct_max_len = binary_request.size() +
            EVP_HPKE_CTX_max_overhead(sender_context.get());
        std::vector<uint8_t> ciphertext(ct_max_len);
        size_t ciphertext_len;
        std::vector<uint8_t> aad = {
            0x80, // Key ID
            0x00, 0x20, // HPKE KEM ID
            0x00, 0x01, // KDF ID
            0x00, 0x01, // AEAD ID
        };
        std::cout << "Ciphertext: " << std::endl;
        for (uint8_t byte : ciphertext) {
            std::cout << std::dec << (int)byte << " ";
        }
        std::cout << std::endl;
        rv = EVP_HPKE_CTX_seal(
            /* *ctx */ sender_context.get(),
            /* *out */ ciphertext.data(),
            /* *out_len */ &ciphertext_len,
            /*  max_out_len */ ciphertext.size(),
            /* *in */ binary_request.data(),
            /*  in_len */ binary_request.size(),
            /* *ad */ aad.data(),
            /*  ad_len */ aad.size()
        );
        if (rv != 1) {
            return {};
        }

        std::cout << "enc" << std::endl;
        for (uint8_t byte : enc) {
            // As int and hex
            std::cout << std::dec << (int)byte << " ";
        }
        std::cout << std::endl;
        std::cout << "Ciphertext: " << std::endl;
        for (uint8_t byte : ciphertext) {
            std::cout << std::dec << (int)byte << " ";
        }
        std::cout << std::endl;

        // Per RFC 9292, the encapsulated request is the concatenation of the
        // aad, enc, and ciphertext.
        encapsulated_request.insert(encapsulated_request.end(), aad.begin(), aad.end());
        encapsulated_request.insert(encapsulated_request.end(), enc, enc + enc_len);
        encapsulated_request.insert(encapsulated_request.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        return encapsulated_request;
    }

    DecapsulationErrorCode decapsulate_request(
        std::vector<uint8_t> erequest,
        uint8_t* drequest,
        size_t* drequest_len,
        size_t max_drequest_len,
        EVP_HPKE_KEY recipient_keypair) {

      // Break the request into 3 parts: AAD, ephemeral public key, and 
      // ciphertext.

      // The first 7 bytes of the encapsulated request are the aad.
      if (erequest.size() < 7) {
        return DecapsulationErrorCode::ERR_NO_ENCAPSULATED_HEADER;
      }
      std::vector<uint8_t> ad;
      for (size_t i = 0; i < 7; i++) {
        ad.push_back(erequest[i]);
      }

      // The next 32 bytes are the ephemeral public key.
      if (erequest.size() < 39) {
        return DecapsulationErrorCode::ERR_NO_PUBLIC_KEY;
      }
      size_t enc_len = 32;  // Hardcoded for now.
      std::vector<uint8_t> enc;
      for (size_t i = 7; i < 7 + enc_len; i++) {
        enc.push_back(erequest[i]);
      }

      // The rest is the ciphertext.
      std::vector<uint8_t> ct;
      for (size_t i = 7 + enc_len; i < erequest.size(); i++) {
        ct.push_back(erequest[i]);
      }

      // TODO: Get info (along with keys) from config.
      // Info
      // Build a sequence of bytes (info) by concatenating the ASCII-encoded
      // string "message/bhttp request", a zero byte, and the header.
      std::string infos = "message/bhttp request";
      std::vector<uint8_t> info;
      for (size_t i = 0; i < infos.size(); i++) {
          info.push_back(uint8_t(infos[i]));
      }
      info.push_back(0);  // Zero byte
      // Header
      info.push_back(0x80); // Key ID
      info.push_back(0x00); info.push_back(0x20); // HPKE KEM ID
      info.push_back(0x00); info.push_back(0x01); // KDF ID
      info.push_back(0x00); info.push_back(0x01); // AEAD ID
      
      // Create a context
      bssl::ScopedEVP_HPKE_CTX receiver_context;
      int rv2 = EVP_HPKE_CTX_setup_recipient(
        /* *ctx */ receiver_context.get(),
        /* *key */ &recipient_keypair,
        /* *kdf */ EVP_hpke_hkdf_sha256(),
        /* *aead */ EVP_hpke_aes_128_gcm(),
        /* *enc */ enc.data(),
        /*  enc_len */ enc.size(),
        /* *info */ info.data(),
        /*  info_len */ info.size()
      );
      if (rv2 != 1) {
        return DecapsulationErrorCode::ERR_NO_CONTEXT_CREATED;
      }

      int rv3 = EVP_HPKE_CTX_open(
        /* *ctx */ receiver_context.get(),
        /* *out */ drequest,
        /* *out_len */ drequest_len,
        /*  max_out_len */ max_drequest_len,
        /* *ct */ ct.data(),
        /*  ct_len */ ct.size(),
        /* *ad */ ad.data(),
        /*  ad_len */ ad.size()
      );
      if (rv3 != 1) {
        return DecapsulationErrorCode::ERR_UNABLE_TO_OPEN;
      }

      return DecapsulationErrorCode::SUCCESS;
    }
}