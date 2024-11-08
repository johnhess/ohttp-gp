#include <vector>
#include <iostream>
#include <stdexcept>

#include "ohttp.h"
#include "openssl/hkdf.h"
#include "openssl/hpke.h"
#include "openssl/err.h"
#include "openssl/rand.h"

namespace ohttp {

    HPKE_KEY* createHpkeKey() {
        HPKE_KEY* key = new HPKE_KEY();
        key->internal_key = EVP_HPKE_KEY_new();
        return key;
    }

    void destroyHpkeKey(HPKE_KEY* key) {
        EVP_HPKE_KEY_free(key->internal_key);
        delete key;
    }

    struct HPKE_KEM {
        const EVP_HPKE_KEM* internal_kem;
    };

    HPKE_KEM* createHpkeKem() {
        HPKE_KEM* kem = new HPKE_KEM();
        kem->internal_kem = EVP_hpke_x25519_hkdf_sha256();
        return kem;
    }

    void destroyHpkeKem(HPKE_KEM* kem) {
        delete kem;
    }

    int HPKE_KEY_generate(HPKE_KEY* key, const HPKE_KEM* kem) {
        return EVP_HPKE_KEY_generate(key->internal_key, kem->internal_kem);
    }

    bool HPKE_KEY_public_key(HPKE_KEY* key, uint8_t* out, size_t* out_len, size_t max_out) {
        return EVP_HPKE_KEY_public_key(key->internal_key, out, out_len, max_out);
    }

    // Generates a config for a single keypair.
    std::vector<uint8_t> generate_key_config(HPKE_KEY *keypair) {
        // HPKE Symmetric Algorithms {
        //   HPKE KDF ID (16),
        //   HPKE AEAD ID (16),
        // }

        // Key Config {
        //   Key Identifier (8),
        //   HPKE KEM ID (16),
        //   HPKE Public Key (Npk * 8),
        //   HPKE Symmetric Algorithms Length (16) = 4..65532,
        //   HPKE Symmetric Algorithms (32) ...,
        // }
        
        std::vector<uint8_t> config;

        // Key Identifier is always 0
        config.push_back(0);

        // KEM_ID
        const EVP_HPKE_KEM *kem = EVP_HPKE_KEY_kem(keypair->internal_key);
        const uint16_t kem_id = EVP_HPKE_KEM_id(kem);
        const uint8_t kem_high_byte = (kem_id >> 8) & 0xFF;
        const uint8_t kem_low_byte = kem_id & 0xFF;
        config.push_back(kem_high_byte);
        config.push_back(kem_low_byte);

        // HPKE Public Key
        uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
        size_t public_key_len;
        EVP_HPKE_KEY* internal_key = keypair->internal_key;
        if (!EVP_HPKE_KEY_public_key(internal_key, public_key, &public_key_len, sizeof(public_key))) {
            config.clear();
            return config;
        }
        std::cout << "Public key length: " << public_key_len << std::endl;
        config.insert(config.end(), public_key, public_key + public_key_len);

        // Symmetric Algorithms Length
        config.push_back(0);
        config.push_back(4);

        // Hardcoded KDF and AEAD IDs
        config.push_back(0x00);
        config.push_back(0x01);
        config.push_back(0x00);
        config.push_back(0x01);

        // Each encoded configuration is prefixed with a 2-byte integer in 
        // network byte order that indicates the length of the key configuration
        // in bytes. The length-prefixed encodings are concatenated to form a
        // list.
        const uint16_t length = config.size();
        const uint8_t high_byte_length = (length >> 8) & 0xFF;
        const uint8_t low_byte_length = length & 0xFF;
        config.insert(config.begin(), low_byte_length);
        config.insert(config.begin(), high_byte_length);

        return config;
    }

    std::vector<uint8_t> get_public_key(std::vector<uint8_t> key_config) {
        // Extract the public key from the key configuration.
        // The public key starts at the 5th byte of the key configuration and is 32 bytes long.
        std::vector<uint8_t> public_key(key_config.begin() + 5, key_config.begin() + 37);
        return public_key;
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
    std::vector<uint8_t> get_binary_request(const std::string& method, const std::string& scheme, const std::string& host, const std::string& path, const std::string& body) {
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
        std::vector<uint8_t> method_value_field = encode_string(method);
        binary_request.insert(binary_request.end(), method_value_field.begin(), method_value_field.end());

        // Scheme Length & Scheme
        std::vector<uint8_t> scheme_value_field = encode_string(scheme);
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

    std::vector<uint8_t> get_binary_response(const int response_code, const std::vector<uint8_t>& content) {
      std::vector<uint8_t> binary_response;
      binary_response.push_back(1); // Known-Length Informational Response
      binary_response.push_back(response_code); // Status Code      
      binary_response.push_back(0); // Known-Length Field Section Length
      binary_response.push_back(content.size()); // Content Length
      binary_response.insert(binary_response.end(), content.begin(), content.end());
      binary_response.push_back(0); // Trailer section length
      return binary_response;
    }

    std::string get_url_from_binary_request(const std::vector<uint8_t>& binary_request) {
        std::string url;
        int offset = 0;
        offset += 1; // Skip framing indicator
        offset += 1 + binary_request[offset]; // Skip method
        size_t scheme_length = binary_request[offset];
        // Add Scheme to URL
        for (size_t i = 0; i < scheme_length; i++) {
            url.push_back(static_cast<char>(binary_request[offset + 1 + i]));
        }
        url += "://";
        offset += 1 + scheme_length; // Skip scheme length and scheme
        size_t authority_length = binary_request[offset];
        for (size_t i = 0; i < authority_length; i++) {
            url.push_back(static_cast<char>(binary_request[offset + 1 + i]));
        }
        offset += 1 + authority_length; // Skip authority length and authority
        size_t path_length = binary_request[offset];
        for (size_t i = 0; i < path_length; i++) {
            url.push_back(static_cast<char>(binary_request[offset + 1 + i]));
        }
        return url;
    }

    std::string get_method_from_binary_request(const std::vector<uint8_t>& binary_request) {
        std::string method;
        size_t method_len = binary_request[1];
        for (size_t i = 2; i < 2 + method_len; i++) {
            method.push_back(static_cast<char>(binary_request[i]));
        }
        return method;
    }

    std::string get_body_from_binary_request(const std::vector<uint8_t>& binary_request) {
        std::string body;
        int offset = 0;
        offset += 1; // Skip framing indicator
        offset += 1 + binary_request[offset]; // Skip method
        offset += 1 + binary_request[offset]; // Skip scheme
        offset += 1 + binary_request[offset]; // Skip authority
        offset += 1 + binary_request[offset]; // Skip path
        offset += 1 + binary_request[offset]; // Skip header section
        size_t body_length = binary_request[offset];
        for (size_t i = 1; i <= body_length; i++) {
            body.push_back(static_cast<char>(binary_request[offset + i]));
        }
        return body;
    }

    // TODO: Support configurable relay/gateway/keys.
    std::vector<uint8_t> get_encapsulated_request(
      EVP_HPKE_CTX* sender_context,
      const std::string& method,
      const std::string& scheme,
      const std::string& host,
      const std::string& path,
      const std::string& body,
      uint8_t* client_enc,
      size_t* client_enc_len,
      uint8_t* pkR,
      size_t pkR_len) {
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
        std::vector<uint8_t> binary_request = get_binary_request(method, scheme, host, path, body);

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

        int rv = EVP_HPKE_CTX_setup_sender(
            /* *ctx */ sender_context,
            /* *out_enc */ client_enc,
            /* *out_enc_len */ client_enc_len,
            /*  max_enc */ EVP_HPKE_MAX_ENC_LENGTH,
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
            EVP_HPKE_CTX_max_overhead(sender_context);
        std::vector<uint8_t> ciphertext(ct_max_len);
        size_t ciphertext_len;
        std::vector<uint8_t> aad = {
            0x80, // Key ID
            0x00, 0x20, // HPKE KEM ID
            0x00, 0x01, // KDF ID
            0x00, 0x01, // AEAD ID
        };
        rv = EVP_HPKE_CTX_seal(
            /* *ctx */ sender_context,
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

        // Per RFC 9292, the encapsulated request is the concatenation of the
        // aad, enc, and ciphertext.
        encapsulated_request.insert(encapsulated_request.end(), aad.begin(), aad.end());
        encapsulated_request.insert(encapsulated_request.end(), client_enc, client_enc + *client_enc_len);
        encapsulated_request.insert(encapsulated_request.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        return encapsulated_request;
    }

    std::vector<uint8_t> encapsulate_response(
        EVP_HPKE_CTX* receiver_context,
        uint8_t* enc,
        size_t enc_len,
        const int response_code,
        const std::string& response_body) {
      std::vector<uint8_t> binary_response = get_binary_response(
          response_code,
          std::vector<uint8_t>(response_body.begin(), response_body.end()));
      
      // random(max(Nn, Nk))
      size_t secret_len = 16;
      std::vector<uint8_t> secret(secret_len);
      std::string context_str = "message/bhttp response";
      std::vector<uint8_t> context = std::vector<uint8_t>(context_str.begin(), context_str.end());
      size_t context_len = context.size();
      int rv = EVP_HPKE_CTX_export(
        /* *ctx */ receiver_context,
        /* *out */ secret.data(),
        /*  secret_len */ secret_len,
        /* *context */ context.data(),
        /*  context_len */ context_len
      );
      if (rv != 1) {
        return {};
      }

      // Nonce of secret_len
      std::vector<uint8_t> response_nonce(secret_len);
      RAND_bytes(response_nonce.data(), secret_len);

      // salt = concat(enc, response_nonce);
      std::vector<uint8_t> salt(enc, enc + enc_len);
      salt.insert(salt.end(), response_nonce.begin(), response_nonce.end());

      // prk = Extract(salt, secret)
      size_t prk_len;
      uint8_t prk[EVP_MAX_MD_SIZE];
      int rv2 = HKDF_extract(
        /* *out_key */ prk,
        /* *out_len */ &prk_len,
        /* *digest */ EVP_sha256(),
        /* *secret */ secret.data(),
        /*  secret_len */ secret_len,
        /* *salt */ salt.data(),
        /*  salt_len */ salt.size()
      );
      if (rv2 != 1) {
        return {};
      }

      // aead_key = Expand(prk, "key", Nk)
      size_t aead_key_len = 16; // Nk
      uint8_t aead_key[aead_key_len];
      std::string info_key_str = "key";
      uint8_t info_key[info_key_str.size()];
      for (size_t i = 0; i < info_key_str.size(); i++) {
        info_key[i] = info_key_str[i];
      }
      size_t info_key_len = sizeof(info_key);
      int rv3 = HKDF_expand(
        /* *out */ aead_key,
        /*  out_len */ aead_key_len,
        /* *digest */ EVP_sha256(),
        /* *prk */ prk,
        /*  prk_len */ prk_len,
        /* *info */ info_key,
        /*  info_len */ info_key_len
      );
      if (rv3 != 1) {
        return {};
      }

      // aead_nonce = Expand(prk, "nonce", Nn)
      size_t aead_nonce_len = 12; // Nn
      uint8_t aead_nonce[aead_nonce_len];
      std::string info_nonce_str = "nonce";
      uint8_t info_nonce[info_nonce_str.size()];
      for (size_t i = 0; i < info_nonce_str.size(); i++) {
        info_nonce[i] = info_nonce_str[i];
      }
      size_t info_nonce_len = sizeof(info_nonce);
      int rv4 = HKDF_expand(
        /* *out */ aead_nonce,
        /*  out_len */ aead_nonce_len,
        /* *digest */ EVP_sha256(),
        /* *prk */ prk,
        /*  prk_len */ prk_len,
        /* *info */ info_nonce,
        /*  info_len */ info_nonce_len
      );
      if (rv4 != 1) {
        return {};
      }
  
      // ct = Seal(aead_key, aead_nonce, "", response)
      const EVP_AEAD* aead = EVP_aead_aes_128_gcm();
      EVP_AEAD_CTX *aead_ctx = EVP_AEAD_CTX_new(
        /* *aead */ aead,
        /* *key */ aead_key,
        /*  key_len */ aead_key_len,
        /*  tag_len */ EVP_AEAD_DEFAULT_TAG_LENGTH
      );

      size_t max_ct_len = binary_response.size() + EVP_AEAD_max_overhead(aead);
      uint8_t ct[max_ct_len];
      size_t ct_len;
      size_t required_len = EVP_AEAD_nonce_length(aead);
      if (required_len != aead_nonce_len) {
        std::cout << "Nonce length mismatch, expected: " << required_len << "; got: " << aead_nonce_len << std::endl;
        return {};
      }
      int rv5 = EVP_AEAD_CTX_seal(
        /* *ctx */ aead_ctx,
        /* *out */ ct,
        /* *out_len */ &ct_len,
        /*  max_out_len */ max_ct_len,
        /* *nonce */ aead_nonce,
        /*  nonce_len */ aead_nonce_len,
        /* *in */ binary_response.data(),
        /*  in_len */ binary_response.size(),
        /* *ad */ nullptr,
        /*  ad_len */ 0
      );
      if (rv5 != 1) {
        return {};
      }

      // enc_response = concat(response_nonce, ct)
      std::vector<uint8_t> enc_response;
      enc_response.insert(enc_response.end(), response_nonce.begin(), response_nonce.end());
      enc_response.insert(enc_response.end(), ct, ct + ct_len);

      return enc_response;
    }

    DecapsulationErrorCode decapsulate_response(
        EVP_HPKE_CTX* sender_context,
        uint8_t* enc,
        size_t enc_len,
        std::vector<uint8_t> eresponse,
        uint8_t* dresponse,
        size_t* dresponse_len,
        size_t max_drequest_len) {
      // Separate into nonce and ciphertext
      if (eresponse.size() < 12) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_AEAD_NONCE" << std::endl;
        return DecapsulationErrorCode::ERR_NO_AEAD_NONCE;
      }
      std::vector<uint8_t> response_nonce(eresponse.begin(), eresponse.begin() + 16);
      std::vector<uint8_t> ct(eresponse.begin() + 16, eresponse.end());
      
      size_t secret_len = 16;
      std::vector<uint8_t> secret(secret_len);
      std::string context_str = "message/bhttp response";
      std::vector<uint8_t> context = std::vector<uint8_t>(context_str.begin(), context_str.end());
      size_t context_len = context.size();
      int rv = EVP_HPKE_CTX_export(
        /* *ctx */ sender_context,
        /* *out */ secret.data(),
        /*  secret_len */ secret_len,
        /* *context */ context.data(),
        /*  context_len */ context_len
      );
      if (rv != 1) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_SECRET" << std::endl;
        return DecapsulationErrorCode::ERR_NO_SECRET;
      }

      // salt = concat(enc, response_nonce);
      std::vector<uint8_t> salt(enc, enc + enc_len);
      salt.insert(salt.end(), response_nonce.begin(), response_nonce.end());

      // prk = Extract(salt, secret)
      size_t prk_len;
      uint8_t prk[EVP_MAX_MD_SIZE];
      int rv2 = HKDF_extract(
        /* *out_key */ prk,
        /* *out_len */ &prk_len,
        /* *digest */ EVP_sha256(),
        /* *secret */ secret.data(),
        /*  secret_len */ secret_len,
        /* *salt */ salt.data(),
        /*  salt_len */ salt.size()
      );
      if (rv2 != 1) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_PRK" << std::endl;
        return DecapsulationErrorCode::ERR_NO_PRK;
      }

      // aead_key = Expand(prk, "key", Nk)
      size_t aead_key_len = 16; // Nk
      uint8_t aead_key[aead_key_len];
      std::string info_key_str = "key";
      uint8_t info_key[info_key_str.size()];
      for (size_t i = 0; i < info_key_str.size(); i++) {
        info_key[i] = info_key_str[i];
      }
      size_t info_key_len = sizeof(info_key);
      int rv3 = HKDF_expand(
        /* *out */ aead_key,
        /*  out_len */ aead_key_len,
        /* *digest */ EVP_sha256(),
        /* *prk */ prk,
        /*  prk_len */ prk_len,
        /* *info */ info_key,
        /*  info_len */ info_key_len
      );
      if (rv3 != 1) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_AEAD_KEY" << std::endl;
        return DecapsulationErrorCode::ERR_NO_AEAD_KEY;
      }

      // aead_nonce = Expand(prk, "nonce", Nn)
      size_t aead_nonce_len = 12; // Nn
      uint8_t aead_nonce[aead_nonce_len];
      std::string info_nonce_str = "nonce";
      uint8_t info_nonce[info_nonce_str.size()];
      for (size_t i = 0; i < info_nonce_str.size(); i++) {
        info_nonce[i] = info_nonce_str[i];
      }
      size_t info_nonce_len = sizeof(info_nonce);
      int rv4 = HKDF_expand(
        /* *out */ aead_nonce,
        /*  out_len */ aead_nonce_len,
        /* *digest */ EVP_sha256(),
        /* *prk */ prk,
        /*  prk_len */ prk_len,
        /* *info */ info_nonce,
        /*  info_len */ info_nonce_len
      );
      if (rv4 != 1) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_AEAD_NONCE" << std::endl;
        return DecapsulationErrorCode::ERR_NO_AEAD_NONCE;
      }
      const EVP_AEAD* aead = EVP_aead_aes_128_gcm();
      EVP_AEAD_CTX *aead_ctx = EVP_AEAD_CTX_new(
        /* *aead */ aead,
        /* *key */ aead_key,
        /*  key_len */ aead_key_len,
        /*  tag_len */ EVP_AEAD_DEFAULT_TAG_LENGTH
      );
      size_t max_pt_len = eresponse.size();
      uint8_t pt[max_pt_len];
      size_t pt_len;
      int rv5 = EVP_AEAD_CTX_open(
        /* *ctx */ aead_ctx,
        /* *out */ pt,
        /* *out_len */ &pt_len,
        /*  max_out_len */ max_pt_len,
        /* *nonce */ aead_nonce,
        /*  nonce_len */ aead_nonce_len,
        /* *in */ ct.data(),
        /*  in_len */ ct.size(),
        /* *ad */ nullptr,
        /*  ad_len */ 0
      );
      if (rv5 != 1) {
        return DecapsulationErrorCode::ERR_UNABLE_TO_OPEN_RESPONSE;
      }

      // Set the values the caller expects.
      if (pt_len > max_drequest_len) {
        std::cout << "return DecapsulationErrorCode::ERR_NO_BUFFER_SPACE" << std::endl;
        return DecapsulationErrorCode::ERR_NO_BUFFER_SPACE;
      }
      *dresponse_len = pt_len;
      std::copy(pt, pt + pt_len, dresponse);

      return DecapsulationErrorCode::SUCCESS;
    }

    DecapsulationErrorCode decapsulate_request(
        EVP_HPKE_CTX* receiver_context,
        std::vector<uint8_t> erequest,
        uint8_t* drequest,
        size_t* drequest_len,
        uint8_t* enc,
        size_t enc_len,
        size_t max_drequest_len,
        HPKE_KEY recipient_keypair) {

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
      enc_len = 32;  // Hardcoded for now.
      for (size_t i = 7; i < 39; i++) {
        enc[i - 7] = erequest[i];
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
      
      int rv2 = EVP_HPKE_CTX_setup_recipient(
        /* *ctx */ receiver_context,
        /* *key */ recipient_keypair.internal_key,
        /* *kdf */ EVP_hpke_hkdf_sha256(),
        /* *aead */ EVP_hpke_aes_128_gcm(),
        /* *enc */ enc,
        /*  enc_len */ enc_len,
        /* *info */ info.data(),
        /*  info_len */ info.size()
      );
      if (rv2 != 1) {
        return DecapsulationErrorCode::ERR_NO_CONTEXT_CREATED;
      }

      int rv3 = EVP_HPKE_CTX_open(
        /* *ctx */ receiver_context,
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