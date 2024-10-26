#include <vector>

#include "gtest/gtest.h"

#include "openssl/hpke.h"
#include "ohttp.h"

namespace {

EVP_HPKE_KEY getKeys() {
  // Use a newly derived keypair to do a roundtrip.
  EVP_HPKE_KEY *test_keypair = EVP_HPKE_KEY_new();
  const EVP_HPKE_KEM *kem = EVP_hpke_x25519_hkdf_sha256();
  int rv = EVP_HPKE_KEY_generate(test_keypair, kem);
  EXPECT_EQ(rv, 1); // Check if key generation was successful
  return *test_keypair;
}

TEST(OhttpTest, GetKeyConfig) {
  EVP_HPKE_KEY keypair = getKeys();
  std::vector<uint8_t> key_config = ohttp::generate_key_config(&keypair);

  // 2 byte length plus one config
  EXPECT_EQ(key_config.size(), 2 + 1 + 2 + 32 + 2 + 4);

  // First 2 bytes are remaining length
  EXPECT_EQ(key_config[0], 0);
  EXPECT_EQ(key_config[1], 1 + 2 + 32 + 2 + 4);
}

TEST(OhttpTest, ExtractPublicKeyFromConfig) {
  EVP_HPKE_KEY keypair = getKeys();
  uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t public_key_len;
  EXPECT_TRUE(EVP_HPKE_KEY_public_key(&keypair, public_key, &public_key_len, sizeof(public_key)));
  std::vector<uint8_t> public_key_vec(public_key, public_key + public_key_len);

  std::vector<uint8_t> key_config = ohttp::generate_key_config(&keypair);
  std::vector<uint8_t> config_public_key = ohttp::get_public_key(key_config);

  EXPECT_EQ(config_public_key.size(), 32);
  EXPECT_EQ(config_public_key, public_key_vec);
}

// Exercise the HPKE library without testing our code just as
// as a proof of concept to compare our code against.
TEST(OhttpTest, TestVector1) {
  const EVP_HPKE_KEM *kem = EVP_hpke_x25519_hkdf_sha256();    // 32
  const EVP_HPKE_KDF *kdf = EVP_hpke_hkdf_sha256();           // 1
  const EVP_HPKE_AEAD *aead = EVP_hpke_aes_128_gcm();         // 1

  EXPECT_TRUE(aead);
  EXPECT_TRUE(kdf);

  // Recipient keypair
  // Use the ones from the test server
  // 7a04f3070f2fc4c52c06eb373060b415dbd8e82effe4088965a2602c27b91646
  // std::vector<uint8_t> public_key_r_ = {
  //   0x7a, 0x04, 0xf3, 0x07, 0x0f, 0x2f, 0xc4, 0xc5,
  //   0x2c, 0x06, 0xeb, 0x37, 0x30, 0x60, 0xb4, 0x15,
  //   0xdb, 0xd8, 0xe8, 0x2e, 0xff, 0xe4, 0x08, 0x89,
  //   0x65, 0xa2, 0x60, 0x2c, 0x27, 0xb9, 0x16, 0x46
  // };
  // 
  // std::vector<uint8_t> secret_key_r_ = {}; 
  std::vector<uint8_t> public_key_r_ = {0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69, 0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda, 0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79, 0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d};
  std::vector<uint8_t> secret_key_r_ = {0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad, 0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5, 0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9, 0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8};

  std::vector<uint8_t> info_ = {0x44, 0x20, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e};
  
  // First round
  std::vector<uint8_t> aad = {0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30}; 
  std::vector<uint8_t> ct = {0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2, 0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4, 0xf8, 0x43, 0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5, 0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9, 0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea, 0x87, 0xe1, 0x3c, 0x51, 0x2a};
  std::vector<uint8_t> nonce = {0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7d};
  std::vector<uint8_t> pt = {0x42, 0x65, 0x61, 0x75, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x2c, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x20, 0x62, 0x65, 0x61, 0x75, 0x74, 0x79};
  
  // Ephemeral keys
  std::vector<uint8_t> secret_key_e_ = {0x52, 0xc4, 0xa7, 0x58, 0xa8, 0x02, 0xcd, 0x8b, 0x93, 0x6e, 0xce, 0xea, 0x31, 0x44, 0x32, 0x79, 0x8d, 0x5b, 0xaf, 0x2d, 0x7e, 0x92, 0x35, 0xdc, 0x08, 0x4a, 0xb1, 0xb9, 0xcf, 0xa2, 0xf7, 0x36};
  std::vector<uint8_t> public_key_e_ = {0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d, 0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31};

  bssl::ScopedEVP_HPKE_CTX sender_ctx;
  uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];  // len is 32
  size_t enc_len;
  // Like our usual setup, but with known seed in secrect_key_e_.
  EXPECT_TRUE(EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
      sender_ctx.get(), enc, &enc_len, sizeof(enc), kem, kdf, aead,
      public_key_r_.data(), public_key_r_.size(), info_.data(), info_.size(),
      secret_key_e_.data(), secret_key_e_.size()));

  std::vector<uint8_t> enc_vec(enc, enc + enc_len);
  EXPECT_EQ(enc_vec, public_key_e_);

  // Verify first output
  std::vector<uint8_t> encrypted(pt.size() + EVP_HPKE_CTX_max_overhead(sender_ctx.get()));
  size_t encrypted_len;
  EXPECT_EQ(1, EVP_HPKE_CTX_seal(sender_ctx.get(), encrypted.data(), &encrypted_len,
                                 encrypted.size(), pt.data(),
                                 pt.size(), aad.data(),
                                 aad.size()));
  std::vector<uint8_t> encrypted_vec(encrypted.data(), encrypted.data() + encrypted_len);
  // EXPECT_EQ(encrypted_vec, ct);

  // Test the recipient.
  bssl::ScopedEVP_HPKE_KEY base_key;
  ASSERT_TRUE(EVP_HPKE_KEY_init(base_key.get(), kem, secret_key_r_.data(),
                                secret_key_r_.size()));

  const EVP_HPKE_KEY *key = base_key.get();

  uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t public_key_len;
  EXPECT_TRUE(EVP_HPKE_KEY_public_key(key, public_key, &public_key_len,
                                      sizeof(public_key)));
  std::vector<uint8_t> public_key_vec(public_key, public_key + public_key_len);
  EXPECT_EQ(public_key_vec, public_key_r_);

  // Now the same with the private key
  uint8_t secret_key[EVP_HPKE_MAX_PRIVATE_KEY_LENGTH];
  size_t secret_key_len;
  EXPECT_TRUE(EVP_HPKE_KEY_private_key(key, secret_key, &secret_key_len,
                                       sizeof(secret_key)));
  std::vector<uint8_t> secret_key_vec(secret_key, secret_key + secret_key_len);
  EXPECT_EQ(secret_key_vec, secret_key_r_);

  // Set up the recipient
  bssl::ScopedEVP_HPKE_CTX recipient_ctx;
  EXPECT_TRUE(EVP_HPKE_CTX_setup_recipient(recipient_ctx.get(), key, kdf,
                                           aead, enc, enc_len, info_.data(),
                                           info_.size()));

  // Verify Decryption
  std::vector<uint8_t> decrypted(ct.size());
  size_t decrypted_len;
  EXPECT_EQ(1, EVP_HPKE_CTX_open(recipient_ctx.get(), decrypted.data(),
                                  &decrypted_len, decrypted.size(),
                                  encrypted.data(), encrypted_len, aad.data(),
                                  aad.size()));
  std::vector<uint8_t> decrypted_vec(decrypted.data(), decrypted.data() + decrypted_len);
  EXPECT_EQ(decrypted_vec, pt);
}

// Test a sample function to make sure build is setup correctly.
TEST(OhttpTest, TestOHTTPDetected) {
  EXPECT_EQ(ohttp::GetFoo(), "foo");
}

// Test encoding strings.
TEST(EncodeStringTest, TestEncodeString) {
  std::string input = "hello";
  // Length is a 2-byte number.
  std::vector<uint8_t> expected = {5, 'h', 'e', 'l', 'l', 'o'};
  EXPECT_EQ(ohttp::encode_string(input), expected);
}

// Test extracting encoded strings.
TEST(DecodeStringTest, TestDecodeString) {
  int starting_offset = 0;
  std::vector<uint8_t> input = {5, 0x42, 0x43, 0x44, 0x45, 0x46, 1, 0x47};
  std::vector<uint8_t> expected = {0x42, 0x43, 0x44, 0x45, 0x46};
  std::vector<uint8_t> output;
  int bytes_used;
  EXPECT_EQ(ohttp::get_next_encoded_string(input, starting_offset, output, bytes_used), ohttp::OhttpParseErrorCode::SUCCESS);
  EXPECT_EQ(output, expected);
  EXPECT_EQ(bytes_used, 6);
  int next_offset = starting_offset + bytes_used;
  expected = {0x47};
  std::vector<uint8_t> output2;
  EXPECT_EQ(ohttp::get_next_encoded_string(input, next_offset, output2, bytes_used), ohttp::OhttpParseErrorCode::SUCCESS);
  EXPECT_EQ(output2, expected);
  EXPECT_EQ(bytes_used, 2);
}

// Test binary request creation per https://www.rfc-editor.org/rfc/rfc9292
TEST(OhttpTest, TestBinaryRequest) {
  std::vector<uint8_t> request =
      ohttp::get_binary_request("/", "ohttp-gateway.jthess.com", "foo");
  std::vector<uint8_t> expected = {
      // Known-Length Request {
      //   Framing Indicator (i) = 0,
      //   Request Control Data (..),
      //   Known-Length Field Section (..),
      //   Known-Length Content (..),
      //   Known-Length Field Section (..),
      //   Padding (..),
      // }

      // Framing Indicator
      0,

      // Control Data
      // Request Control Data {
      //   Method Length (i),
      4,
      //   Method (..),
      'P', 'O', 'S', 'T',  // Method Length & Method
      //   Scheme Length (i),
      5,
      //   Scheme (..),
      'h', 't', 't', 'p', 's',
      //   Authority Length (i),
      24,
      //   Authority (..),
      'o', 'h', 't', 't', 'p', '-', 'g', 'a', 't', 'e', 'w', 'a', 'y', '.', 'j',
      't', 'h', 'e', 's', 's', '.', 'c', 'o', 'm',
      //   Path Length (i),
      1,
      //   Path (..),
      // }
      '/',

      // Header section.
      // Known-Length Field Section {
      //   Length (i),
      0,
      //   Field Line (..) ...,
      // }

      // Known-Length Content {
      //   Content Length (i),
      3,
      //   Content (..),
      'f', 'o', 'o',
      // }

      // Trailer section.
      // Known-Length Field Section {
      //   Length (i),
      0,
      //   Field Line (..) ...,
      // }
  };
  EXPECT_EQ(request, expected);
}

TEST(OhttpTest, TestBinaryResponse) {
  std::string response_message = "this is a response";
  std::vector<uint8_t> response_message_vec = std::vector<uint8_t>(response_message.begin(), response_message.end());
  std::vector<uint8_t> response = ohttp::get_binary_response(response_message_vec);
  std::vector<uint8_t> expected = {
    // Known-Length Response {
    //   Framing Indicator (i) = 1,
    //   Known-Length Informational Response (..) ...,
    //   Final Response Control Data (..),
    //   Known-Length Field Section (..),
    //   Known-Length Content (..),
    //   Known-Length Field Section (..),
    //   Padding (..),
    // }
    1,

    // No informational responses in this test.
    // Known-Length Informational Response {
    //   Informational Response Control Data (..),
    //   Known-Length Field Section (..),
    // }

    // Final Response Control Data {
    //   Status Code (i) = 200..599,
    // }
    200,

    // Known-Length Field Section {
    //   Length (i),
    //   Field Line (..) ...,
    // }
    0,

    // Known-Length Content {
    //   Content Length (i),
    //   Content (..),
    // }
    18, // Length of "this is a response"
    't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e',

    // Trailer section.
    // Known-Length Field Section {
    //   Length (i),
    //   Field Line (..) ...,
    // }
    0,
  };
  EXPECT_EQ(response, expected);
}

TEST(OhttpTest, EncapsulateAndDecapsulateResponse) {
  EVP_HPKE_KEY test_keypair = getKeys();
  uint8_t pkR[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = EVP_HPKE_KEY_public_key(
      &test_keypair, pkR, &pkR_len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);

  EVP_HPKE_CTX sender_context;
  std::vector<uint8_t> encapsulated_request =
      ohttp::get_encapsulated_request(
        &sender_context,
        "/", "ohttp-gateway.jthess.com", "foo",
        pkR,
        pkR_len);
    
  EVP_HPKE_CTX receiver_context;
  size_t max_req_out_len = encapsulated_request.size();
  std::vector<uint8_t> request_bhttp(max_req_out_len);
  size_t req_out_len;
  size_t enc_len = 32;
  u_int8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    &receiver_context,
    encapsulated_request,
    request_bhttp.data(),
    &req_out_len,
    enc,
    enc_len,
    max_req_out_len,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::SUCCESS);

  // Give a made up response.
  std::vector<uint8_t> encapsulated_response = ohttp::encapsulate_response(
    &receiver_context,
    enc,
    enc_len,
    "this is a response");
  // Be sure its actually populated; we'll verify contents below.
  EXPECT_GT(encapsulated_response.size(), 32 + 18);

  // Then decapsulate the response back at the sender.
  size_t max_resp_out_len = encapsulated_response.size();
  uint8_t response_bhttp[max_resp_out_len];
  size_t resp_out_len;
  ohttp::DecapsulationErrorCode rv3 = ohttp::decapsulate_response(
    &sender_context,
    enc,
    enc_len,
    encapsulated_response,
    response_bhttp,
    &resp_out_len,
    max_resp_out_len);
  EXPECT_EQ(rv3, ohttp::DecapsulationErrorCode::SUCCESS);

  EXPECT_EQ(resp_out_len, 23);  // 18 plus the BHTTP encoding
}

TEST(OhttpTest, ParseBinaryRequest)
{
  std::vector<uint8_t> request =
      ohttp::get_binary_request("/", "ohttp-gateway.jthess.com", "foo");

  std::string method = ohttp::get_method_from_binary_request(request);
  std::string expected_method = "POST";
  EXPECT_EQ(method, expected_method);

  std::string url = ohttp::get_url_from_binary_request(request);
  std::string expected_url = "https://ohttp-gateway.jthess.com/";
  EXPECT_EQ(url, expected_url);

  std::string body = ohttp::get_body_from_binary_request(request);
  std::string expected_body = "foo";
  EXPECT_EQ(body, expected_body);
}

// Test that encapsulation starts with the correct header.
TEST(OhttpTest, TestEncapsulatedRequestHeader) {
  // Encapsulation per RFC 9458:
  // https://www.rfc-editor.org/rfc/rfc9458

  // hdr = concat(encode(1, key_id),
  //              encode(2, kem_id),
  //              encode(2, kdf_id),
  //              encode(2, aead_id))
  // info = concat(encode_str("message/bhttp request"),
  //               encode(1, 0),
  //               hdr)
  // enc, sctxt = SetupBaseS(pkR, info)
  // ct = sctxt.Seal("", request)
  // enc_request = concat(hdr, enc, ct)

  EVP_HPKE_KEY test_keypair = getKeys();
  uint8_t pkR[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = EVP_HPKE_KEY_public_key(
      &test_keypair, pkR, &pkR_len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  EVP_HPKE_CTX sender_context;
  std::vector<uint8_t> request =
      ohttp::get_encapsulated_request(&sender_context, "/", "ohttp-gateway.jthess.com", "foo", pkR, pkR_len);

  std::vector<uint8_t> expected_hdr = {
      0x80,        // Key ID
      0x00, 0x20,  // HPKE KEM ID
      0x00, 0x01,  // KDF ID
      0x00, 0x01,  // AEAD ID
  };

  // hdr portion of the encapsulated request is the first 7 bytes of request.
  int hdr_length = 7;
  std::vector<uint8_t> actual_hdr(hdr_length);
  std::copy(request.begin() + 0, request.begin() + hdr_length,
            actual_hdr.begin());
  EXPECT_EQ(expected_hdr, actual_hdr);

  // enc and ct vary.  Their creation is outsourced to HPKE implementation from
  // openssl.
}

TEST(OhttpTest, DecapsulateEmptyRequestFails) {
  EVP_HPKE_KEY test_keypair = getKeys();
  size_t pkR_len = 32;
  uint8_t pkR[pkR_len];
  size_t written;
  int rv = EVP_HPKE_KEY_public_key(
      &test_keypair, pkR, &written, pkR_len);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  // Now, decapsulate it with the same keypair
  EVP_HPKE_CTX receiver_context;
  std::vector<uint8_t> empty_request = {};
  std::vector<uint8_t> request_bhttp(0);
  size_t out_len;
  size_t enc_len = 32;
  uint8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    &receiver_context,
    empty_request,
    request_bhttp.data(),
    &out_len,
    enc,
    enc_len,
    0,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::ERR_NO_ENCAPSULATED_HEADER);
}

// Enc/Decapsulate routrip test
TEST(OhttpTest, EncapsulateAndDecapsulateRequest) {
  // Recipient keys
  EVP_HPKE_KEY test_keypair = getKeys();
  uint8_t pkR[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = EVP_HPKE_KEY_public_key(
      &test_keypair, pkR, &pkR_len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  // Encapsulate it
  EVP_HPKE_CTX sender_context;
  std::vector<uint8_t> request =
      ohttp::get_encapsulated_request(&sender_context, "/", "ohttp-gateway.jthess.com", "foo", pkR, pkR_len);

  EVP_HPKE_CTX receiver_context;
  size_t max_out_len = request.size();
  std::vector<uint8_t> request_bhttp(max_out_len);
  size_t out_len;
  size_t enc_len = 32;
  uint8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    &receiver_context,
    request,
    request_bhttp.data(),
    &out_len,
    enc,
    enc_len,
    max_out_len,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::SUCCESS);

  std::vector<uint8_t> expected_bhttp = ohttp::get_binary_request("/", "ohttp-gateway.jthess.com", "foo");
  EXPECT_EQ(out_len, expected_bhttp.size());
  std::vector<uint8_t> request_bhttp_vec(request_bhttp.data(), request_bhttp.data() + out_len);
  EXPECT_EQ(request_bhttp_vec, expected_bhttp);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}