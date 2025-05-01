#ifndef __CRYPTO_DRIVER_HPP__
#define __CRYPTO_DRIVER_HPP__

#include <cryptopp/cryptlib.h>
#include <cryptopp/dh.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/hkdf.h> // Include HKDF
#include <cryptopp/hmac.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>


#include <optional>
#include <stdexcept>
#include <string>
#include <utility> // For std::pair

#include "messages.hpp" // Include for key type definitions

// Define constants for KDF info fields (ensure they are distinct)
const CryptoPP::byte KDF_RK_INFO[] = {0x01, 'R', 'K'}; // Example info for Root Key KDF
const CryptoPP::byte KDF_CK_INFO[] = {0x02, 'C', 'K'}; // Example info for Chain Key KDF
const CryptoPP::byte KDF_MK_INFO[] = {0x03, 'M', 'K'}; // Example info for Message Key KDF


// Using SHA256 for HMAC and HKDF typically
using HASH = CryptoPP::SHA256;
using HMAC_DR = CryptoPP::HMAC<HASH>;
const unsigned int KEY_SIZE = CryptoPP::AES::DEFAULT_KEYLENGTH; // 16 bytes for AES-128
const unsigned int HASH_SIZE = HASH::DIGESTSIZE; // 32 bytes for SHA256


class CryptoDriver {
  CryptoPP::DH dh;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::SecByteBlock dh_priv_key;
  CryptoPP::SecByteBlock dh_pub_key;

  // --- Key Derivation Function (HKDF based) ---
  // HKDF<HASH> kdf; // Can instantiate HKDF if needed directly

  // Helper for HKDF extraction and expansion
  void HKDF(const CryptoPP::SecByteBlock& salt,
            const CryptoPP::SecByteBlock& ikm, // Input Keying Material
            const CryptoPP::byte* info, size_t info_len,
            CryptoPP::SecByteBlock& derived_key1, size_t dk1_len,
            CryptoPP::SecByteBlock& derived_key2, size_t dk2_len);

  // Specific KDF for Double Ratchet steps
  // Derives new Root Key (RK) and Chain Key (CK) from old RK and DH shared secret
  std::pair<RootKey, ChainKey> KDF_RK(const RootKey& rk,
                                       const CryptoPP::SecByteBlock& dh_shared_secret);

  // Derives next Chain Key (CK) and Message Key (MK) from current CK
  std::pair<ChainKey, MessageKey> KDF_CK(const ChainKey& ck);


public:
  CryptoDriver(); // Constructor initializes DH domain

  // --- DH Key Management ---
  void DH_initialize(); // Generates initial long-term keys (or load)
  void DH_generate_ratchet_keypair(CryptoPP::SecByteBlock& priv_key, DHPublicKey& pub_key);
  CryptoPP::SecByteBlock DH_generate_shared_secret(const CryptoPP::SecByteBlock &priv_key,
                                                  const DHPublicKey &their_pub_key);

  // Expose current public key
  DHPublicKey get_dh_public_key() const; // Get the *initial* identity public key
  // Note: Ratchet keys are managed within the Client state now


  // --- Symmetric Cryptography (Existing Methods - check if modifications needed) ---
  // Ensure these handle SecByteBlock correctly

  // Generate a key (potentially rename or clarify if it's for AES or HMAC)
  // These might become less relevant if keys are derived solely via KDF_CK
  CryptoPP::SecByteBlock AES_generate_key(const CryptoPP::SecByteBlock &shared_secret);
  CryptoPP::SecByteBlock HMAC_generate_key(const CryptoPP::SecByteBlock &shared_secret);


  // AES Encryption (CBC Mode in original - Consider AES-GCM for AEAD)
  // Pass associated_data (header bytes) for AEAD modes or MAC calculation
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  AES_encrypt(const MessageKey &key, const std::string &plaintext, const std::string& associated_data);

  // AES Decryption
  std::optional<std::string> AES_decrypt(const MessageKey &key,
                                       const CryptoPP::SecByteBlock &iv,
                                       const CryptoPP::SecByteBlock &ciphertext,
                                       const std::string& associated_data); // Pass AD for verification

  // HMAC Generation & Verification
  CryptoPP::SecByteBlock HMAC_generate(const MessageKey &key, // Use message key for MAC
                                       const CryptoPP::SecByteBlock &iv,
                                       const CryptoPP::SecByteBlock &ciphertext,
                                       const std::string& associated_data); // Include AD in MAC

  bool HMAC_verify(const MessageKey &key, // Use message key for MAC
                   const CryptoPP::SecByteBlock &iv,
                   const CryptoPP::SecByteBlock &ciphertext,
                   const CryptoPP::SecByteBlock &mac,
                   const std::string& associated_data); // Include AD in verification

};

#endif // __CRYPTO_DRIVER_HPP__