#include "../../include/drivers/crypto_driver.hpp"
#include "../../include-shared/util.hpp" // For print_bytes if needed
#include "../../include-shared/messages.hpp" // Include for key type definitions


#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/eccrypto.h> // For ECC curves if using ECDH
#include <cryptopp/oids.h>     // For OIDs like secp256r1
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>      // For DH2 if needed
#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>    // For CBC_Mode
#include <cryptopp/filters.h>  // For StringSource, StreamTransformationFilter

#include <iostream>
#include <stdexcept>


// Constructor: Initialize DH domain parameters
CryptoDriver::CryptoDriver() {
    // Using primes from RFC 3526, 2048-bit MODP Group
    // Replace with your chosen domain parameters if different
    CryptoPP::Integer p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                        "ABF5AE8CDB0933D71E8C94E04A25619DCEF135F07C4295A6"
                        "AC7420BD99FBFB5531D58DEAEC5425EDC94EB75551DE6BF7"
                        "6FD94801F860934A7217A43B213A3A37F04CE47134F343D1"
                        "B6F1A8F1D81C5DE011C81F78810F5FFA00253C8901669B4B"
                        "8B46077738D76968F4693D0ED304BD2BBF837049A29EFA03"
                        "683391FDE5B007B3F00877A25BE67AF05715388B08181BD8"
                        "E4151B18EB6840877626190E37512E40F07F868F87265A53"
                        "C9A9C940E84F316CC0D94EA02211ABCFC431C945D5A884E3"
                        "690CEBE389F4743D5F558EB837337D6F6175D912C8F1B364"
                        "7971504E24A8B597EDFF89F126F0EE69BF06A1A32716A902"
                        "78BA17");
    CryptoPP::Integer g = 2;
    this->dh.AccessGroupParameters().Initialize(p, g);

    // Initialize maybe? Or require explicit call?
    // DH_initialize(); // Let's require explicit initialization after construction
}

// --- HKDF Implementation ---
void CryptoDriver::HKDF(const CryptoPP::SecByteBlock& salt,
                        const CryptoPP::SecByteBlock& ikm,
                        const CryptoPP::SecByteBlock& info, size_t info_len,
                        CryptoPP::SecByteBlock& derived_key1, size_t dk1_len,
                        CryptoPP::SecByteBlock& derived_key2, size_t dk2_len) {
    CryptoPP::HKDF<HASH> kdf;
    size_t total_len = dk1_len + dk2_len;
    CryptoPP::SecByteBlock derived_keys(total_len);

    kdf.DeriveKey(derived_keys.BytePtr(), derived_keys.SizeInBytes(),
                  ikm.BytePtr(), ikm.SizeInBytes(),
                  salt.BytePtr(), salt.SizeInBytes(),
                  info.BytePtr(), info_len);

    derived_key1.Assign(derived_keys.BytePtr(), dk1_len);
    if (dk2_len > 0) {
      derived_key2.Assign(derived_keys.BytePtr() + dk1_len, dk2_len);
    }
}


// --- Double Ratchet KDFs ---
std::pair<RootKey, ChainKey> CryptoDriver::KDF_RK(const RootKey& rk,
                                                 const CryptoPP::SecByteBlock& dh_shared_secret) {
    RootKey new_rk(HASH_SIZE); // Typically 32 bytes for SHA256-based HKDF
    ChainKey new_ck(HASH_SIZE);

    // Salt = Old Root Key, IKM = DH Shared Secret
    HKDF(rk, dh_shared_secret, KDF_RK_INFO, sizeof(KDF_RK_INFO), new_rk, HASH_SIZE, new_ck, HASH_SIZE);

    return {new_rk, new_ck};
}

std::pair<ChainKey, MessageKey> CryptoDriver::KDF_CK(const ChainKey& ck) {
    MessageKey mk(KEY_SIZE); // e.g., 16 bytes for AES-128
    ChainKey next_ck(HASH_SIZE); // 32 bytes

    // Use HMAC with constant inputs (as described in Signal spec)
    // Derive Message Key
    HMAC_DR hmac_mk(ck.BytePtr(), ck.size());
    hmac_mk.Update(KDF_MK_INFO, sizeof(KDF_MK_INFO));
    mk.resize(KEY_SIZE); // Ensure correct size before Final
    hmac_mk.TruncatedFinal(mk.BytePtr(), KEY_SIZE);

    // Derive Next Chain Key
    HMAC_DR hmac_ck(ck.BytePtr(), ck.size());
    hmac_ck.Update(KDF_CK_INFO, sizeof(KDF_CK_INFO));
    next_ck.resize(HASH_SIZE); // Ensure correct size
    hmac_ck.TruncatedFinal(next_ck.BytePtr(), HASH_SIZE);


    return {next_ck, mk};
}


// --- DH Key Management ---
void CryptoDriver::DH_initialize() {
  // Generate the initial long-term identity key pair
  // In a real system, this might be loaded from storage
  dh_priv_key.New(dh.PrivateKeyLength());
  dh_pub_key.New(dh.PublicKeyLength());
  dh.GenerateKeyPair(prng, dh_priv_key, dh_pub_key);
}

void CryptoDriver::DH_generate_ratchet_keypair(CryptoPP::SecByteBlock& priv_key, DHPublicKey& pub_key) {
    priv_key.New(dh.PrivateKeyLength());
    pub_key.New(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, priv_key, pub_key);
}


CryptoPP::SecByteBlock CryptoDriver::DH_generate_shared_secret(const CryptoPP::SecByteBlock &priv_key,
                                                              const DHPublicKey &their_pub_key) {
  CryptoPP::SecByteBlock shared_secret(dh.AgreedValueLength());
  if (!dh.Agree(shared_secret, priv_key, their_pub_key)) {
    throw std::runtime_error("DH key agreement failed");
  }
  // Consider running the result through a KDF (like HKDF) if not using directly in KDF_RK
  // For DR, KDF_RK handles this, so return the raw agreed value.
  return shared_secret;
}

DHPublicKey CryptoDriver::get_dh_public_key() const {
    // Ensure initialized
    if (dh_pub_key.empty()) {
        throw std::runtime_error("DH keys not initialized, can't find public key");
    }
  return dh_pub_key;
}

CryptoPP::SecByteBlock CryptoDriver::get_dh_private_key() const {
    // Ensure initialized
    if (dh_priv_key.empty()) {
        throw std::runtime_error("DH keys not initialized, can't find private key");
    }
  return dh_priv_key;
}


// --- Symmetric Cryptography ---

// These generation functions are less useful now, keys come from KDF_CK
CryptoPP::SecByteBlock CryptoDriver::AES_generate_key(const CryptoPP::SecByteBlock &shared_secret) {
    // Example: Use HKDF to derive AES key from shared secret (if needed outside DR)
    CryptoPP::SecByteBlock aes_key(KEY_SIZE);
    CryptoPP::HKDF<HASH> kdf;
    kdf.DeriveKey(aes_key.BytePtr(), aes_key.size(),
                  shared_secret.BytePtr(), shared_secret.size(),
                  nullptr, 0, // No salt
                  string_to_byteblock("AES Key").BytePtr(), 7); // Simple info
    return aes_key;
}

CryptoPP::SecByteBlock CryptoDriver::HMAC_generate_key(const CryptoPP::SecByteBlock &shared_secret) {
     // Example: Use HKDF to derive HMAC key from shared secret (if needed outside DR)
    CryptoPP::SecByteBlock hmac_key(HASH_SIZE); // Use full hash output size for HMAC keys
    CryptoPP::HKDF<HASH> kdf;
    kdf.DeriveKey(hmac_key.BytePtr(), hmac_key.size(),
                  shared_secret.BytePtr(), shared_secret.size(),
                  nullptr, 0, // No salt
                  string_to_byteblock("HMAC Key").BytePtr(), 8); // Simple info
    return hmac_key;
}


// AES Encryption (Using CBC mode as per original code - Ensure AD is used in MAC!)
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
CryptoDriver::AES_encrypt(const MessageKey &key, const std::string &plaintext, const std::string& associated_data) {
    // Ensure key is correct size
    if (key.size() != KEY_SIZE) {
        throw std::runtime_error("AES encryption error: Incorrect key size.");
    }

    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE); // 16 bytes IV for AES
    prng.GenerateBlock(iv, iv.size());

    CryptoPP::SecByteBlock ciphertext;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Use StringSource and StreamTransformationFilter for padding
        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
               new CryptoPP::ArraySink(ciphertext.BytePtr(), ciphertext.SizeInBytes())
            ) // StreamTransformationFilter
        ); // StringSource
    } catch(const CryptoPP::Exception& e) {
        throw std::runtime_error("AES encryption failed: " + std::string(e.what()));
    }

    // IMPORTANT: The MAC must cover the IV, Ciphertext, AND Associated Data (header)
    // The HMAC generation function should handle this.

    return {iv, ciphertext};
}

// TODO: instead of using optional, throw an error if decryption fails 

// AES Decryption (Using CBC mode)
std::string CryptoDriver::AES_decrypt(const MessageKey &key,
                                      const CryptoPP::SecByteBlock &iv,
                                      const CryptoPP::SecByteBlock &ciphertext,
                                      const std::string& associated_data) {
    // Ensure key is correct size
     if (key.size() != KEY_SIZE) {
        std::cerr << "AES decryption error: Incorrect key size." << std::endl;
        throw std::runtime_error("AES decryption error: Incorrect key size.");
        return "";
    }
    // Ensure IV is correct size
     if (iv.size() != CryptoPP::AES::BLOCKSIZE) {
         std::cerr << "AES decryption error: Incorrect IV size." << std::endl;
        throw std::runtime_error("AES decryption error: Incorrect IV size.");
         return "";
     }

    std::string recovered_plaintext;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Use SecByteBlockSource and StreamTransformationFilter
        CryptoPP::ArraySource ss(ciphertext.BytePtr(), ciphertext.SizeInBytes(), true,
            new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::StringSink(recovered_plaintext)
            )  // StreamTransformationFilter
        );

    } catch(const CryptoPP::Exception& e) {
        std::cerr << "AES decryption failed: " << e.what() << std::endl;
        throw std::runtime_error("AES decryption failed: " + std::string(e.what()));
        return ""; 
    }

    // IMPORTANT: MAC verification MUST happen *before* returning plaintext.
    // The caller (Client::RatchetDecrypt) must call HMAC_verify including the associated_data.

    return recovered_plaintext;
}


// HMAC Generation (Includes Associated Data)
CryptoPP::SecByteBlock CryptoDriver::HMAC_generate(const MessageKey &key,
                                       const CryptoPP::SecByteBlock &iv,
                                       const CryptoPP::SecByteBlock &ciphertext,
                                       const std::string& associated_data) {
    CryptoPP::SecByteBlock mac(HASH_SIZE); // 32 bytes for SHA256
    try {
        HMAC_DR hmac(key.BytePtr(), key.size());

        // Hash(AD || IV || Ciphertext)
        hmac.Update(string_to_byteblock(associated_data).BytePtr(), associated_data.size());
        hmac.Update(iv.BytePtr(), iv.size());
        hmac.Update(ciphertext.BytePtr(), ciphertext.size());

        mac.resize(HASH_SIZE); // Ensure correct size before Final
        hmac.Final(mac.BytePtr());
    } catch(const CryptoPP::Exception& e) {
        throw std::runtime_error("HMAC generation failed: " + std::string(e.what()));
    }
    return mac;
}


// HMAC Verification (Includes Associated Data)
bool CryptoDriver::HMAC_verify(const MessageKey &key,
                               const CryptoPP::SecByteBlock &iv,
                               const CryptoPP::SecByteBlock &ciphertext,
                               const CryptoPP::SecByteBlock &mac,
                               const std::string& associated_data) {
    try {
        HMAC_DR hmac(key.BytePtr(), key.size());

         // Hash(AD || IV || Ciphertext) - must be identical to generation
        hmac.Update(string_to_byteblock(associated_data).BytePtr(), associated_data.size());
        hmac.Update(iv.BytePtr(), iv.size());
        hmac.Update(ciphertext.BytePtr(), ciphertext.size());

        return hmac.Verify(mac.BytePtr());

    } catch(const CryptoPP::Exception& e) {
        std::cerr << "HMAC verification failed: " << e.what() << std::endl;
        return false;
    }
}