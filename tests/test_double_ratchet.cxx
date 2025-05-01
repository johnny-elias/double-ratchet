#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include "drivers/crypto_driver.hpp"
#include "include-shared/messages.hpp"
#include "include-shared/util.hpp" // For Util::byteblock_to_hex etc.

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <iostream>
#include <stdexcept> // For runtime_error

// --- Test Setup ---

// Structure to hold the Double Ratchet state for one party in tests
struct DRState {
    RootKey RK;
    ChainKey CKs;
    ChainKey CKr;
    CryptoPP::SecByteBlock DHs_priv; // Our current DH ratchet private key
    DHPublicKey DHs_pub;             // Our current DH ratchet public key
    DHPublicKey DHr_pub;             // Remote party's current DH ratchet public key
    uint32_t Ns = 0;
    uint32_t Nr = 0;
    uint32_t PN = 0;
    std::map<SkippedMessageKeyId, MessageKey> MKskipped;
    bool initialized = false;

    // Need access to crypto functions
    std::shared_ptr<CryptoDriver> crypto; // Use shared_ptr for convenience

    DRState(std::shared_ptr<CryptoDriver> crypto_ptr) : crypto(crypto_ptr) {}
};

// Helper function to simulate KDF_RK from CryptoDriver
// Needed because KDF_RK is private in the provided code.
// In a real test setup, you might make KDFs public or use friend classes.
// For now, we replicate the logic here based on the CryptoDriver implementation.
std::pair<RootKey, ChainKey> Simulate_KDF_RK(
    const RootKey& rk,
    const CryptoPP::SecByteBlock& dh_shared_secret,
    std::shared_ptr<CryptoDriver> crypto // Pass crypto driver instance if needed for HKDF helper
) {
    // Replicate the HKDF logic from CryptoDriver::KDF_RK
    // This assumes HKDF helper or direct HKDF usage is accessible/replicated
    RootKey new_rk(HASH_SIZE);
    ChainKey new_ck(HASH_SIZE);

    // --- Replicated HKDF Logic (Example - adjust if CryptoDriver::HKDF is different) ---
    CryptoPP::HKDF<HASH> kdf;
    size_t total_len = HASH_SIZE + HASH_SIZE;
    CryptoPP::SecByteBlock derived_keys(total_len);

    kdf.DeriveKey(derived_keys.BytePtr(), derived_keys.SizeInBytes(),
                  dh_shared_secret.BytePtr(), dh_shared_secret.SizeInBytes(), // IKM = DH secret
                  rk.BytePtr(), rk.SizeInBytes(),                             // Salt = old RK
                  KDF_RK_INFO, sizeof(KDF_RK_INFO));                          // Info

    new_rk.Assign(derived_keys.BytePtr(), HASH_SIZE);
    new_ck.Assign(derived_keys.BytePtr() + HASH_SIZE, HASH_SIZE);
    // --- End Replicated HKDF Logic ---

    return {new_rk, new_ck};
}

// Helper function to simulate KDF_CK from CryptoDriver
// Needed because KDF_CK is private. Replicate logic.
std::pair<ChainKey, MessageKey> Simulate_KDF_CK(
    const ChainKey& ck,
    std::shared_ptr<CryptoDriver> crypto // Pass crypto driver instance
) {
     // Replicate the HMAC logic from CryptoDriver::KDF_CK
    MessageKey mk(KEY_SIZE);
    ChainKey next_ck(HASH_SIZE);

    // Derive Message Key
    HMAC_DR hmac_mk(ck.BytePtr(), ck.size());
    hmac_mk.Update(KDF_MK_INFO, sizeof(KDF_MK_INFO));
    mk.resize(KEY_SIZE);
    hmac_mk.TruncatedFinal(mk.BytePtr(), KEY_SIZE);

    // Derive Next Chain Key
    HMAC_DR hmac_ck(ck.BytePtr(), ck.size());
    hmac_ck.Update(KDF_CK_INFO, sizeof(KDF_CK_INFO));
    next_ck.resize(HASH_SIZE);
    hmac_ck.TruncatedFinal(next_ck.BytePtr(), HASH_SIZE);

    return {next_ck, mk};
}


// Simulate Alice's initialization (mirrors Client::RatchetInitAlice)
void SimulateRatchetInitAlice(DRState& alice_state, const CryptoPP::SecByteBlock& SK, const DHPublicKey& bob_ratchet_pub_key) {
    // Alice generates her first ratchet key pair
    alice_state.crypto->DH_generate_ratchet_keypair(alice_state.DHs_priv, alice_state.DHs_pub);
    alice_state.DHr_pub = bob_ratchet_pub_key;

    CryptoPP::SecByteBlock dh_output = alice_state.crypto->DH_generate_shared_secret(alice_state.DHs_priv, alice_state.DHr_pub);

    // Use simulated KDF_RK
    std::tie(alice_state.RK, alice_state.CKs) = Simulate_KDF_RK(SK, dh_output, alice_state.crypto);

    alice_state.CKr.ZeroBytes(); // No receiving chain key yet
    alice_state.Ns = 0;
    alice_state.Nr = 0;
    alice_state.PN = 0;
    alice_state.MKskipped.clear();
    alice_state.initialized = true;
    std::cout << "[SimAliceInit] Alice DHs_pub: " << Util::byteblock_to_hex(alice_state.DHs_pub) << std::endl;
    std::cout << "[SimAliceInit] Alice DHr_pub: " << Util::byteblock_to_hex(alice_state.DHr_pub) << std::endl;
    std::cout << "[SimAliceInit] Alice RK: " << Util::byteblock_to_hex(alice_state.RK) << std::endl;
    std::cout << "[SimAliceInit] Alice CKs: " << Util::byteblock_to_hex(alice_state.CKs) << std::endl;
}

// Simulate Bob's initialization (mirrors Client::RatchetInitBob)
void SimulateRatchetInitBob(DRState& bob_state, const CryptoPP::SecByteBlock& SK, const CryptoPP::SecByteBlock& bob_ratchet_priv_key, const DHPublicKey& bob_ratchet_pub_key) {
    bob_state.DHs_priv = bob_ratchet_priv_key; // Bob's first ratchet key pair
    bob_state.DHs_pub = bob_ratchet_pub_key;
    bob_state.RK = SK; // Initial RK is the shared secret

    bob_state.DHr_pub.ZeroBytes(); // Bob doesn't know Alice's key yet
    bob_state.CKs.ZeroBytes();
    bob_state.CKr.ZeroBytes();
    bob_state.Ns = 0;
    bob_state.Nr = 0;
    bob_state.PN = 0;
    bob_state.MKskipped.clear();
    bob_state.initialized = true;
     std::cout << "[SimBobInit] Bob DHs_pub: " << Util::byteblock_to_hex(bob_state.DHs_pub) << std::endl;
     std::cout << "[SimBobInit] Bob RK: " << Util::byteblock_to_hex(bob_state.RK) << std::endl;
}


// Simulate the DH Ratchet step (mirrors Client::DoDH RatchetStep)
void SimulateDoDH RatchetStep(DRState& state, const DHPublicKey& received_dh_pub) {
    std::cout << "[SimDHRatchet] Starting for PK: " << Util::byteblock_to_hex(state.DHs_pub) << std::endl;
    std::cout << "[SimDHRatchet] Received PK: " << Util::byteblock_to_hex(received_dh_pub) << std::endl;

    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr_pub = received_dh_pub;
    std::cout << "[SimDHRatchet] Updated DHr_pub: " << Util::byteblock_to_hex(state.DHr_pub) << std::endl;

    // Step 1: Update RK and CKr
    CryptoPP::SecByteBlock dh_output1 = state.crypto->DH_generate_shared_secret(state.DHs_priv, state.DHr_pub);
    std::tie(state.RK, state.CKr) = Simulate_KDF_RK(state.RK, dh_output1, state.crypto);
    std::cout << "[SimDHRatchet] Step 1 -> New RK: " << Util::byteblock_to_hex(state.RK) << ", New CKr: " << Util::byteblock_to_hex(state.CKr) << std::endl;


    // Step 2: Generate new sending key pair and update RK and CKs
    state.crypto->DH_generate_ratchet_keypair(state.DHs_priv, state.DHs_pub);
     std::cout << "[SimDHRatchet] Generated new DHs pair. Pub: " << Util::byteblock_to_hex(state.DHs_pub) << std::endl;

    CryptoPP::SecByteBlock dh_output2 = state.crypto->DH_generate_shared_secret(state.DHs_priv, state.DHr_pub);
    std::tie(state.RK, state.CKs) = Simulate_KDF_RK(state.RK, dh_output2, state.crypto);
    std::cout << "[SimDHRatchet] Step 2 -> New RK: " << Util::byteblock_to_hex(state.RK) << ", New CKs: " << Util::byteblock_to_hex(state.CKs) << std::endl;


    state.MKskipped.clear(); // Clear skipped keys (simplified approach)
    std::cout << "[SimDHRatchet] Ratchet step finished." << std::endl;
}


// Simulate message encryption (mirrors Client::RatchetEncrypt)
std::optional<Message_Message> SimulateRatchetEncrypt(DRState& state, const std::string& plaintext) {
    if (!state.initialized || state.CKs.empty()) {
        std::cerr << "SimulateRatchetEncrypt Error: State not initialized or CKs empty." << std::endl;
        return std::nullopt;
    }
     std::cout << "[SimEncrypt] Encrypting Ns=" << state.Ns << ", PN=" << state.PN << ", PubKey=" << Util::byteblock_to_hex(state.DHs_pub) << std::endl;


    MessageKey MK;
    try {
        std::tie(state.CKs, MK) = Simulate_KDF_CK(state.CKs, state.crypto);
         std::cout << "[SimEncrypt] Advanced CKs: " << Util::byteblock_to_hex(state.CKs) << std::endl;
         std::cout << "[SimEncrypt] Derived MK: " << Util::byteblock_to_hex(MK) << std::endl;

    } catch (const std::exception& e) {
         std::cerr << "SimulateRatchetEncrypt Error during KDF_CK: " << e.what() << std::endl;
         return std::nullopt;
    }

    Message_Message msg;
    msg.header.dh_pub = state.DHs_pub;
    msg.header.pn = state.PN;
    msg.header.n = state.Ns;

    std::string associated_data = msg.get_serialized_header();
     std::cout << "[SimEncrypt] AD: " << Util::string_to_hex(associated_data) << std::endl;


    try {
        auto [iv, ciphertext] = state.crypto->AES_encrypt(MK, plaintext, associated_data);
        msg.iv = iv;
        msg.ciphertext = ciphertext;
        msg.mac = state.crypto->HMAC_generate(MK, iv, ciphertext, associated_data);
         std::cout << "[SimEncrypt] Encrypted. IV: " << Util::byteblock_to_hex(iv) << ", CT size: " << ciphertext.size() << ", MAC: " << Util::byteblock_to_hex(msg.mac) << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "SimulateRatchetEncrypt Error during AES/HMAC: " << e.what() << std::endl;
        return std::nullopt;
    }

    state.Ns++;
    return msg;
}

// Simulate message decryption (mirrors Client::RatchetDecrypt)
std::optional<std::string> SimulateRatchetDecrypt(DRState& state, const Message_Message& msg) {
     if (!state.initialized) {
        std::cerr << "SimulateRatchetDecrypt Error: State not initialized." << std::endl;
        return std::nullopt;
    }
     std::cout << "[SimDecrypt] Decrypting msg: DHr=" << Util::byteblock_to_hex(msg.header.dh_pub) << ", N=" << msg.header.n << ", PN=" << msg.header.pn << std::endl;
     std::cout << "[SimDecrypt] Current state: Nr=" << state.Nr << ", Current DHr_pub=" << Util::byteblock_to_hex(state.DHr_pub) << std::endl;


    std::string associated_data = msg.get_serialized_header();
     std::cout << "[SimDecrypt] AD: " << Util::string_to_hex(associated_data) << std::endl;


    // 1. Try skipped message keys
    SkippedMessageKeyId current_key_id{msg.header.dh_pub, msg.header.n};
    auto it = state.MKskipped.find(current_key_id);
    if (it != state.MKskipped.end()) {
        MessageKey MK = it->second;
        state.MKskipped.erase(it);
        std::cout << "[SimDecrypt] Found key in MKskipped for N=" << msg.header.n << std::endl;

        if (!state.crypto->HMAC_verify(MK, msg.iv, msg.ciphertext, msg.mac, associated_data)) {
             std::cerr << "SimulateRatchetDecrypt Error: MAC verification failed for skipped message." << std::endl;
            return std::nullopt;
        }
        std::cout << "[SimDecrypt] MAC verified for skipped message." << std::endl;

        auto plaintext = state.crypto->AES_decrypt(MK, msg.iv, msg.ciphertext, associated_data);
        if (plaintext) {
             std::cout << "[SimDecrypt] Decryption successful for skipped message." << std::endl;
            return plaintext;
        } else {
             std::cerr << "SimulateRatchetDecrypt Error: Decryption failed for skipped message." << std::endl;
            return std::nullopt;
        }
    }
     std::cout << "[SimDecrypt] Key not found in MKskipped." << std::endl;


    // 2. Check for DH Ratchet step
    // Need to handle the case where Bob receives first message (DHr_pub is empty)
    if (state.DHr_pub.empty() || msg.header.dh_pub != state.DHr_pub) {
         if (!state.DHr_pub.empty()) { // Don't ratchet if it was already empty
             std::cout << "[SimDecrypt] New remote DH public key received. Performing DH Ratchet step." << std::endl;
             SimulateDoDH RatchetStep(state, msg.header.dh_pub);
         } else {
             // This is Bob receiving the first message from Alice
             std::cout << "[SimDecrypt] First message from Alice received. Initializing CKr and performing DH ratchet." << std::endl;
             // Initialize Bob's receiving state based on Alice's first message
             state.DHr_pub = msg.header.dh_pub; // Set Alice's pub key
              std::cout << "[SimDecrypt] Set DHr_pub: " << Util::byteblock_to_hex(state.DHr_pub) << std::endl;
             // Perform the DH step to get CKr
             SimulateDoDH RatchetStep(state, msg.header.dh_pub); // This will also set CKs for Bob
         }
    }


    // 3. Advance receiving chain key CKr
     if (state.CKr.empty()) {
         std::cerr << "SimulateRatchetDecrypt Error: CKr is empty after potential ratchet step. Cannot proceed." << std::endl;
         return std::nullopt;
     }

     std::cout << "[SimDecrypt] Advancing CKr (Nr=" << state.Nr << ") to reach N=" << msg.header.n << std::endl;
    unsigned int skipped_count = 0;
    while (msg.header.n > state.Nr) {
        if (skipped_count >= Client::MAX_SKIPPED_KEYS) { // Use constant from Client
             std::cerr << "SimulateRatchetDecrypt Error: Exceeded MAX_SKIPPED_KEYS." << std::endl;
            return std::nullopt;
        }
        try {
            MessageKey skipped_MK;
            std::tie(state.CKr, skipped_MK) = Simulate_KDF_CK(state.CKr, state.crypto);

            SkippedMessageKeyId skipped_key_id{state.DHr_pub, state.Nr}; // Use current DHr_pub
            state.MKskipped[skipped_key_id] = skipped_MK;
             std::cout << "[SimDecrypt] Stored skipped MK for Nr=" << state.Nr << " under PK " << Util::byteblock_to_hex(state.DHr_pub) << ": " << Util::byteblock_to_hex(skipped_MK) << std::endl;

            state.Nr++;
            skipped_count++;
        } catch (const std::exception& e) {
             std::cerr << "SimulateRatchetDecrypt Error during KDF_CK while advancing CKr: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
     std::cout << "[SimDecrypt] Advanced CKr. Current Nr=" << state.Nr << std::endl;


    // 4. Decrypt the current message
    if (msg.header.n == state.Nr) {
         std::cout << "[SimDecrypt] Message N matches current Nr. Deriving final MK." << std::endl;
        MessageKey MK;
        try {
            std::tie(state.CKr, MK) = Simulate_KDF_CK(state.CKr, state.crypto);
            state.Nr++;
            std::cout << "[SimDecrypt] Advanced CKr: " << Util::byteblock_to_hex(state.CKr) << std::endl;
            std::cout << "[SimDecrypt] Derived MK for N=" << msg.header.n << ": " << Util::byteblock_to_hex(MK) << std::endl;


            if (!state.crypto->HMAC_verify(MK, msg.iv, msg.ciphertext, msg.mac, associated_data)) {
                 std::cerr << "SimulateRatchetDecrypt Error: MAC verification failed for message N=" << msg.header.n << std::endl;
                 state.Nr--; // Roll back Nr?
                return std::nullopt;
            }
             std::cout << "[SimDecrypt] MAC verified successfully for message N=" << msg.header.n << std::endl;

            auto plaintext = state.crypto->AES_decrypt(MK, msg.iv, msg.ciphertext, associated_data);
            if (plaintext) {
                 std::cout << "[SimDecrypt] Decryption successful for message N=" << msg.header.n << std::endl;
                return plaintext;
            } else {
                 std::cerr << "SimulateRatchetDecrypt Error: Decryption failed for message N=" << msg.header.n << std::endl;
                 state.Nr--; // Roll back Nr?
                return std::nullopt;
            }
        } catch (const std::exception& e) {
             std::cerr << "SimulateRatchetDecrypt Error during final KDF_CK/Decrypt/Verify: " << e.what() << std::endl;
            return std::nullopt;
        }
    } else {
         std::cout << "[SimDecrypt] Received old message N=" << msg.header.n << " but Nr=" << state.Nr << ". Discarding." << std::endl;
        return std::nullopt;
    }
}


// --- Test Cases ---

TEST_CASE("Double Ratchet Simulation") {
    // Shared crypto driver instance
    auto crypto = std::make_shared<CryptoDriver>();
    crypto->DH_initialize(); // Initialize DH parameters

    // Create state for Alice and Bob
    DRState alice_state(crypto);
    DRState bob_state(crypto);

    // Simulate Initial Key Exchange (generate a dummy shared secret SK)
    // In reality, this comes from X3DH or your simplified handshake
    CryptoPP::SecByteBlock bob_initial_priv;
    DHPublicKey bob_initial_pub;
    crypto->DH_generate_ratchet_keypair(bob_initial_priv, bob_initial_pub);
     std::cout << "Bob Initial Pub Key: " << Util::byteblock_to_hex(bob_initial_pub) << std::endl;

    // Dummy SK (replace with actual shared secret from your handshake if possible)
    CryptoPP::SecByteBlock SK(32); // 32 bytes for SHA256-based KDFs
    CryptoPP::OS_GenerateRandomBlock(false, SK.BytePtr(), SK.size());
     std::cout << "Generated Dummy SK: " << Util::byteblock_to_hex(SK) << std::endl;


    // Initialize Alice and Bob
    SimulateRatchetInitAlice(alice_state, SK, bob_initial_pub);
    SimulateRatchetInitBob(bob_state, SK, bob_initial_priv, bob_initial_pub);

    REQUIRE(alice_state.initialized);
    REQUIRE(bob_state.initialized);
    REQUIRE(alice_state.DHr_pub == bob_state.DHs_pub); // Alice knows Bob's key

    SUBCASE("Basic Send/Receive A -> B") {
        std::string msg_a1_text = "Hello Bob!";
        auto msg_a1 = SimulateRatchetEncrypt(alice_state, msg_a1_text);
        REQUIRE(msg_a1.has_value());
        CHECK(alice_state.Ns == 1);

        // Bob receives
        auto decrypted_b1 = SimulateRatchetDecrypt(bob_state, *msg_a1);
        REQUIRE(decrypted_b1.has_value());
        CHECK(*decrypted_b1 == msg_a1_text);
        CHECK(bob_state.Nr == 1);
        CHECK(bob_state.DHr_pub == alice_state.DHs_pub); // Bob should have learned Alice's key
        CHECK(!bob_state.CKr.empty()); // Bob's CKr should be initialized now
        CHECK(!bob_state.CKs.empty()); // Bob's CKs should be initialized now (from DH ratchet)
    }

    SUBCASE("Basic Send/Receive B -> A") {
        // Requires A->B first for Bob to initialize CKr/CKs
        auto msg_a1 = SimulateRatchetEncrypt(alice_state, "Hi Bob");
        REQUIRE(msg_a1.has_value());
        auto decrypted_b1 = SimulateRatchetDecrypt(bob_state, *msg_a1);
        REQUIRE(decrypted_b1.has_value());

        // Now Bob sends to Alice
        std::string msg_b1_text = "Hello Alice!";
        auto msg_b1 = SimulateRatchetEncrypt(bob_state, msg_b1_text);
        REQUIRE(msg_b1.has_value());
        CHECK(bob_state.Ns == 1);

        // Alice receives
        auto decrypted_a1 = SimulateRatchetDecrypt(alice_state, *msg_b1);
        REQUIRE(decrypted_a1.has_value());
        CHECK(*decrypted_a1 == msg_b1_text);
        CHECK(alice_state.Nr == 1);
        CHECK(alice_state.DHr_pub == bob_state.DHs_pub); // Alice should see Bob's key hasn't changed yet
    }

     SUBCASE("Multiple Messages A -> B") {
        std::string msg1_text = "Message 1";
        std::string msg2_text = "Message the second";
        std::string msg3_text = "Third time's the charm";

        auto msg1 = SimulateRatchetEncrypt(alice_state, msg1_text);
        REQUIRE(msg1.has_value());
        CHECK(alice_state.Ns == 1);
        auto msg2 = SimulateRatchetEncrypt(alice_state, msg2_text);
        REQUIRE(msg2.has_value());
        CHECK(alice_state.Ns == 2);
         auto msg3 = SimulateRatchetEncrypt(alice_state, msg3_text);
        REQUIRE(msg3.has_value());
        CHECK(alice_state.Ns == 3);


        // Bob receives in order
        auto dec1 = SimulateRatchetDecrypt(bob_state, *msg1);
        REQUIRE(dec1.has_value());
        CHECK(*dec1 == msg1_text);
        CHECK(bob_state.Nr == 1);

        auto dec2 = SimulateRatchetDecrypt(bob_state, *msg2);
        REQUIRE(dec2.has_value());
        CHECK(*dec2 == msg2_text);
        CHECK(bob_state.Nr == 2);

         auto dec3 = SimulateRatchetDecrypt(bob_state, *msg3);
        REQUIRE(dec3.has_value());
        CHECK(*dec3 == msg3_text);
        CHECK(bob_state.Nr == 3);
     }

      SUBCASE("Alternating Messages A->B, B->A") {
        std::string msg_a1_text = "Ping";
        std::string msg_b1_text = "Pong";
        std::string msg_a2_text = "Ping again";

        // A -> B
        auto msg_a1 = SimulateRatchetEncrypt(alice_state, msg_a1_text);
        REQUIRE(msg_a1.has_value());
        auto dec_b1 = SimulateRatchetDecrypt(bob_state, *msg_a1);
        REQUIRE(dec_b1.has_value());
        CHECK(*dec_b1 == msg_a1_text);

        // B -> A
        auto msg_b1 = SimulateRatchetEncrypt(bob_state, msg_b1_text);
        REQUIRE(msg_b1.has_value());
        auto dec_a1 = SimulateRatchetDecrypt(alice_state, *msg_b1);
        REQUIRE(dec_a1.has_value());
        CHECK(*dec_a1 == msg_b1_text);

         // A -> B again
        auto msg_a2 = SimulateRatchetEncrypt(alice_state, msg_a2_text);
        REQUIRE(msg_a2.has_value());
        auto dec_b2 = SimulateRatchetDecrypt(bob_state, *msg_a2);
        REQUIRE(dec_b2.has_value());
        CHECK(*dec_b2 == msg_a2_text);

        CHECK(alice_state.Ns == 2);
        CHECK(alice_state.Nr == 1);
        CHECK(bob_state.Ns == 1);
        CHECK(bob_state.Nr == 2);
      }


    SUBCASE("DH Ratchet Step (Bob receives new key from Alice)") {
        std::string msg_a1_text = "Alice Message 1 (Before Ratchet)";
        std::string msg_a2_text = "Alice Message 2 (Causes Ratchet)";
        std::string msg_b1_text = "Bob Message 1 (After Ratchet)";

        // A -> B (Normal)
        auto msg_a1 = SimulateRatchetEncrypt(alice_state, msg_a1_text);
        REQUIRE(msg_a1.has_value());
        auto dec_b1 = SimulateRatchetDecrypt(bob_state, *msg_a1);
        REQUIRE(dec_b1.has_value());
        CHECK(*dec_b1 == msg_a1_text);
        DHPublicKey alice_pk_before_ratchet = alice_state.DHs_pub; // Store Alice's PK

        // Alice sends another message, triggering a DH ratchet step *on her side* first
        // (In simulation, we trigger it manually before sending)
        DHPublicKey alice_old_pk = alice_state.DHs_pub;
        SimulateDoDH RatchetStep(alice_state, bob_state.DHs_pub); // Alice ratchets based on Bob's current key
        REQUIRE(alice_state.DHs_pub != alice_old_pk); // Alice should have a new key pair
        CHECK(alice_state.Ns == 0); // Ns resets after ratchet
        CHECK(alice_state.PN == 1); // PN should be 1 (msg_a1 was sent)

        // Alice sends message with her *new* public key
        auto msg_a2 = SimulateRatchetEncrypt(alice_state, msg_a2_text);
        REQUIRE(msg_a2.has_value());
        CHECK(msg_a2->header.dh_pub == alice_state.DHs_pub); // Header has new PK
        CHECK(msg_a2->header.n == 0); // N is 0 for first message in new chain
        CHECK(msg_a2->header.pn == 1); // PN is 1

        // Bob receives msg_a2, which triggers his DH ratchet step
        DHPublicKey bob_pk_before_ratchet = bob_state.DHs_pub;
        auto dec_b2 = SimulateRatchetDecrypt(bob_state, *msg_a2);
        REQUIRE(dec_b2.has_value());
        CHECK(*dec_b2 == msg_a2_text);
        CHECK(bob_state.DHr_pub == alice_state.DHs_pub); // Bob learns Alice's new key
        CHECK(bob_state.DHs_pub != bob_pk_before_ratchet); // Bob also generated a new key pair
        CHECK(bob_state.Nr == 1); // Nr increments after successful decrypt
        CHECK(bob_state.Ns == 0); // Bob's Ns reset
        CHECK(bob_state.PN > 0); // Bob's PN should be non-zero if he sent messages before


        // Bob sends a message back using his new ratchet state
        auto msg_b1 = SimulateRatchetEncrypt(bob_state, msg_b1_text);
        REQUIRE(msg_b1.has_value());
        CHECK(msg_b1->header.dh_pub == bob_state.DHs_pub); // Bob uses his new PK
        CHECK(msg_b1->header.n == 0);

        // Alice receives Bob's message (this should NOT trigger a ratchet for Alice)
        auto dec_a1 = SimulateRatchetDecrypt(alice_state, *msg_b1);
        REQUIRE(dec_a1.has_value());
        CHECK(*dec_a1 == msg_b1_text);
        CHECK(alice_state.DHr_pub == bob_state.DHs_pub); // Alice learns Bob's new key
        CHECK(alice_state.Nr == 1); // Alice's Nr increments
    }

     SUBCASE("Out-of-Order Messages (Same Epoch)") {
        std::string msg1_text = "First";
        std::string msg2_text = "Second";
        std::string msg3_text = "Third";

        auto msg1 = SimulateRatchetEncrypt(alice_state, msg1_text); REQUIRE(msg1.has_value());
        auto msg2 = SimulateRatchetEncrypt(alice_state, msg2_text); REQUIRE(msg2.has_value());
        auto msg3 = SimulateRatchetEncrypt(alice_state, msg3_text); REQUIRE(msg3.has_value());

        CHECK(msg1->header.n == 0);
        CHECK(msg2->header.n == 1);
        CHECK(msg3->header.n == 2);


        // Bob receives 3, then 1, then 2
        auto dec3 = SimulateRatchetDecrypt(bob_state, *msg3); // Should store keys for 0, 1, 2
        REQUIRE(dec3.has_value());
        CHECK(*dec3 == msg3_text);
        CHECK(bob_state.Nr == 3); // Nr advances past received message
        CHECK(bob_state.MKskipped.size() == 2); // Keys for 0 and 1 should be stored

        auto dec1 = SimulateRatchetDecrypt(bob_state, *msg1); // Should use stored key for 0
        REQUIRE(dec1.has_value());
        CHECK(*dec1 == msg1_text);
        CHECK(bob_state.Nr == 3); // Nr doesn't change
        CHECK(bob_state.MKskipped.size() == 1); // Key for 0 removed

        auto dec2 = SimulateRatchetDecrypt(bob_state, *msg2); // Should use stored key for 1
        REQUIRE(dec2.has_value());
        CHECK(*dec2 == msg2_text);
        CHECK(bob_state.Nr == 3); // Nr doesn't change
        CHECK(bob_state.MKskipped.empty()); // All skipped keys used
     }

      SUBCASE("Lost Message") {
        std::string msg1_text = "Uno";
        std::string msg2_text = "Dos (Lost)";
        std::string msg3_text = "Tres";

        auto msg1 = SimulateRatchetEncrypt(alice_state, msg1_text); REQUIRE(msg1.has_value());
        auto msg2 = SimulateRatchetEncrypt(alice_state, msg2_text); REQUIRE(msg2.has_value()); // Simulate sending msg2
        auto msg3 = SimulateRatchetEncrypt(alice_state, msg3_text); REQUIRE(msg3.has_value());

        // Bob receives 1, then 3 (msg 2 is lost)
        auto dec1 = SimulateRatchetDecrypt(bob_state, *msg1);
        REQUIRE(dec1.has_value());
        CHECK(*dec1 == msg1_text);
        CHECK(bob_state.Nr == 1);
        CHECK(bob_state.MKskipped.empty());

        auto dec3 = SimulateRatchetDecrypt(bob_state, *msg3); // Should store key for 2
        REQUIRE(dec3.has_value());
        CHECK(*dec3 == msg3_text);
        CHECK(bob_state.Nr == 3); // Nr advances past 3
        CHECK(bob_state.MKskipped.size() == 1); // Key for 2 stored

        // Check if key for N=2 exists
        SkippedMessageKeyId lost_key_id{bob_state.DHr_pub, 1}; // Key for N=1 was used, key for N=2 should be stored
        CHECK(bob_state.MKskipped.count(lost_key_id) == 1);

        // If msg2 arrived later, it could be decrypted using the stored key (not tested here)
      }

      // Add more tests:
      // - Out-of-order across DH Ratchet step (very complex)
      // - Max skipped keys limit hit
      // - Decryption failure (bad MAC, wrong key) - requires modifying message manually
}
