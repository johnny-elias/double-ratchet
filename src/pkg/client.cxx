#include "../../include/pkg/client.hpp"
#include "../../include-shared/util.hpp" // For print_bytes etc.
#include "../../include-shared/logger.hpp"

#include <chrono> // For sleep_for
#include <future> // For std::async, std::future
#include <stdexcept>
#include <cryptopp/osrng.h> // For AutoSeededRandomPool

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param network_driver NetworkDriver to handle network operations i.e. sending and receiving msgs 
 * @param crypto_driver CryptoDriver to handle crypto related functionality
 * @param cli_driver CryptoDriver to handle crypto related functionality
 */
Client::Client(std::shared_ptr<CryptoDriver> crypto_driver,
               std::shared_ptr<NetworkDriver> network_driver) {
    this->cli_driver = std::make_shared<CLIDriver>();
    this->crypto_driver = crypto_driver;
    this->network_driver = network_driver;

    initLogger(logging::trivial::severity_level::trace);
    src::severity_logger<logging::trivial::severity_level> lg;
    this->lg = lg;
    CUSTOM_LOG(lg, trace) << "Client initialized.";
}

Client::~Client() {
  stop(); // Ensure stop is called to join threads
  // Queues and drivers will be cleaned up by unique_ptr automatically
}

// Simplified initial key setup - This needs careful review based on your exact handshake.
// Assumes a simple DH exchange happens before DR starts.
void Client:: prepare_keys(bool is_initiator, std::string& remote_addr) {
    CUSTOM_LOG(lg, trace) << "Initializing CryptoDriver and generating initial DH keys...";
    crypto_driver->DH_initialize(); // Generate initial identity key pair
    DHPublicKey my_initial_pub_key = crypto_driver->get_dh_public_key();
    // CUSTOM_LOG(lg, trace) << "My initial public key generated: " + byteblock_to_string(my_initial_pub_key);


    if (is_initiator) {
        CUSTOM_LOG(lg, trace) << "Running as initiator. Waiting for connection and remote key...";

        // Initiator (Alice) waits for Bob's initial key exchange message
        // This loop assumes the first message received *must* be a KeyExchange
        // In a real scenario, might need more robust handshake logic.
        while (!initial_key_exchanged && running) {
             std::string buf;
             auto data = this->network_driver->read();
             if (data.size() > 0) {
                 try {
                    // Assume type byte prefix is used
                    if (data.empty()) continue;
                    MessageType type = static_cast<MessageType>(data[0]);

                    // build msg_data from bytes 1..end
                    std::string msg_data(data.begin() + 1, data.end());

                    if (type == MessageType::KEY_EXCHANGE) {
                        Message_KeyExchange key_msg;
                        key_msg.deserialize(msg_data);
                        CUSTOM_LOG(lg, trace) << "Received initial key exchange message from responder.";
                        HandleKeyExchange(key_msg); // Process Bob's initial key

                        // Send back initiator's own key exchange
                        Message_KeyExchange my_key_msg;
                        my_key_msg.pub_val = my_initial_pub_key;
                        my_key_msg.iv.New(CryptoPP::AES::BLOCKSIZE);
                        crypto_driver->prng.GenerateBlock(my_key_msg.iv, my_key_msg.iv.size());

                        std::vector<unsigned char> serialized_msg = str2chvec(prefix_message_type(my_key_msg));
                        network_driver->send(serialized_msg);
                        CUSTOM_LOG(lg, trace) << "Initiator sent KEY_EXCHANGE reply to responder.";
                    } else {
                        CUSTOM_LOG(lg, trace) << "Warning: Expected KeyExchange message first, received other type. Ignoring.";
                    }

                 } catch (const std::exception& e) {
                    CUSTOM_LOG(lg, trace) << "Error processing initial received message: " + std::string(e.what());
                 }
             }
             std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Prevent busy-waiting
        }
        if (!initial_key_exchanged) {
             throw std::runtime_error("Failed to receive initial key exchange from responder.");
        }


    } else {
        CUSTOM_LOG(lg, trace) << "Running as responder. Starting listener and sending initial key...";

        // Responder (Bob) sends his initial public key immediately upon connection
        // This assumes the initiator connects promptly.
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait for connection
        if (!running) return; // Exit if stopped during wait

        Message_KeyExchange key_msg;
        key_msg.pub_val = my_initial_pub_key;
        // IV might not be strictly necessary for unencrypted initial key exchange, but included for structure
        CryptoPP::AutoSeededRandomPool prng;
        key_msg.iv.New(CryptoPP::AES::BLOCKSIZE);
        prng.GenerateBlock(key_msg.iv, key_msg.iv.size());

        std::vector<unsigned char> serialized_msg = str2chvec(prefix_message_type(key_msg));
        network_driver->send(serialized_msg);
        CUSTOM_LOG(lg, trace) << "Sent initial key exchange message to initiator.";
        // Bob now waits for Alice's first DR message to complete initialization
    }
     CUSTOM_LOG(lg, trace) << "Initial key preparation/exchange phase completed.";
}


// Handles the simplified initial key exchange message
// Calculates the initial shared secret needed to start DR
void Client::HandleKeyExchange(const Message_KeyExchange &msg) {
    std::lock_guard<std::mutex> lock(mtx); // Protect access to shared state

    if (initial_key_exchanged) {
        CUSTOM_LOG(lg, trace) << "Warning: Received duplicate KeyExchange message. Ignoring.";
        return;
    }

    CUSTOM_LOG(lg, trace) << "Handling KeyExchange message...";
    // Store the received public key (this is the OTHER party's initial identity/ratchet key)
    DHPublicKey initial_remote_pub_key = msg.pub_val; // In simplified scheme, this is both identity and first ratchet key
    // CUSTOM_LOG(lg, trace) << "Received initial remote public key: " + byteblock_to_string(initial_remote_pub_key);

    // Generate the initial shared secret using our *ratchet* private key and their public key
    // In this simplified setup, the initial DH key pair IS the first ratchet key pair
    CryptoPP::SecByteBlock our_initial_priv_key; 
    our_initial_priv_key = crypto_driver->get_dh_private_key(); 

    // Assuming we have the correct initial private key 'our_initial_priv_key'
    initial_shared_secret = crypto_driver->DH_generate_shared_secret(our_initial_priv_key, initial_remote_pub_key);

    // CUSTOM_LOG(lg, trace) << "Calculated initial shared secret: " + byteblock_to_string(initial_shared_secret);


    // --- Initialize Double Ratchet State ---
    // This logic depends on who initiates DR. Let's assume the 'is_initiator' flag determines Alice/Bob role FOR DR.
    // In the simplified setup, the client role (initiator/responder) aligns with DR Alice/Bob.

    if (is_initiator_) { // Client is Initiator -> Acts as DR Alice
        CUSTOM_LOG(lg, trace) << "Initializing DR as Alice...";
        // Alice needs Bob's initial public key (which we just received)
        // Alice generates her first ratchet key pair NOW.
        crypto_driver->DH_generate_ratchet_keypair(DHs_priv, DHs_pub);
        RatchetInitAlice(initial_shared_secret, initial_remote_pub_key, initial_remote_pub_key); // Bob's first key is used twice here
    } else { // Client is Responder -> Acts as DR Bob
        CUSTOM_LOG(lg, trace) << "Initializing DR as Bob...";
        // Bob uses his initial key pair as the first ratchet key pair.
        // FIXME: Bob needs his initial private/public keys here. Use the temporary ones again...
         DHs_priv = our_initial_priv_key;
         DHs_pub = initial_remote_pub_key;
         RatchetInitBob(initial_shared_secret, DHs_priv, DHs_pub);
         // Bob sets DHr_pub when he receives Alice's first DR message.
    }


    initial_key_exchanged = true;
    dr_initialized = true; // DR is now ready
     CUSTOM_LOG(lg, trace) << "Double Ratchet state initialized.";
}


// --- Double Ratchet Initialization ---

// Alice initializes based on initial SK and Bob's public keys.
// In X3DH, bob_identity_pub_key and bob_ratchet_pub_key might differ. Simplified here.
void Client::RatchetInitAlice(const CryptoPP::SecByteBlock& SK, const DHPublicKey& bob_identity_pub_key, const DHPublicKey& bob_ratchet_pub_key) {
    // DHs (sending key pair) should have been generated just before calling this
    this->DHr_pub = bob_ratchet_pub_key; // Bob's initial ratchet key

    // First DH ratchet step derives initial RK and CKs
    CryptoPP::SecByteBlock dh_output = crypto_driver->DH_generate_shared_secret(DHs_priv, DHr_pub);
    std::tie(this->RK, this->CKs) = crypto_driver->KDF_RK(SK, dh_output);

    this->CKr = integer_to_byteblock(0); // No receiving chain key yet
    this->Ns = 0;
    this->Nr = 0;
    this->PN = 0;
    this->MKskipped.clear();
     CUSTOM_LOG(lg, trace) << "RatchetInitAlice completed. RK and CKs derived.";
    //  CUSTOM_LOG(lg, trace) << "RK: " + byteblock_to_string(RK);
    //  CUSTOM_LOG(lg, trace) << "CKs: " + byteblock_to_string(CKs);
    //  CUSTOM_LOG(lg, trace) << "DHs_pub: " + byteblock_to_string(DHs_pub);
    //  CUSTOM_LOG(lg, trace) << "DHr_pub: " + byteblock_to_string(DHr_pub);

}

// Bob initializes based on initial SK and his own first ratchet key pair.
void Client::RatchetInitBob(const CryptoPP::SecByteBlock& SK, const CryptoPP::SecByteBlock& bob_ratchet_priv_key, const DHPublicKey& bob_ratchet_pub_key) {
    this->DHs_priv = bob_ratchet_priv_key; // Bob's first ratchet key pair
    this->DHs_pub = bob_ratchet_pub_key;
    this->RK = SK; // Initial RK is the shared secret from key exchange

    this->DHr_pub = integer_to_byteblock(0); // Bob doesn't know Alice's key yet
    this->CKs = integer_to_byteblock(0);    // No sending chain key yet
    this->CKr = integer_to_byteblock(0);    // No receiving chain key yet (derived on first message)
    this->Ns = 0;
    this->Nr = 0;
    this->PN = 0;
    this->MKskipped.clear();
    CUSTOM_LOG(lg, trace) << "RatchetInitBob completed. RK set.";
    // CUSTOM_LOG(lg, trace) << "RK: " + byteblock_to_string(RK);
    // CUSTOM_LOG(lg, trace) << "DHs_pub: " + byteblock_to_string(DHs_pub);
}


// --- Double Ratchet Core Logic ---

// Encrypts plaintext using the sending ratchet
Message_Message Client::RatchetEncrypt(const std::string& plaintext) {
    std::lock_guard<std::mutex> lock(mtx); // Lock DR state for writing

    if (!dr_initialized || CKs.empty()) {
        CUSTOM_LOG(lg, trace) << "Error: RatchetEncrypt called before DR initialization or CKs is ready.";
        return {};
    }
    CUSTOM_LOG(lg, trace) << "RatchetEncrypt: Ns=" + std::to_string(Ns) + ", PN=" + std::to_string(PN);


    MessageKey MK;
    try {
        // Advance sending chain key and get message key
        std::tie(CKs, MK) = crypto_driver->KDF_CK(CKs);
        //  CUSTOM_LOG(lg, trace) << "Advanced CKs: " + byteblock_to_string(CKs);
        //  CUSTOM_LOG(lg, trace) << "Derived MK for Ns=" + std::to_string(Ns) + ": " + byteblock_to_string(MK);

    } catch (const std::exception& e) {
         CUSTOM_LOG(lg, trace) << "Error during KDF_CK for sending: " + std::string(e.what());
         return {};
    }

    Message_Message msg;
    msg.header.dh_pub = DHs_pub; // Current sending ratchet public key
    msg.header.pn = PN;
    msg.header.n = Ns;

    std::string associated_data = msg.get_serialized_header();
    // CUSTOM_LOG(lg, trace) << "Encrypting with AD: " + associated_data;


    try {
         // Encrypt plaintext
        auto [iv, ciphertext] = crypto_driver->AES_encrypt(MK, plaintext, associated_data);
        msg.iv = iv;
        msg.ciphertext = ciphertext;

        // Generate MAC (must include AD)
        msg.mac = crypto_driver->HMAC_generate(MK, iv, ciphertext, associated_data);

        //  CUSTOM_LOG(lg, trace) << "Encryption successful. IV: " + byteblock_to_string(iv) + ", CT size: " + std::to_string(ciphertext.size()) + ", MAC: " + byteblock_to_string(msg.mac);

    } catch (const std::exception& e) {
        CUSTOM_LOG(lg, trace) << "Error during encryption/MAC generation: " + std::string(e.what());
        // Clean up potentially derived keys? CKs was already updated.
        return {};
    }


    Ns++; // Increment message number for next message
    return msg;
}


// Decrypts a received message
std::string Client::RatchetDecrypt(const Message_Message& msg) {
    std::lock_guard<std::mutex> lock(mtx); // Lock DR state for reading/writing

    if (!dr_initialized) {
        CUSTOM_LOG(lg, trace) << "Error: RatchetDecrypt called before DR initialization.";
        return "";
    }

    // CUSTOM_LOG(lg, trace) << "RatchetDecrypt received msg: DHr=" + byteblock_to_string(msg.header.dh_pub) + ", N=" + std::to_string(msg.header.n) + ", PN=" + std::to_string(msg.header.pn);


    // Get Associated Data from the received message header
    std::string associated_data = msg.get_serialized_header();
     CUSTOM_LOG(lg, trace) << "Decrypting with AD: " + associated_data;


    // 1. Try skipped message keys first
    SkippedMessageKeyId current_key_id{msg.header.dh_pub, msg.header.n};
    auto it = MKskipped.find(current_key_id);
    if (it != MKskipped.end()) {
        MessageKey MK = it->second;
        MKskipped.erase(it); // Remove key once used
        CUSTOM_LOG(lg, trace) << "Found message key in MKskipped for N=" + std::to_string(msg.header.n);

        // Verify MAC first
        if (!crypto_driver->HMAC_verify(MK, msg.iv, msg.ciphertext, msg.mac, associated_data)) {
            CUSTOM_LOG(lg, trace) << "Error: MAC verification failed for skipped message.";
            return "";
        }
         CUSTOM_LOG(lg, trace) << "MAC verified successfully for skipped message.";


        // Decrypt
        std::string plaintext = crypto_driver->AES_decrypt(MK, msg.iv, msg.ciphertext, associated_data);
        CUSTOM_LOG(lg, trace) << "Decryption successful for skipped message.";
        return plaintext;
    }
     CUSTOM_LOG(lg, trace) << "Message key not found in MKskipped.";


    // 2. Check for DH Ratchet step (new remote public key)
    if (msg.header.dh_pub != DHr_pub) {
        CUSTOM_LOG(lg, trace) << "New remote DH public key received. Performing DH Ratchet step.";
        // CUSTOM_LOG(lg, trace) << "Old DHr_pub: " + byteblock_to_string(DHr_pub);
        // CUSTOM_LOG(lg, trace) << "New DHr_pub: " + byteblock_to_string(msg.header.dh_pub);

        // Before performing the step, try to process skipped messages belonging to the *old* CKr chain
        // This part is tricky - how do we know which chain the skipped messages belong to?
        // The map key includes the public key, so TrySkipped only processes relevant ones.
        // TrySkippedMessageKeys(DHr_pub, Nr, msg); // Pass the *original* msg for context if needed, though not strictly necessary here

        // Perform the DH ratchet update
        try {
             DoDHRatchetStep(msg.header.dh_pub);
        } catch (const std::exception& e) {
             CUSTOM_LOG(lg, trace) << "Error during DH Ratchet step: " + std::string(e.what());
             return "";
        }
         CUSTOM_LOG(lg, trace) << "DH Ratchet step completed.";

         // Important: After a DH ratchet, Nr is reset to 0.
         // We expect the message N to be 0 for the first message on the new chain.
         if (msg.header.n != 0) {
             CUSTOM_LOG(lg, trace) << "Warning: First message after DH ratchet step has N != 0. This might indicate message loss during ratchet.";
             // Proceed to advance CKr below, potentially storing skipped keys.
         }

    }

    // 3. Advance receiving chain key CKr to find the message key
    // Check if CKr is valid (it might be empty if Bob just initialized)
     if (CKr.empty()) {
        CUSTOM_LOG(lg, trace) << "Error: Receiving chain key CKr is not initialized. Cannot process message.";
         // This can happen if Bob receives a message before Alice sends the first one after init.
         // Or if DH Ratchet step failed previously.
         return "";
     }


    CUSTOM_LOG(lg, trace) << "Advancing CKr (currently Nr=" + std::to_string(Nr) + ") to reach N=" + std::to_string(msg.header.n);
    unsigned int skipped_count = 0;
    while (msg.header.n > Nr) {
        if (skipped_count >= MAX_SKIPPED_KEYS) {
            CUSTOM_LOG(lg, trace) << "Error: Exceeded MAX_SKIPPED_KEYS limit while advancing CKr.";
            return ""; // Or handle differently (e.g., request re-sync)
        }

        try {
            MessageKey skipped_MK;
            std::tie(CKr, skipped_MK) = crypto_driver->KDF_CK(CKr);

            // Store the skipped key
            SkippedMessageKeyId skipped_key_id{DHr_pub, Nr}; // Use current DHr_pub for this chain
            MKskipped[skipped_key_id] = skipped_MK;
            // CUSTOM_LOG(lg, trace) << "Derived and stored skipped MK for Nr=" + std::to_string(Nr) + " under PK " + byteblock_to_string(DHr_pub) + ": " + byteblock_to_string(skipped_MK);


            Nr++;
            skipped_count++;
        } catch (const std::exception& e) {
            CUSTOM_LOG(lg, trace) << "Error during KDF_CK while advancing CKr: " + std::string(e.what());
            return "";
        }
    }
     CUSTOM_LOG(lg, trace) << "Advanced CKr. Current Nr=" + std::to_string(Nr);

    // 4. Decrypt the current message
    if (msg.header.n == Nr) {
        CUSTOM_LOG(lg, trace) << "Message N matches current Nr. Deriving final MK.";
        MessageKey MK;
        try {
            std::tie(CKr, MK) = crypto_driver->KDF_CK(CKr); // Advance one last time for this message
            Nr++; // Increment Nr *after* successful processing of message N

            // CUSTOM_LOG(lg, trace) << "Advanced CKr: " + byteblock_to_string(CKr);
            // CUSTOM_LOG(lg, trace) << "Derived MK for N=" + std::to_string(msg.header.n) + ": " + byteblock_to_string(MK);


            // Verify MAC first!
            if (!crypto_driver->HMAC_verify(MK, msg.iv, msg.ciphertext, msg.mac, associated_data)) {
                CUSTOM_LOG(lg, trace) << "Error: MAC verification failed for message N=" + std::to_string(msg.header.n);
                 Nr--; // Roll back Nr increment if MAC fails? Or consider state compromised? Critical decision.
                return "";
            }
             CUSTOM_LOG(lg, trace) << "MAC verified successfully for message N=" + std::to_string(msg.header.n);


            // Decrypt
            auto plaintext = crypto_driver->AES_decrypt(MK, msg.iv, msg.ciphertext, associated_data);
            CUSTOM_LOG(lg, trace) << "Decryption successful for message N=" + std::to_string(msg.header.n);
            return plaintext;
        } catch (const std::exception& e) {
            CUSTOM_LOG(lg, trace) << "Error during final KDF_CK or Decrypt/Verify for N=" + std::to_string(msg.header.n) + ": " + std::string(e.what());
            return "";
        }
    } else {
        // msg.header.n < Nr
        CUSTOM_LOG(lg, trace) << "Received out-of-order (old) message N=" + std::to_string(msg.header.n) + " but Nr is already " + std::to_string(Nr) + ". Discarding.";
        // This message was already processed or skipped past.
        return "";
    }
}

// Performs a DH Ratchet step
void Client::DoDHRatchetStep(const DHPublicKey& received_dh_pub) {
    // Assumes lock is already held by caller (RatchetDecrypt)

    CUSTOM_LOG(lg, trace) << "--- Performing DH Ratchet Step ---";
    PN = Ns;   // Store number of messages sent in the outgoing chain being replaced
    Ns = 0;    // Reset sending message number
    Nr = 0;    // Reset receiving message number

    DHr_pub = received_dh_pub; // Update remote public key
    // CUSTOM_LOG(lg, trace) << "Updated DHr_pub: " + byteblock_to_string(DHr_pub);


    // Calculate first DH output using OLD sending key pair and NEW remote key
    CryptoPP::SecByteBlock dh_output1 = crypto_driver->DH_generate_shared_secret(DHs_priv, DHr_pub);
    std::tie(RK, CKr) = crypto_driver->KDF_RK(RK, dh_output1); // Update RK, derive NEW receiving chain key
    // CUSTOM_LOG(lg, trace) << "Step 1 KDF_RK -> New RK: " + byteblock_to_string(RK) + ", New CKr: " + byteblock_to_string(CKr);


    // Generate NEW sending key pair
    crypto_driver->DH_generate_ratchet_keypair(DHs_priv, DHs_pub);
    // CUSTOM_LOG(lg, trace) << "Generated new DHs pair. Pub: " + byteblock_to_string(DHs_pub);

    // Calculate second DH output using NEW sending key pair and NEW remote key
    CryptoPP::SecByteBlock dh_output2 = crypto_driver->DH_generate_shared_secret(DHs_priv, DHr_pub);
    std::tie(RK, CKs) = crypto_driver->KDF_RK(RK, dh_output2); // Update RK again, derive NEW sending chain key
    // CUSTOM_LOG(lg, trace) << "Step 2 KDF_RK -> New RK: " + byteblock_to_string(RK) + ", New CKs: " + byteblock_to_string(CKs);


    // Clear skipped message keys (associated with old chains)
    // Note: Signal spec sometimes keeps skipped keys associated with the *previous* DHr_pub.
    // For simplicity here, we clear all. Review this if implementing precisely per spec.
    MKskipped.clear();
    CUSTOM_LOG(lg, trace) << "Cleared MKskipped.";
    CUSTOM_LOG(lg, trace) << "--- DH Ratchet Step Complete ---";
}


// Tries to process skipped messages (Placeholder - complex logic)
void Client::TrySkippedMessageKeys(const DHPublicKey& pk_to_check, uint32_t up_to_n, const Message_Message& original_msg) {
     // Assumes lock is already held by caller (RatchetDecrypt)
    // CUSTOM_LOG(lg, trace) << "TrySkippedMessageKeys called for PK " + byteblock_to_string(pk_to_check) + " up to N=" + std::to_string(up_to_n);

    // Iterate through MKskipped and find keys matching pk_to_check
    // This requires careful implementation to avoid modifying map while iterating etc.
    for (auto it = MKskipped.begin(); it != MKskipped.end(); /* no increment here */) {
        const SkippedMessageKeyId& id = it->first;
        if (id.pk == pk_to_check && id.n < up_to_n) { // Check if PK matches and N is within the old chain range
             CUSTOM_LOG(lg, trace) << "Found potentially relevant skipped key for N=" + std::to_string(id.n);
            // This is complex: You don't have the original message for these skipped keys anymore.
            // The standard approach doesn't re-decrypt here. The keys are just stored
            // until a message arrives that explicitly matches the (pk, n) pair.
            // So, this function might just be for logging or cleanup in a simplified model.
            // If you *did* store the full skipped messages, you would try decrypting here.

            // For now, just log and remove (as if processed, though we didn't decrypt)
            // CUSTOM_LOG(lg, trace) << "Removing skipped key for PK " + byteblock_to_string(id.pk) + ", N=" + std::to_string(id.n) + " during DH ratchet transition (assuming processed/stale).";
            it = MKskipped.erase(it); // Erase and get iterator to next element
        } else {
            ++it; // Move to next element
        }
    }
     CUSTOM_LOG(lg, trace) << "Finished TrySkippedMessageKeys.";
}


// --- Client Thread Loops ---

void Client::cli_loop() {
  CUSTOM_LOG(lg, trace) << "Starting CLI loop.";
  while (running) {
    std::string input = cli_driver->read_input();
    if (!running) break; // Check running flag again after blocking call

    if (!input.empty()) {
        if (input == "/quit") {
            CUSTOM_LOG(lg, trace) << "Quit command received from CLI.";
            running = false; // Signal other threads to stop
            // Potentially send a final disconnect message? (Not implemented)
        } else {
            // Queue the message for sending
            std::lock_guard<std::mutex> lock(send_queue_mtx);
            send_queue.push(input);
             CUSTOM_LOG(lg, trace) << "Queued message for sending: " + input;
        }
    }
     // Add a small sleep to prevent busy-waiting if read_input is non-blocking
     std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
   CUSTOM_LOG(lg, trace) << "Exiting CLI loop.";
}

void Client::network_loop() {
  CUSTOM_LOG(lg, trace) << "Starting Network loop.";
  while (running) {
    std::string data = chvec2str(network_driver->read());

    if (!running) break; // Check after blocking call

    if (data.length() > 0) {
        CUSTOM_LOG(lg, trace) << "Received raw data (" + std::to_string(data.length()) + " bytes): ";
         // Determine message type and deserialize (basic version)
         try {
             // Assume type byte prefix
             if (data.empty()) continue;
             MessageType type = static_cast<MessageType>(data[0]);
             std::string msg_data = data.substr(1);

             std::unique_ptr<Message> msg;
             if (type == MessageType::KEY_EXCHANGE) {
                  // This should only happen during initial setup now
                 if (!initial_key_exchanged) {
                     CUSTOM_LOG(lg, trace) << "Received KEY_EXCHANGE message during setup phase.";
                     auto key_msg = std::make_unique<Message_KeyExchange>();
                     key_msg->deserialize(msg_data);

                     HandleKeyExchange(*key_msg);

                      CUSTOM_LOG(lg, trace) << "Responder: DR initialized from KEY_EXCHANGE.";
                 } else {
                      CUSTOM_LOG(lg, trace) << "Warning: Received unexpected KEY_EXCHANGE message after setup. Ignoring.";
                 }

             } else if (type == MessageType::MESSAGE) {
                 CUSTOM_LOG(lg, trace) << "Received MESSAGE message.";
                 msg = std::make_unique<Message_Message>();
                 msg->deserialize(msg_data); // Deserialize the DR message
                  // Queue the deserialized message object
                 std::lock_guard<std::mutex> lock(receive_queue_mtx);
                 receive_queue.push(std::move(msg));
                 CUSTOM_LOG(lg, trace) << "Queued received message for processing.";

             } else {
                 CUSTOM_LOG(lg, trace) << "Warning: Received unknown message type. Discarding.";
             }

         } catch (const std::exception& e) {
             CUSTOM_LOG(lg, trace) << "Error deserializing or queuing received message: " + std::string(e.what());
         }
    } 

    // Add a small sleep if receive is non-blocking or to reduce CPU usage
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
   CUSTOM_LOG(lg, trace) << "Exiting Network loop.";
}

void Client::send_loop() {
   CUSTOM_LOG(lg, trace) << "Starting Send loop.";
  while (running) {
    std::string plaintext_to_send;
    bool message_found = false;

    { // Scope for lock
      std::lock_guard<std::mutex> lock(send_queue_mtx);
      if (!send_queue.empty()) {
        plaintext_to_send = send_queue.front();
        send_queue.pop();
        message_found = true;
      }
    } // Lock released

    if (message_found) {
        if (!dr_initialized) {
             CUSTOM_LOG(lg, trace) << "Warning: Trying to send message before Double Ratchet is initialized. Message dropped.";
             continue; // Skip sending if DR isn't ready
        }

         CUSTOM_LOG(lg, trace) << "Processing message from send queue: " + plaintext_to_send;
         // Encrypt using Double Ratchet
        Message_Message dr_msg_opt = RatchetEncrypt(plaintext_to_send);

        CUSTOM_LOG(lg, trace) << "Message encrypted successfully. Serializing and sending.";
        std::vector<unsigned char> serialized_msg = str2chvec(prefix_message_type(dr_msg_opt)); // Add type prefix
        network_driver->send(serialized_msg);
        CUSTOM_LOG(lg, trace) << "Sent " + std::to_string(serialized_msg.size()) + " bytes.";
       
    }

    // Sleep even if no message was found to avoid busy-waiting
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
    CUSTOM_LOG(lg, trace) << "Exiting Send loop.";
}

void Client::receive_loop() {
    CUSTOM_LOG(lg, trace) << "Starting Receive loop.";
  while (running) {
    std::unique_ptr<Message> received_msg;
    bool message_found = false;

    { // Scope for lock
      std::lock_guard<std::mutex> lock(receive_queue_mtx);
      if (!receive_queue.empty()) {
        received_msg = std::move(receive_queue.front());
        receive_queue.pop();
        message_found = true;
      }
    } // Lock released

    if (message_found) {
        if (!received_msg) {
             CUSTOM_LOG(lg, trace) << "Error: Null message dequeued.";
             continue;
        }

        // We only expect Message_Message types after initialization
        if (received_msg->type() == MessageType::MESSAGE) {
             CUSTOM_LOG(lg, trace) << "Processing received message from queue.";
             // Downcast carefully
            Message_Message* dr_msg_ptr = dynamic_cast<Message_Message*>(received_msg.get());
            if (!dr_msg_ptr) {
                 CUSTOM_LOG(lg, trace) << "Error: Failed to cast received message to Message_Message.";
                 continue;
            }

            // Decrypt using Double Ratchet
            std::string plaintext_opt = RatchetDecrypt(*dr_msg_ptr);
            CUSTOM_LOG(lg, trace) << "Decryption successful.";
            cli_driver->print_info("<Peer>" + plaintext_opt);
           
        } else {
             CUSTOM_LOG(lg, trace) << "Warning: Received non-MESSAGE type message in receive_loop after initialization. Discarding.";
        }
    }

    // Sleep even if no message was found
     std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
   CUSTOM_LOG(lg, trace) << "Exiting Receive loop.";
}

void Client::run(bool is_initiator, std::string remote_addr) {
    is_initiator_ = is_initiator;
  running = true;
   CUSTOM_LOG(lg, trace) << "Client starting run...";

  try {
    // Initialize network connection and perform initial key exchange
    prepare_keys(is_initiator, remote_addr);

    // Start worker threads *after* initial setup
    CUSTOM_LOG(lg, trace) << "Starting worker threads...";
    cli_thread = std::thread(&Client::cli_loop, this);
    network_thread = std::thread(&Client::network_loop, this);
    send_thread = std::thread(&Client::send_loop, this);
    receive_thread = std::thread(&Client::receive_loop, this);
     CUSTOM_LOG(lg, trace) << "All threads started.";

  } catch (const std::exception& e) {
     CUSTOM_LOG(lg, trace) << "Error during initialization: " + std::string(e.what());
    cli_driver->print_warning("Initialization failed: " + std::string(e.what()));
    running = false; // Prevent threads from doing work if init failed
  }

  // Keep main thread alive while worker threads run (or join them here)
  // If prepare_keys succeeded, the threads are running. We can wait for them.
   if (running) {
       CUSTOM_LOG(lg, trace) << "Client running. Joining CLI thread to keep alive...";
       if (cli_thread.joinable()) {
           cli_thread.join(); // Wait for user to quit via CLI
       }
       CUSTOM_LOG(lg, trace) << "CLI thread finished. Initiating shutdown.";
       stop(); // Ensure other threads are stopped and joined if CLI loop exits
   } else {
        CUSTOM_LOG(lg, trace) << "Initialization failed, client did not fully start.";
   }
   CUSTOM_LOG(lg, trace) << "Client run finished.";
}

void Client::stop() {
   CUSTOM_LOG(lg, trace) << "Client stop requested.";
  // Graceful shutdown sequence
  running = false; // Signal all loops to terminate

   CUSTOM_LOG(lg, trace) << "Signaled threads to stop. Joining threads...";

  // Optional: Add mechanisms to interrupt blocking calls in loops (e.g., close sockets)
  network_driver->disconnect(); // Help network_loop unblock
  cli_driver->notify_shutdown(); // Help cli_loop unblock if needed

  // Join threads to ensure they exit cleanly
  if (cli_thread.joinable()) {
    CUSTOM_LOG(lg, trace) << "Joining CLI thread...";
    cli_thread.join();
    CUSTOM_LOG(lg, trace) << "CLI thread joined.";
  }
   if (send_thread.joinable()) {
     CUSTOM_LOG(lg, trace) << "Joining Send thread...";
     send_thread.join();
     CUSTOM_LOG(lg, trace) << "Send thread joined.";
   }
  if (receive_thread.joinable()) {
     CUSTOM_LOG(lg, trace) << "Joining Receive thread...";
     receive_thread.join();
     CUSTOM_LOG(lg, trace) << "Receive thread joined.";
   }
  if (network_thread.joinable()) {
     CUSTOM_LOG(lg, trace) << "Joining Network thread...";
    network_thread.join();
     CUSTOM_LOG(lg, trace) << "Network thread joined.";
  }

   CUSTOM_LOG(lg, trace) << "All threads joined. Client stopped.";
}