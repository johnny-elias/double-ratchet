#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

#include <atomic>
#include <iostream>
#include <map>
#include <memory> // For std::unique_ptr
#include <mutex>
#include <queue>
#include <string>
#include <thread> // For std::thread
#include <utility> // For std::pair

#include <cryptopp/secblock.h> // For SecByteBlock

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"


// Define a structure for the skipped message key map key
// Requires a less-than operator for std::map
struct SkippedMessageKeyId {
    DHPublicKey pk;
    uint32_t n;

    bool operator<(const SkippedMessageKeyId& other) const {
        // Compare public keys first, then message numbers
        int pk_cmp = memcmp(pk.BytePtr(), other.pk.BytePtr(), std::min(pk.size(), other.pk.size()));
        if (pk_cmp != 0) {
            return pk_cmp < 0;
        }
        // If Pks are potentially different sizes but prefixes match, compare sizes
         if (pk.size() != other.pk.size()) {
             return pk.size() < other.pk.size();
         }
        // If Pks are identical, compare message numbers
        return n < other.n;
    }
};


class Client {
private:
  // Drivers
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  // State
  std::atomic<bool> running;
  src::severity_logger<logging::trivial::severity_level> lg; // Logger instance
  std::mutex mtx; // Mutex for protecting shared state (like DR state)

  // Message Queues
  std::queue<std::string> send_queue;
  std::mutex send_queue_mtx;
  std::queue<std::unique_ptr<Message>> receive_queue;
  std::mutex receive_queue_mtx;

  bool is_initiator_ = false;


  // --- Double Ratchet State ---
  bool dr_initialized; // Flag to check if DR state is ready
  bool first_dr_message_received; // Flag to check if first message is sent
  RootKey RK;          // Root Key
  ChainKey CKs;        // Sending Chain Key
  ChainKey CKr;        // Receiving Chain Key
  CryptoPP::SecByteBlock DHs_priv; // Our current DH ratchet private key
  DHPublicKey DHs_pub; // Our current DH ratchet public key
  DHPublicKey DHr_pub; // Remote party's current DH ratchet public key
  uint32_t Ns = 0;         // Sending message number
  uint32_t Nr = 0;         // Receiving message number
  uint32_t PN = 0;         // Previous sending chain length
  // Stores skipped message keys: map<(remote_pub_key, message_num), message_key>
  std::map<SkippedMessageKeyId, MessageKey> MKskipped;
  static const unsigned int MAX_SKIPPED_KEYS = 20; // Limit stored skipped keys

  // --- Initial Key Exchange State (Simplified) ---
  // In a full implementation (X3DH), this would be more complex.
  // Assuming simple DH exchange for initial SK establishment.
  bool initial_key_exchanged = false;
  CryptoPP::SecByteBlock initial_shared_secret;
  // DHPublicKey initial_remote_pub_key; // Store the initial key received


  // --- Threads ---
  std::thread network_thread;
  std::thread cli_thread;
  std::thread send_thread;
  std::thread receive_thread;


  // --- Private Helper Methods ---
  void cli_loop();
  void network_loop();
  void send_loop();
  void receive_loop();

  // Key Preparation / Initial Exchange (Simplified)
  void prepare_keys(bool is_initiator, std::string& remote_addr);
  void HandleKeyExchange(const Message_KeyExchange &msg);


  // --- Double Ratchet Core Logic ---
  // Initialization based on initial shared secret SK
  void RatchetInitAlice(const CryptoPP::SecByteBlock& SK, const DHPublicKey& bob_identity_pub_key, const DHPublicKey& bob_ratchet_pub_key);
  void RatchetInitBob(const CryptoPP::SecByteBlock& SK, const CryptoPP::SecByteBlock& bob_ratchet_priv_key, const DHPublicKey& bob_ratchet_pub_key);

  // Encrypts plaintext using the sending ratchet
  Message_Message RatchetEncrypt(const std::string& plaintext);

  // Decrypts a received message using the receiving ratchet (handles skipped msgs & DH steps)
  std::string RatchetDecrypt(const Message_Message& msg);

  // Performs a DH Ratchet step when a new remote key is received
  void DoDHRatchetStep(const DHPublicKey& received_dh_pub);

  // Tries to decrypt using stored skipped keys for a given chain
  void TrySkippedMessageKeys(const DHPublicKey& pk, uint32_t n, const Message_Message& original_msg);

public:
  Client(std::shared_ptr<CryptoDriver> crypto_driver,
         std::shared_ptr<NetworkDriver> network_driver);
  ~Client(); // Destructor to join threads

  void run(bool is_initiator, std::string remote_addr);
  void stop();
};

#endif // __CLIENT_HPP__