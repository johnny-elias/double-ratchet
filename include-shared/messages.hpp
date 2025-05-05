#ifndef __MESSAGES_HPP__
#define __MESSAGES_HPP__

// #include <cstdint>
// #include <cstring> // For memcpy
// #include <iostream>
// #include <memory>
// #include <optional>
// #include <stdexcept>
// #include <string>
// #include <variant>
// #include <vector>
// #include <map>
// #include <algorithm> // For std::min

// // Include util.hpp *before* it's used for hton/ntoh
// #include "util.hpp"

// // Include CryptoPP headers needed for key types and byte definition
// #include <cryptopp/secblock.h>
// #include <cryptopp/integer.h>
// #include <cryptopp/osrng.h>
// #include <cryptopp/dh.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>

// Define key types (adjust size based on your DH domain and hash function, typically 32 bytes)
using RootKey = CryptoPP::SecByteBlock;
using ChainKey = CryptoPP::SecByteBlock;
using MessageKey = CryptoPP::SecByteBlock;
using DHPublicKey = CryptoPP::SecByteBlock; // Store public keys as byte blocks

// Define a simple structure for the DR header (can be serialized separately or as part of AD)
struct DoubleRatchetHeader {
    DHPublicKey dh_pub; // Sender's current ratchet public key
    uint32_t pn;        // Previous chain length
    uint32_t n;         // Message number in current chain

    DoubleRatchetHeader() : pn(0), n(0) {} // Default constructor

    // Basic serialization (example - needs robust implementation)
    std::string serialize() const {
        std::string s;
        // Size of pub key + pub key bytes + sizeof(pn) + pn bytes + sizeof(n) + n bytes
        uint32_t pub_key_size = dh_pub.size(); 
        s.append(reinterpret_cast<const char*>(&pub_key_size), sizeof(pub_key_size));
        s.append(reinterpret_cast<const char*>(dh_pub.BytePtr()), pub_key_size);

        s.append(reinterpret_cast<const char*>(&pn), sizeof(pn));

        s.append(reinterpret_cast<const char*>(&n), sizeof(n));
        return s;
    }

    // Basic deserialization (example - needs robust implementation)
    // Returns the number of bytes consumed, or 0 on error.
    size_t deserialize(const std::string& data) {
        size_t offset = 0;

        // Read pub key size
        if (data.size() < offset + sizeof(uint32_t)) return 0;
        uint32_t pub_key_size;
        std::memcpy(&pub_key_size, data.data() + offset, sizeof(pub_key_size));
        offset += sizeof(pub_key_size);

        // Read pub key bytes
        if (data.size() < offset + pub_key_size) return 0;
        // Use global namespace 'byte' type defined by CryptoPP's config.h
        dh_pub.Assign(reinterpret_cast<const byte*>(data.data() + offset), pub_key_size);
        offset += pub_key_size;

        // Read PN
        if (data.size() < offset + sizeof(uint32_t)) return 0;
        uint32_t pn;
        std::memcpy(&pn, data.data() + offset, sizeof(pn));
        offset += sizeof(pn);

        // Read N
        if (data.size() < offset + sizeof(uint32_t)) return 0;
        uint32_t n;
        std::memcpy(&n, data.data() + offset, sizeof(n));
        offset += sizeof(n);

        return offset; // Return bytes consumed
    }

     // For using DHPublicKey in std::map keys (like SkippedMessageKeyId)
     // Provides a strict weak ordering.
    bool operator<(const DHPublicKey& other) const {
         size_t len1 = dh_pub.size();
         size_t len2 = other.size();
         size_t min_len = std::min(len1, len2);
         int cmp = std::memcmp(dh_pub.BytePtr(), other.BytePtr(), min_len);
         if (cmp != 0) {
             return cmp < 0;
         }
         // If prefixes match, shorter key comes first
         return len1 < len2;
     }
     // Need operator== for some map operations or direct comparison
     bool operator==(const DHPublicKey& other) const {
        return dh_pub == other; // CryptoPP::SecByteBlock has operator==
     }
};


enum class MessageType : uint8_t { KEY_EXCHANGE = 0, MESSAGE = 1 };

struct Message {
  virtual MessageType type() const = 0;
  // Use std::string for serialization buffer
  virtual std::string serialize() const = 0;
  // Return bytes consumed or throw on error
  virtual size_t deserialize(const std::string &bytes) = 0;

  virtual ~Message() = default; // Add virtual destructor for polymorphism
};

// --- Existing KeyExchange Message ---
// Represents the simplified initial exchange before DR starts.
struct Message_KeyExchange : public Message {
  MessageType type() const override { return MessageType::KEY_EXCHANGE; }

  CryptoPP::SecByteBlock iv;      // May not be needed if unencrypted
  CryptoPP::SecByteBlock pub_val; // DH Public value

  std::string serialize() const override {
      std::string serialized_data;
      // Example: Add sizes before data (network byte order)
      uint32_t iv_size = iv.size();
      serialized_data.append(reinterpret_cast<const char*>(&iv_size), sizeof(iv_size));
      serialized_data.append(reinterpret_cast<const char*>(iv.BytePtr()), iv_size);

      uint32_t pub_val_size = pub_val.size();
      serialized_data.append(reinterpret_cast<const char*>(&pub_val_size), sizeof(pub_val_size));
      serialized_data.append(reinterpret_cast<const char*>(pub_val.BytePtr()), pub_val_size);

      return serialized_data;
  }

  size_t deserialize(const std::string &bytes) override {
      size_t offset = 0;

      // Read IV size and data
      uint32_t iv_size;
      if (bytes.size() < offset + sizeof(iv_size)) throw std::runtime_error("Deserialization error: IV size missing");
      std::memcpy(&iv_size, bytes.data() + offset, sizeof(iv_size));

      offset += sizeof(iv_size);
      if (bytes.size() < offset + iv_size) throw std::runtime_error("Deserialization error: IV data missing");
      // Use global namespace 'byte'
      iv.Assign(reinterpret_cast<const byte*>(bytes.data() + offset), iv_size);
      offset += iv_size;

      // Read Public Value size and data
      uint32_t pub_val_size;
       if (bytes.size() < offset + sizeof(pub_val_size)) throw std::runtime_error("Deserialization error: pub_val size missing");
      std::memcpy(&pub_val_size, bytes.data() + offset, sizeof(pub_val_size));
      
      offset += sizeof(pub_val_size);
      if (bytes.size() < offset + pub_val_size) throw std::runtime_error("Deserialization error: pub_val data missing");
       // Use global namespace 'byte'
      pub_val.Assign(reinterpret_cast<const byte*>(bytes.data() + offset), pub_val_size);
      offset += pub_val_size;

      return offset; // Return bytes consumed
  }
};


// --- Message used for Double Ratchet encrypted data ---
struct Message_Message : public Message {
  MessageType type() const override { return MessageType::MESSAGE; }

  DoubleRatchetHeader header; // Contains DH pub key, PN, N
  CryptoPP::SecByteBlock iv; // Initialization vector for AES
  CryptoPP::SecByteBlock ciphertext;
  CryptoPP::SecByteBlock mac; // MAC for ciphertext integrity/authenticity


  // Serialization - Header needs to be serialized too.
  // We will serialize the header separately and pass it as Associated Data (AD)
  // The main message serialization only includes IV, Ciphertext, MAC
  std::string serialize() const override {
      std::string serialized_data;

      // Serialize Header (this part is needed for the receiver to process)
      std::string serialized_header = header.serialize();
      uint32_t header_size = serialized_header.size();
      serialized_data.append(reinterpret_cast<const char*>(&header_size), sizeof(header_size));
      serialized_data.append(serialized_header);

      // Serialize IV
      uint32_t iv_size = iv.size();
      serialized_data.append(reinterpret_cast<const char*>(&iv_size), sizeof(iv_size));
      serialized_data.append(reinterpret_cast<const char*>(iv.BytePtr()), iv_size);

      // Serialize Ciphertext
      uint32_t ct_size = ciphertext.size();
      serialized_data.append(reinterpret_cast<const char*>(&ct_size), sizeof(ct_size));
      serialized_data.append(reinterpret_cast<const char*>(ciphertext.BytePtr()), ct_size);

       // Serialize MAC
      uint32_t mac_size = mac.size();
      serialized_data.append(reinterpret_cast<const char*>(&mac_size), sizeof(mac_size));
      serialized_data.append(reinterpret_cast<const char*>(mac.BytePtr()), mac_size);


      return serialized_data;
  }

  // Deserialization - Header needs to be deserialized first.
  // The Associated Data (AD) will be constructed from the serialized header bytes
  // before attempting decryption/MAC verification.
  // Returns bytes consumed or throws on error.
  size_t deserialize(const std::string &bytes) override {
      size_t offset = 0;

      // Deserialize Header
      uint32_t header_size;
      if (bytes.size() < offset + sizeof(header_size)) throw std::runtime_error("Deserialization error: header size missing");
      std::memcpy(&header_size, bytes.data() + offset, sizeof(header_size));
      offset += sizeof(header_size);

      if (bytes.size() < offset + header_size) throw std::runtime_error("Deserialization error: header data missing");
      std::string serialized_header = bytes.substr(offset, header_size);
      size_t header_bytes_consumed = header.deserialize(serialized_header);
      if (header_bytes_consumed == 0 || header_bytes_consumed != header_size) { // Check if deserialize failed or consumed unexpected amount
          throw std::runtime_error("Deserialization error: failed to parse header or size mismatch");
      }
      offset += header_size; // Advance by the actual header size read from the stream

      // Deserialize IV
      uint32_t iv_size;
      if (bytes.size() < offset + sizeof(iv_size)) throw std::runtime_error("Deserialization error: IV size missing");
      std::memcpy(&iv_size, bytes.data() + offset, sizeof(iv_size));

      offset += sizeof(iv_size);
      if (bytes.size() < offset + iv_size) throw std::runtime_error("Deserialization error: IV data missing");
       // Use global namespace 'byte'
      iv.Assign(reinterpret_cast<const byte*>(bytes.data() + offset), iv_size);
      offset += iv_size;

      // Deserialize Ciphertext
      uint32_t ct_size;
      if (bytes.size() < offset + sizeof(ct_size)) throw std::runtime_error("Deserialization error: ciphertext size missing");
      std::memcpy(&ct_size, bytes.data() + offset, sizeof(ct_size));

      offset += sizeof(ct_size);
      if (bytes.size() < offset + ct_size) throw std::runtime_error("Deserialization error: ciphertext data missing");
       // Use global namespace 'byte'
      ciphertext.Assign(reinterpret_cast<const byte*>(bytes.data() + offset), ct_size);
      offset += ct_size;

       // Deserialize MAC
      uint32_t mac_size;
       if (bytes.size() < offset + sizeof(mac_size)) throw std::runtime_error("Deserialization error: MAC size missing");
      std::memcpy(&mac_size, bytes.data() + offset, sizeof(mac_size));

      offset += sizeof(mac_size);
      // Check if enough data remains for the MAC
      if (bytes.size() < offset + mac_size) throw std::runtime_error("Deserialization error: MAC data missing or incomplete");
       // Use global namespace 'byte'
      mac.Assign(reinterpret_cast<const byte*>(bytes.data() + offset), mac_size);
      offset += mac_size; // Important: increment offset by the actual MAC size read

      // Optional: Check if there's extra unexpected data
      if (offset != bytes.size()) {
         std::cerr << "Warning: Extra data detected after deserialization. Consumed " << offset << " of " << bytes.size() << " bytes." << std::endl;
      }
      return offset; // Return total bytes consumed
  }

  // Helper to get the serialized header bytes, useful for Associated Data (AD)
  std::string get_serialized_header() const {
      return header.serialize();
  }
};


// Factory function to create message objects from bytes
// Assumes first byte is the type, rest is data.
inline std::unique_ptr<Message> MessageFactory(const std::string &bytes) {
  if (bytes.empty()) {
    throw std::runtime_error("Cannot create message from empty bytes");
  }

  // Extract type byte first
  MessageType type = static_cast<MessageType>(bytes[0]);
  std::string message_data = bytes.substr(1); // Rest of the data

  std::unique_ptr<Message> msg;

  switch (type) {
  case MessageType::KEY_EXCHANGE: {
    msg = std::make_unique<Message_KeyExchange>();
    break;
  }
  case MessageType::MESSAGE: {
    msg = std::make_unique<Message_Message>();
    break;
  }
  default:
    // Use std::to_string for the integer value of the unknown type
    throw std::runtime_error("Unknown message type encountered: " + std::to_string(static_cast<int>(type)));
  }

  try {
      size_t consumed = msg->deserialize(message_data); // Deserialize using the remaining data
      // Optional: Check if deserialize consumed all data if expected
      // if (consumed != message_data.size()) { ... warning ... }
  } catch (const std::exception& e) {
      // Re-throw or wrap the exception with more context
       throw std::runtime_error("Failed to deserialize message type " + std::to_string(static_cast<int>(type)) + ": " + e.what());
  }
  return msg;
}


// Function to add the type prefix for sending
inline std::string prefix_message_type(const Message& msg) {
    std::string serialized_msg = msg.serialize();
    char type_byte = static_cast<char>(msg.type());
    return type_byte + serialized_msg; // Prepend the type byte
}

#endif // __MESSAGES_HPP__
