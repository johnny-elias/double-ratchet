# Secure Chat Client with Double Ratchet Implementation

## Overview

This project implements the **Double Ratchet algorithm** for end-to-end encryption. Building upon a basic Diffie-Hellman key exchange foundation, this implementation adds the symmetric-key ratchet component of the Double Ratchet protocol, providing enhanced security properties like **forward secrecy** and **post-compromise security**.

The goal is to simulate key aspects of the Signal protocol's session management, allowing two users to communicate securely over an unreliable network.

## Features

* **End-to-End Encryption:** Messages are encrypted using AES (currently CBC mode, potentially GCM) with keys derived uniquely for each message.
* **Double Ratchet Algorithm:**
    * **Diffie-Hellman (DH) Ratchet:** Updates keys based on new DH key agreements between parties.
    * **Symmetric-Key Ratchet:** Uses HKDF (based on HMAC-SHA256) to derive message keys from chain keys, advancing the state with each message.
* **Message Integrity:** HMAC-SHA256 is used to ensure messages are not tampered with during transit.
* **Out-of-Order Message Handling:** Stores skipped message keys to allow decryption of messages arriving out of sequence within the current DH epoch.
* **Basic Networking:** Simple TCP client/server model for communication.
* **Command-Line Interface (CLI):** Basic text-based interface for sending and receiving messages.
* **Logging:** Provides detailed logging for debugging and tracing protocol state.

## Core Concepts: Double Ratchet

The Double Ratchet algorithm combines two cryptographic ratchets:

1.  **Diffie-Hellman Ratchet:** When parties exchange new DH public keys, a DH calculation is performed. The output is mixed into a **Root Key** using a Key Derivation Function (KDF), providing post-compromise security. This step also derives new **Chain Keys**.
2.  **Symmetric-Key (Hashing) Ratchet:** For each message sent or received within a DH epoch, a **Chain Key** is updated using a KDF (typically HMAC-based). This KDF step produces a unique **Message Key** (for encryption/decryption) and the next Chain Key. This provides forward secrecy, as message keys cannot be derived from later chain keys.

## Dependencies

* **CMake:** (Version 3.16 or higher recommended) - For building the project.
* **C++ Compiler:** A modern C++ compiler supporting C++17 (or as required by dependencies).
* **Crypto++ Library:** (Version 8.x recommended) - Provides cryptographic primitives (DH, AES, SHA256, HMAC, HKDF). Assumed to be installed or linked via CMake.
* **doctest:** (Fetched via CMake `FetchContent`) - For the unit testing framework.

## Testing

Tests are included in the `test/` directory and use the `doctest` framework.

1.  **Build the tests** (usually done as part of the main build):
    ```bash
    cd build
    make
    ```
2.  **Run the tests:**
    ```bash
    make test
    # or directly execute the test runner:
    # ./test/unit_tests
    ```

## Authors

* Johannes Elias (johannes@brown.edu)
* Alaina Lin (alaina@brown.edu)

