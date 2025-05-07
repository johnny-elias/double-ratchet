#include <iostream>
#include <string>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include "../include-shared/util.hpp"      // for print_key_as_hex, integer_to_byteblock, etc.
#include "../include-shared/messages.hpp"  // for DHPublicKey, MessageKey, ChainKey, RootKey
#include "../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;
using namespace std;

string toHex(const SecByteBlock& b) {
    string s;
    HexEncoder encoder(new StringSink(s));
    encoder.Put(b, b.size());
    encoder.MessageEnd();
    return s;
}

int main() {
    CryptoDriver cd;

    // 1) Alice & Bob each generate a ratchet keypair:
    SecByteBlock a_priv, a_pub, b_priv, b_pub;
    cd.DH_generate_ratchet_keypair(a_priv, a_pub);
    cd.DH_generate_ratchet_keypair(b_priv, b_pub);

    cout << "Alice pub  (" << a_pub.size() << " bytes):\n" 
         << toHex(a_pub) << "\n\n";
    cout << "Bob   pub  (" << b_pub.size() << " bytes):\n" 
         << toHex(b_pub) << "\n\n";

    // 2) DH agree → shared secret
    auto ss_ab = cd.DH_generate_shared_secret(a_priv, b_pub);
    auto ss_ba = cd.DH_generate_shared_secret(b_priv, a_pub);
    cout << "Shared secret match? " << (ss_ab == ss_ba ? "YES" : "NO") << "\n";
    cout << "Shared secret (" << ss_ab.size() << " bytes):\n" 
         << toHex(ss_ab) << "\n\n";

    // 3) Root Key Derivation: use zero‐block as initial RK
    RootKey rk0(HASH::DIGESTSIZE);            // all zeros
    RootKey rk1; ChainKey ck1;
    tie(rk1, ck1) = cd.KDF_RK(rk0, ss_ab);

    cout << "New RootKey  (32 bytes):\n" << toHex(rk1) << "\n\n";
    cout << "New ChainKey (32 bytes):\n" << toHex(ck1) << "\n\n";

    // 4) Chain‑KDF → next ChainKey + MessageKey
    ChainKey ck2; MessageKey mk;
    tie(ck2, mk) = cd.KDF_CK(ck1);

    cout << "Next ChainKey  (32 bytes):\n" << toHex(ck2) << "\n\n";
    cout << "MessageKey     (16 bytes):\n" << toHex(mk) << "\n\n";

    // 5) Encrypt + decrypt
    string pt = "Hello, Double Ratchet!";
    auto [iv, ct] = cd.AES_encrypt(mk, pt, "");
    auto mac = cd.HMAC_generate(mk, iv, ct, "");

    cout << "IV  (16 bytes):\n" << toHex(iv) << "\n\n";
    cout << "CT  ("<< ct.size() <<" bytes):\n" << toHex(ct) << "\n\n";
    cout << "MAC (32 bytes):\n" << toHex(mac) << "\n\n";

    string recovered = cd.AES_decrypt(mk, iv, ct, "");
    cout << "Decrypted:\n  " << recovered << "\n";

    return 0;
}
