#!/usr/bin/env python3
"""
Simple test of crypto functions without server
"""
import sys
import os

# Add the client directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'client'))

from ciphermodule import generate_user_keypairs, encrypt_and_sign_for_user, decrypt_and_verify_received
import json

def test_basic_crypto():
    """Test basic crypto functions without file I/O"""
    print("🧪 Testing Basic Crypto Functions")
    print("=" * 40)
    
    # Generate keys for Alice and Bob
    print("1. Generating keys...")
    alice_keys = generate_user_keypairs()
    bob_keys = generate_user_keypairs()
    
    print(f"✅ Alice keys: {list(alice_keys.keys())}")
    print(f"✅ Bob keys: {list(bob_keys.keys())}")
    
    # Test message encryption
    print("\n2. Testing message encryption...")
    message = "Hello Bob! This is Alice's secret message."
    print(f"Original: {message}")
    
    # Alice sends to Bob
    encrypted_package = encrypt_and_sign_for_user(
        message,
        bob_keys['ecc_public'],     # Bob's public key
        alice_keys['dsa_private']   # Alice's private key
    )
    
    print(f"✅ Encrypted package created with keys: {list(encrypted_package.keys())}")
    
    # Bob receives from Alice
    decrypted, signature_valid, timestamp = decrypt_and_verify_received(
        encrypted_package,
        bob_keys['ecc_private'],    # Bob's private key
        alice_keys['dsa_public']    # Alice's public key
    )
    
    print(f"Decrypted: {decrypted}")
    print(f"Signature valid: {signature_valid}")
    print(f"Timestamp: {timestamp}")
    
    success = (decrypted == message and signature_valid)
    print(f"\n✅ End-to-end test: {'PASS' if success else 'FAIL'}")
    
    return success

def test_json_serialization():
    """Test JSON message format"""
    print("\n🧪 Testing JSON Message Format")
    print("=" * 40)
    
    alice_keys = generate_user_keypairs()
    bob_keys = generate_user_keypairs()
    
    # Test public key message
    public_key_msg = {
        'type': 'public_keys',
        'username': 'alice',
        'ecc_public': alice_keys['ecc_public'],
        'dsa_public': alice_keys['dsa_public']
    }
    
    try:
        json_str = json.dumps(public_key_msg, indent=2)
        print(f"✅ Public key JSON serialization: SUCCESS")
        print(f"   Size: {len(json_str)} characters")
    except Exception as e:
        print(f"❌ Public key JSON serialization failed: {e}")
        return False
    
    # Test secure message format
    message = "Test secure message"
    encrypted_package = encrypt_and_sign_for_user(
        message,
        bob_keys['ecc_public'],
        alice_keys['dsa_private']
    )
    
    secure_msg = {
        'type': 'secure_message',
        'sender': 'alice',
        'recipient': 'bob',
        'encrypted_data': encrypted_package
    }
    
    try:
        secure_json = json.dumps(secure_msg, indent=2)
        print(f"✅ Secure message JSON serialization: SUCCESS")
        print(f"   Size: {len(secure_json)} characters")
        
        # Test parsing back
        parsed = json.loads(secure_json)
        print(f"✅ JSON parsing successful: {parsed['type']}")
        
    except Exception as e:
        print(f"❌ Secure message JSON serialization failed: {e}")
        return False
    
    return True

def test_key_types():
    """Check what types of keys we're generating"""
    print("\n🧪 Testing Key Types")
    print("=" * 40)
    
    keys = generate_user_keypairs()
    
    for key_name, key_value in keys.items():
        print(f"{key_name}: {type(key_value)} - {len(str(key_value))} chars")
        if isinstance(key_value, str) and key_value.startswith('-----'):
            print(f"  ✅ {key_name} is valid PEM format")
        else:
            print(f"  ❌ {key_name} is not valid PEM format")

def main():
    """Run all tests"""
    print("🚀 Client Crypto Testing Suite")
    print("=" * 50)
    print("Testing without server connection...")
    print()
    
    try:
        # Test 1: Basic crypto
        crypto_success = test_basic_crypto()
        
        # Test 2: Key types
        test_key_types()
        
        # Test 3: JSON serialization
        json_success = test_json_serialization()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 FINAL RESULTS:")
        print(f"🔐 Crypto functions: {'✅ PASS' if crypto_success else '❌ FAIL'}")
        print(f"📄 JSON serialization: {'✅ PASS' if json_success else '❌ FAIL'}")
        
        if crypto_success and json_success:
            print("🎉 ALL TESTS PASSED! Your crypto client is ready!")
        else:
            print("⚠️  Some tests failed. Check the output above.")
            
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
