#!/usr/bin/env python3
"""
Test client key storage and loading
"""
import sys
import os

# Add the client directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'client'))

import client
import json

def test_key_storage():
    """Test key generation, storage, and loading"""
    print("🗝️  Testing Key Storage System")
    print("=" * 40)
    
    # Test 1: Generate and save Alice's keys
    print("1. Generating Alice's keys...")
    client.load_or_generate_keys("alice")
    alice_keys_1 = client.user_keys.copy()
    
    print(f"✅ Alice keys generated: {list(alice_keys_1.keys())}")
    
    # Check if file was created
    if os.path.exists("users_keys/alice_keys.json"):
        print("✅ Alice's key file created successfully")
        
        # Read the file directly
        with open("users_keys/alice_keys.json", 'r') as f:
            file_content = json.load(f)
        print(f"   File contains: {list(file_content.keys())}")
    else:
        print("❌ Alice's key file NOT created")
        return False
    
    # Test 2: Load Alice's keys again (should load from file)
    print("\n2. Loading Alice's keys from file...")
    client.user_keys = None  # Reset
    client.load_or_generate_keys("alice")
    alice_keys_2 = client.user_keys.copy()
    
    # Compare keys
    keys_match = (alice_keys_1['ecc_private'] == alice_keys_2['ecc_private'] and 
                  alice_keys_1['dsa_private'] == alice_keys_2['dsa_private'])
    
    print(f"✅ Keys loaded from file: {'MATCH' if keys_match else 'DIFFERENT'}")
    
    # Test 3: Generate Bob's keys
    print("\n3. Generating Bob's keys...")
    client.load_or_generate_keys("bob")
    bob_keys = client.user_keys.copy()
    
    print(f"✅ Bob keys generated: {list(bob_keys.keys())}")
    
    # Check both files exist
    alice_file = os.path.exists("users_keys/alice_keys.json")
    bob_file = os.path.exists("users_keys/bob_keys.json")
    
    print(f"✅ File system check:")
    print(f"   Alice file: {'✅ EXISTS' if alice_file else '❌ MISSING'}")
    print(f"   Bob file: {'✅ EXISTS' if bob_file else '❌ MISSING'}")
    
    # Test 4: Test that different users have different keys
    keys_different = (alice_keys_1['ecc_private'] != bob_keys['ecc_private'])
    print(f"   Different users have different keys: {'✅ YES' if keys_different else '❌ NO'}")
    
    return keys_match and alice_file and bob_file and keys_different

def test_message_flow():
    """Test the complete message flow with stored keys"""
    print("\n💬 Testing Complete Message Flow")
    print("=" * 40)
    
    # Load Alice and Bob's keys
    client.load_or_generate_keys("alice")
    alice_keys = client.user_keys.copy()
    
    client.load_or_generate_keys("bob")
    bob_keys = client.user_keys.copy()
    
    # Simulate the complete client message flow
    print("1. Simulating Alice sending secure message to Bob...")
    
    # Step 1: Alice creates a secure message
    message = "Meet me at the library at 3pm. -Alice"
    
    # Step 2: Alice encrypts and signs for Bob
    from ciphermodule import encrypt_and_sign_for_user, decrypt_and_verify_received
    
    encrypted_package = encrypt_and_sign_for_user(
        message,
        bob_keys['ecc_public'],     # Bob can decrypt
        alice_keys['dsa_private']   # Signed by Alice
    )
    
    # Step 3: Create the JSON message that would be sent to server
    secure_msg = {
        'type': 'secure_message',
        'sender': 'alice',
        'recipient': 'bob',
        'encrypted_data': encrypted_package
    }
    
    print(f"✅ Secure message created")
    print(f"   Message type: {secure_msg['type']}")
    print(f"   From: {secure_msg['sender']} → To: {secure_msg['recipient']}")
    
    # Step 4: Bob receives and processes the message
    print("\n2. Simulating Bob receiving and decrypting message...")
    
    # Extract the encrypted data (like handle_secure_message does)
    received_encrypted_data = secure_msg['encrypted_data']
    
    # Bob decrypts with his keys and Alice's public key
    decrypted_message, signature_valid, timestamp = decrypt_and_verify_received(
        received_encrypted_data,
        bob_keys['ecc_private'],    # Bob's private key for decryption
        alice_keys['dsa_public']    # Alice's public key for signature verification
    )
    
    print(f"✅ Message decrypted successfully")
    print(f"   Original: {message}")
    print(f"   Decrypted: {decrypted_message}")
    print(f"   Signature valid: {signature_valid}")
    print(f"   Match: {'✅ PERFECT' if message == decrypted_message else '❌ FAILED'}")
    
    return message == decrypted_message and signature_valid

def main():
    """Run storage tests"""
    print("🧪 Client Storage & Flow Testing")
    print("=" * 50)
    
    try:
        # Test key storage
        storage_success = test_key_storage()
        
        # Test message flow
        flow_success = test_message_flow()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 TEST RESULTS:")
        print(f"🗝️  Key storage: {'✅ PASS' if storage_success else '❌ FAIL'}")
        print(f"💬 Message flow: {'✅ PASS' if flow_success else '❌ FAIL'}")
        
        if storage_success and flow_success:
            print("\n🎉 ALL SYSTEMS GO!")
            print("Your client is ready for server integration!")
        else:
            print("\n⚠️  Some systems need attention.")
            
    except Exception as e:
        print(f"❌ Testing failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
