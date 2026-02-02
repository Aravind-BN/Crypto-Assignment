from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import json
from datetime import datetime
import hashlib

# Try to import Kyber from different sources
USING_REAL_KYBER = False

try:
    # Try oqs (Open Quantum Safe) - more reliable
    import oqs
    USING_REAL_KYBER = True
    print("✓ Using real CRYSTALS-Kyber from liboqs")
    
    class KyberWrapper:
        @staticmethod
        def keypair():
            kem = oqs.KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
        
        @staticmethod
        def enc(public_key):
            kem = oqs.KeyEncapsulation("Kyber512")
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
        
        @staticmethod
        def dec(ciphertext, secret_key):
            kem = oqs.KeyEncapsulation("Kyber512", secret_key=secret_key)
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
    
    kyber = KyberWrapper()
    
except ImportError:
    print("⚠ liboqs not found, using educational Kyber simulation")
    print("  (Install with: pip uninstall pqcrypto && pip install liboqs-python)")
    
    # Educational simulation that demonstrates Kyber concepts
    class KyberSimulation:
        """
        Educational CRYSTALS-Kyber simulation for demonstration.
        Shows the correct flow and uses proper key/ciphertext sizes.
        
        Note: This is for educational purposes. For production, use:
        - liboqs-python (recommended)
        - pqcrypto (if properly compiled)
        """
        
        @staticmethod
        def keypair():
            """Generate Kyber-512 keypair (correct sizes)"""
            secret_key = os.urandom(1632)  # Kyber-512 secret key size
            # Public key derived from secret (simplified)
            public_key = hashlib.sha3_512(secret_key).digest() + os.urandom(736)  # 800 bytes total
            return public_key, secret_key
        
        @staticmethod
        def enc(public_key):
            """Encapsulate shared secret (Kyber-512 sizes)"""
            # Generate random 32-byte shared secret
            shared_secret = os.urandom(32)
            # Create ciphertext (768 bytes for Kyber-512)
            # In real Kyber: ciphertext contains encrypted message
            ciphertext_data = hashlib.sha3_256(public_key + shared_secret).digest()
            ciphertext = ciphertext_data + os.urandom(768 - len(ciphertext_data))
            return ciphertext, shared_secret
        
        @staticmethod
        def dec(ciphertext, secret_key):
            """Decapsulate shared secret"""
            # Derive shared secret from ciphertext and secret key
            # In real Kyber: polynomial operations recover the secret
            shared_secret = hashlib.sha3_256(secret_key[:32] + ciphertext[:32]).digest()
            return shared_secret
    
    kyber = KyberSimulation()

app = Flask(__name__)

# Simulate stored keys (in real Apple Pay, these would be in Secure Element)
MERCHANT_KYBER_KEYS = {}
DEVICE_KEYS = {}

def initialize_keys():
    """Initialize cryptographic keys for demonstration"""
    # Generate Kyber keypair for key establishment
    public_key, secret_key = kyber.keypair()
    MERCHANT_KYBER_KEYS['public'] = public_key
    MERCHANT_KYBER_KEYS['secret'] = secret_key
    
    # Generate ChaCha20-Poly1305 key for transaction encryption
    DEVICE_KEYS['chacha_key'] = ChaCha20Poly1305.generate_key()

initialize_keys()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/payment", methods=["POST"])
def process_payment():
    try:
        data = request.json
        amount = data.get('amount', '0.00')
        merchant = data.get('merchant', 'Unknown Merchant')
        card_last4 = data.get('card_last4', '****')
        
        # Create transaction data
        transaction_data = {
            'amount': amount,
            'merchant': merchant,
            'card_last4': card_last4,
            'timestamp': datetime.now().isoformat(),
            'transaction_id': os.urandom(8).hex()
        }
        
        plaintext = json.dumps(transaction_data).encode('utf-8')
        
        # Step 1: CRYSTALS-Kyber - Establish shared secret (simulates secure key exchange)
        # In real Apple Pay, this would be used to establish a secure session with the payment terminal
        kyber_ciphertext, shared_secret_alice = kyber.enc(MERCHANT_KYBER_KEYS['public'])
        shared_secret_bob = kyber.dec(kyber_ciphertext, MERCHANT_KYBER_KEYS['secret'])
        
        # Verify both parties have the same shared secret
        kyber_verification = shared_secret_alice == shared_secret_bob
        
        # Step 2: ChaCha20-Poly1305 - Encrypt actual payment data
        # Uses the symmetric key to encrypt transaction details
        chacha = ChaCha20Poly1305(DEVICE_KEYS['chacha_key'])
        nonce = os.urandom(12)
        encrypted_payment = chacha.encrypt(nonce, plaintext, None)
        
        # Decrypt to verify (simulates merchant receiving and decrypting)
        decrypted_payment = chacha.decrypt(nonce, encrypted_payment, None)
        decrypted_data = json.loads(decrypted_payment.decode('utf-8'))
        
        # Prepare response with detailed cryptographic information
        response = {
            'success': True,
            'transaction': transaction_data,
            'cryptography': {
                'kyber': {
                    'description': 'Post-Quantum Key Encapsulation Mechanism',
                    'implementation': 'Real Kyber (liboqs)' if USING_REAL_KYBER else 'Educational Simulation',
                    'purpose': 'Establishes shared secret between device and merchant',
                    'ciphertext_length': len(kyber_ciphertext),
                    'shared_secret_length': len(shared_secret_alice),
                    'verification': 'Shared secrets match' if kyber_verification else 'Mismatch',
                    'ciphertext_preview': kyber_ciphertext[:32].hex() + '...',
                    'shared_secret_preview': shared_secret_alice[:16].hex() + '...'
                },
                'chacha20_poly1305': {
                    'description': 'Authenticated Encryption with Associated Data (AEAD)',
                    'purpose': 'Encrypts transaction data with authentication',
                    'plaintext': plaintext.decode('utf-8'),
                    'ciphertext_length': len(encrypted_payment),
                    'nonce': nonce.hex(),
                    'ciphertext_preview': encrypted_payment[:32].hex() + '...',
                    'decrypted': decrypted_data,
                    'authenticated': True
                }
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/key-info", methods=["GET"])
def get_key_info():
    """Endpoint to display key information for educational purposes"""
    return jsonify({
        'kyber': {
            'algorithm': 'CRYSTALS-Kyber-512',
            'type': 'Post-Quantum KEM',
            'public_key_size': len(MERCHANT_KYBER_KEYS['public']),
            'secret_key_size': len(MERCHANT_KYBER_KEYS['secret']),
            'security_level': 'NIST Level 1 (128-bit quantum security)',
            'purpose': 'Quantum-resistant key establishment'
        },
        'chacha20_poly1305': {
            'algorithm': 'ChaCha20-Poly1305',
            'type': 'AEAD Cipher',
            'key_size': len(DEVICE_KEYS['chacha_key']) * 8,
            'nonce_size': 96,
            'tag_size': 128,
            'purpose': 'Fast, secure authenticated encryption'
        }
    })

if __name__ == "__main__":
    app.run(debug=True)