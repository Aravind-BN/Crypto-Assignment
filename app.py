from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import json
from datetime import datetime
import hashlib

# Educational CRYSTALS-Kyber simulation for assignment purposes
class KyberSimulation:
    @staticmethod
    # STEP 1: Key Generation
    def keypair():
        secret_key = os.urandom(1632)  # Kyber-512 secret key size
        # Public key derived from secret (simplified version for demonstration)
        public_key = hashlib.sha3_512(secret_key).digest() + os.urandom(736)  # 800 bytes total
        return public_key, secret_key
    
    @staticmethod
    #Step 2: Encryption/ Encapsulation of public say -> shared_secret_A
    def enc(public_key):
        # Generate random 32-byte shared secret
        shared_secret = os.urandom(32)
        # Create ciphertext (768 bytes for Kyber-512)
        # First 32 bytes of ciphertext contain info to recover shared secret
        ciphertext = shared_secret + os.urandom(768 - 32)
        return ciphertext, shared_secret
    
    @staticmethod
    # Step 3: Decryption/ Decapsultation of ciphertext + secret_key -> shared_secret_B
    def dec(ciphertext, secret_key):
        # Extract the shared secret from ciphertext (first 32 bytes)
        shared_secret = ciphertext[:32]
        return shared_secret

kyber = KyberSimulation()

app = Flask(__name__)

# Simulate stored keys (in real Apple Pay, these would be in Secure Element and wouldn't be revealed easily)
MERCHANT_KYBER_KEYS = {}
DEVICE_KEYS = {}

# Initializing DUMMY keys for demonstration
def initialize_keys():
    # Generate dummy Kyber keypair for key establishment
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
        
        # Creation of Transaction Data (to be encrypted)
        transaction_data = {
            'amount': amount,
            'merchant': merchant,
            'card_last4': card_last4,
            'timestamp': datetime.now().isoformat(),
            'transaction_id': os.urandom(8).hex()
        }
        
        plaintext = json.dumps(transaction_data).encode('utf-8')
        
        # Step 1: CRYSTALS-Kyber - Establish shared secret (simulates secure key exchange)
        kyber_ciphertext, shared_secret_alice = kyber.enc(MERCHANT_KYBER_KEYS['public'])
        shared_secret_bob = kyber.dec(kyber_ciphertext, MERCHANT_KYBER_KEYS['secret'])
        
        # Check whether both shared secrets match 
        kyber_verification = shared_secret_alice == shared_secret_bob
        
        # Step 2: ChaCha20-Poly1305 - Encrypt actual payment data
        # Uses the symmetric key to encrypt transaction details
        chacha = ChaCha20Poly1305(DEVICE_KEYS['chacha_key'])
        nonce = os.urandom(12) # 96-bit nonce for ChaCha20-Poly1305, will be regenerated every transaction for security
        encrypted_payment = chacha.encrypt(nonce, plaintext, None)
        
        # Decryption
        decrypted_payment = chacha.decrypt(nonce, encrypted_payment, None)
        decrypted_data = json.loads(decrypted_payment.decode('utf-8'))
        
        # Responses for viewing in the app
        response = {
            'success': True,
            'transaction': transaction_data,
            'keys': {
                'kyber_public_key': MERCHANT_KYBER_KEYS['public'].hex(),
                'kyber_secret_key': MERCHANT_KYBER_KEYS['secret'].hex(),
                'chacha_key': DEVICE_KEYS['chacha_key'].hex()
            },
            'cryptography': {
                'kyber': {
                    'description': 'Post-Quantum Key Encapsulation Mechanism',
                    'implementation': 'Educational Simulation',
                    'purpose': 'Establishes shared secret between device and merchant',
                    'ciphertext_length': len(kyber_ciphertext),
                    'ciphertext_full': kyber_ciphertext.hex(),
                    'shared_secret_alice': shared_secret_alice.hex(),
                    'shared_secret_bob': shared_secret_bob.hex(),
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
                    'ciphertext_full': encrypted_payment.hex(),
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

# Key Information Reveal
def get_key_info():
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