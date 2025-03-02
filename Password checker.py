import re
import math
import json
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class PasswordPolicy:
    def __init__(self):
        self.min_length = 8
        self.min_score = 3
        self.special_chars = "!@#$%^&*(),.?\":{}|<>"
        self.common_passwords_file = Path(__file__).parent / "common_passwords.txt"

    def load_common_passwords(self):
        try:
            with open(self.common_passwords_file, 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return set()

class PasswordStrengthChecker:
    def __init__(self):
        self.policy = PasswordPolicy()
        self.common_passwords = self.policy.load_common_passwords()
        
    def calculate_entropy(self, password):
        char_set_size = 0
        if re.search(r'[a-z]', password): char_set_size += 26
        if re.search(r'[A-Z]', password): char_set_size += 26
        if re.search(r'\d', password): char_set_size += 10
        if re.search(f'[{re.escape(self.policy.special_chars)}]', password): 
            char_set_size += len(self.policy.special_chars)
        
        return len(password) * math.log2(max(char_set_size, 1))

    def check_password_strength(self, password):
        score = 0
        feedback = []
        details = {
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_numbers': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(f'[{re.escape(self.policy.special_chars)}]', password)),
        }

        # Basic checks
        if details['length'] < self.policy.min_length:
            feedback.append(f"Password must be at least {self.policy.min_length} characters long")
        else:
            score += 1

        # Character composition checks
        if not details['has_lowercase']: feedback.append("Include lowercase letters")
        else: score += 1
        if not details['has_uppercase']: feedback.append("Include uppercase letters")
        else: score += 1
        if not details['has_numbers']: feedback.append("Include numbers")
        else: score += 1
        if not details['has_special']: feedback.append("Include special characters")
        else: score += 1

        # Advanced checks
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("This is a commonly used password")

        if details['entropy'] < 50:
            feedback.append("Password is not complex enough")
        elif details['entropy'] >= 70 and score < 6:
            score += 1

        # Sequential and repeated characters
        if re.search(r'(.)\1{2,}', password):
            feedback.append("Avoid repeated characters")
            score = max(0, score - 1)

        if re.search(r'(abc|123|qwe|password)', password.lower()):
            feedback.append("Avoid common patterns")
            score = max(0, score - 1)

        # Cap the score at 6
        score = min(6, score)

        # Determine strength level
        strength = "Weak"
        if score >= 5:
            strength = "Strong"
        elif score >= self.policy.min_score:
            strength = "Moderate"

        return {
            'strength': strength,
            'score': score,
            'entropy': round(details['entropy'], 2),
            'feedback': feedback,
            'details': details
        }

class PasswordEncryption:
    def __init__(self):
        self.salt = os.urandom(16)
        self.key = self._generate_key()
        self.cipher_suite = Fernet(self.key)

    def _generate_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"secret_key"))
        return key

    def encrypt_password(self, password):
        try:
            encrypted_password = self.cipher_suite.encrypt(password.encode())
            return True, encrypted_password
        except Exception as e:
            return False, str(e)

def main():
    checker = PasswordStrengthChecker()
    encryptor = PasswordEncryption()
    print("Professional Password Strength Analyzer with Encryption")
    print("=" * 50)
    
    while True:
        password = input("\nEnter a password to analyze (or 'q' to quit): ")
        if password.lower() == 'q':
            break
            
        # Check password strength
        result = checker.check_password_strength(password)
        
        # Encrypt password
        encryption_success, encrypted_data = encryptor.encrypt_password(password)
        
        print(f"\nAnalysis Results:")
        print(f"Strength: {result['strength']}")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Score: {result['score']}/6")
        
        print(f"\nEncryption Status:")
        if encryption_success:
            print("✓ Password successfully encrypted with AES-256")
        else:
            print("✗ Password encryption failed")
        
        if result['feedback']:
            print("\nRecommendations:")
            for suggestion in result['feedback']:
                print(f"• {suggestion}")

if __name__ == "__main__":
    main()
