# ...existing code...

class PasswordPolicy:
    def __init__(self):
        self.min_length = 8
        self.min_score = 3
        self.special_chars = "!@#$%^&*(),.?\":{}|<>"
        self.common_passwords_file = Path(__file__).parent / "data" / "common_passwords.txt"

# ...existing code...
