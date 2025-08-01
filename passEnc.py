import bcrypt

# User's raw password input
password = input("Enter your password: ")

# Convert to bytes
password_bytes = password.encode('utf-8')

# Generate salt
salt = bcrypt.gensalt()

# Hash the password
hashed_password = bcrypt.hashpw(password_bytes, salt)

# Store hashed_password (save in DB, etc.)
print("Encrypted password:", hashed_password)

# Check password later (e.g., during login)
check_password = input("Re-enter password to check: ").encode('utf-8')

if bcrypt.checkpw(check_password, hashed_password):
    print("✅ Password match")
else:
    print("❌ Incorrect password")
