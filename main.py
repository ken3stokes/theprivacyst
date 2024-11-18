from flask import Flask, render_template, request, jsonify
from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
import random
import string
import hashlib
import re
import math
from hashlib import sha3_256, sha3_512

app = Flask(__name__)

@app.route('/')
def home():
    data_policy = "Our mission is to provide you with the tools and knowledge you need to safeguard your online presence."
    return render_template('index.html')

@app.route('/release_notes')
def release_notes():
    return render_template('release_notes.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/user_guide')
def user_guide():
    return render_template('user_guide.html')

@app.route('/ssh_key_generator', methods=['GET', 'POST'])
def ssh_key_generator():
    private_key = None
    public_key = None
    error_message = None

    if request.method == 'POST':
        try:
            key_length = int(request.form.get('key_length', 2048))
            if key_length not in [2048, 4096]:
                raise ValueError("Invalid key length. Valid options are 2048 and 4096.")

            key_type = request.form.get('key_type', 'RSA')
            if key_type not in ['RSA', 'DSA', 'ECDSA', 'Ed25519']:
                raise ValueError("Invalid key type. Valid options are RSA, DSA, ECDSA, and Ed25519.")

            if key_type == 'RSA':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_length,
                    backend=default_backend()
                )
            elif key_type == 'DSA':
                key = dsa.generate_private_key(
                    key_size=key_length,
                    backend=default_backend()
                )
            elif key_type == 'ECDSA':
                key = ec.generate_private_key(
                    ec.SECP256R1(),
                    backend=default_backend()
                )
            elif key_type == 'Ed25519':
                key = Ed25519PrivateKey.generate()

            private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except ValueError as e:
            error_message = str(e)
        except Exception as e:
            print(f"An error occurred while generating or extracting keys: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('ssh_key_generator.html', private_key=private_key, public_key=public_key, error_message=error_message)

@app.route('/password_calculator', methods=['GET', 'POST'])
def password_calculator():
    password = None
    error_message = None

    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12))

            # Validate the length to be within acceptable limits
            if not 8 <= length <= 128:
                error_message = "Length should be between 8 and 128."
                raise ValueError(error_message)

            include_uppercase = request.form.get('include_uppercase') == 'on'
            include_lowercase = request.form.get('include_lowercase') == 'on'
            include_digits = request.form.get('include_digits') == 'on'
            include_special_chars = request.form.get('include_special_chars') == 'on'

            characters = ''
            if include_uppercase:
                characters += string.ascii_uppercase
            if include_lowercase:
                characters += string.ascii_lowercase
            if include_digits:
                characters += string.digits
            if include_special_chars:
                characters += string.punctuation

            if characters:
                password = ''.join(random.choice(characters) for _ in range(length))
            else:
                error_message = "Please select at least one character type."
        except ValueError as e:
            # Catch the ValueError raised in case of incorrect length
            print(f"A value error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('password_calculator.html', password=password, error_message=error_message)

@app.route('/username_generator', methods=['GET', 'POST'])
def username_generator():
    username = None
    error_message = None

    if request.method == 'POST':
        try:
            style = request.form.get('style', 'quantum')
            include_numbers = request.form.get('numbers') == 'on'
            include_special = request.form.get('special') == 'on'
            make_memorable = request.form.get('memorable') == 'on'

            # Define character sets
            letters = string.ascii_lowercase
            numbers = string.digits if include_numbers else ''
            specials = '_-.' if include_special else ''
            chars = letters + numbers + specials

            # Generate username based on style
            if style == 'quantum':
                prefix = ''.join(random.choices(letters, k=3))
                suffix = ''.join(random.choices(string.digits, k=3)) if include_numbers else ''
                username = f"q_{prefix}{suffix}"
            elif style == 'neural':
                adjectives = ['quantum', 'neural', 'cyber', 'digital', 'crypto']
                nouns = ['mind', 'net', 'byte', 'bit', 'hash']
                username = f"{random.choice(adjectives)}_{random.choice(nouns)}"
                if include_numbers:
                    username += str(random.randint(100, 999))
            elif style == 'classic':
                username = ''.join(random.choices(chars, k=8))
            else:  # random style
                length = random.randint(8, 12)
                username = ''.join(random.choices(chars, k=length))

        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('username_generator.html', username=username, error_message=error_message)

@app.route('/hash_generator', methods=['GET', 'POST'])
def hash_generator():
    hash_result = None
    error_message = None

    if request.method == 'POST':
        try:
            algorithm = request.form.get('algorithm', 'sha256')
            input_text = request.form.get('input_text', '')

            if not input_text:
                raise ValueError("Input text cannot be empty")

            # Convert input to bytes
            input_bytes = input_text.encode('utf-8')

            # Generate hash based on selected algorithm
            if algorithm == 'md5':
                hash_obj = hashlib.md5(input_bytes)
            elif algorithm == 'sha1':
                hash_obj = hashlib.sha1(input_bytes)
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256(input_bytes)
            elif algorithm == 'sha384':
                hash_obj = hashlib.sha384(input_bytes)
            elif algorithm == 'sha512':
                hash_obj = hashlib.sha512(input_bytes)
            elif algorithm == 'sha3_256':
                hash_obj = sha3_256(input_bytes)
            elif algorithm == 'sha3_512':
                hash_obj = sha3_512(input_bytes)
            else:
                raise ValueError("Invalid hash algorithm selected")

            hash_result = hash_obj.hexdigest()

        except Exception as e:
            error_message = str(e)

    return render_template('hash_generator.html',
                         hash_result=hash_result,
                         error_message=error_message)

@app.route('/password_strength', methods=['GET'])
def password_strength():
    return render_template('password_strength.html')


@app.route('/api/analyze_password', methods=['POST'])
def analyze_password():
    data = request.get_json()
    password = data.get('password', '')

    # Base score starts at 0
    score = 0
    recommendations = []

    # Length analysis (more stringent)
    length = len(password)
    if length < 8:
        length_analysis = f"Length: {length} characters (Very Weak)"
        recommendations.append("Password is too short. Use at least 12 characters")
        score += length * 2
    elif length < 12:
        length_analysis = f"Length: {length} characters (Weak)"
        recommendations.append("Increase length to at least 12 characters for better security")
        score += length * 3
    elif length < 16:
        length_analysis = f"Length: {length} characters (Moderate)"
        recommendations.append("Consider using 16+ characters for maximum security")
        score += length * 4
    else:
        length_analysis = f"Length: {length} characters (Good)"
        score += 50  # Reward good length more significantly

    # Character mix analysis (more detailed)
    uppercase_count = sum(1 for c in password if c.isupper())
    lowercase_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    special_count = sum(1 for c in password if not c.isalnum())

    char_types = []
    if uppercase_count: char_types.append(f"{uppercase_count} uppercase")
    if lowercase_count: char_types.append(f"{lowercase_count} lowercase")
    if digit_count: char_types.append(f"{digit_count} numbers")
    if special_count: char_types.append(f"{special_count} special")

    char_analysis = f"Contains: {', '.join(char_types)}"

    # More stringent character requirements
    if uppercase_count < 2:
        recommendations.append("Add more uppercase letters (at least 2)")
    if lowercase_count < 2:
        recommendations.append("Add more lowercase letters (at least 2)")
    if digit_count < 2:
        recommendations.append("Add more numbers (at least 2)")
    if special_count < 2:
        recommendations.append("Add more special characters (at least 2)")

    # Score character mix (weighted scoring)
    score += min(uppercase_count * 2, 10)  # Up to 10 points
    score += min(lowercase_count * 2, 10)  # Up to 10 points
    score += min(digit_count * 2, 10)  # Up to 10 points
    score += min(special_count * 3, 15)  # Up to 15 points (weighted more)

    # Enhanced pattern analysis
    patterns = []
    deductions = 0

    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        patterns.append("Repeated characters")
        deductions += 15

    # Check for sequential characters
    if any(str(i) + str(i + 1) + str(i + 2) in password for i in range(8)):
        patterns.append("Sequential numbers")
        deductions += 15

    if any(chr(i) + chr(i + 1) + chr(i + 2) in password.lower() for i in range(ord('a'), ord('x'))):
        patterns.append("Sequential letters")
        deductions += 15

    # Check for common patterns
    common_patterns = [
        r'password', r'123', r'abc', r'qwerty', r'admin', r'letmein',
        r'welcome', r'monkey', r'\d{4}', r'(19|20)\d{2}'  # Years and 4-digit numbers
    ]

    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            patterns.append("Common password pattern")
            deductions += 20
            break

    # Word patterns (simplified - you might want to add more)
    common_words = ['password', 'admin', 'welcome', 'monkey', 'dragon', 'master']
    for word in common_words:
        if word in password.lower():
            patterns.append(f"Common word: {word}")
            deductions += 20

    pattern_analysis = "No obvious patterns found" if not patterns else f"Found: {', '.join(patterns)}"
    score = max(0, score - deductions)  # Apply pattern deductions

    # Enhanced crack time estimation
    char_space = 0
    if uppercase_count: char_space += 26
    if lowercase_count: char_space += 26
    if digit_count: char_space += 10
    if special_count: char_space += 32

    combinations = char_space ** length
    # Modern computer can try about 10 billion passwords per second
    crack_attempts_per_second = 10_000_000_000

    seconds_to_crack = combinations / crack_attempts_per_second

    if seconds_to_crack < 60:
        crack_time = "Instant"
        recommendations.append("❗ This password can be cracked instantly!")
    elif seconds_to_crack < 3600:
        crack_time = f"About {math.ceil(seconds_to_crack / 60)} minutes"
        recommendations.append("❗ This password can be cracked in less than an hour!")
    elif seconds_to_crack < 86400:
        crack_time = f"About {math.ceil(seconds_to_crack / 3600)} hours"
        recommendations.append("Consider a stronger password")
    elif seconds_to_crack < 31536000:
        crack_time = f"About {math.ceil(seconds_to_crack / 86400)} days"
    elif seconds_to_crack < 31536000 * 100:
        crack_time = f"About {math.ceil(seconds_to_crack / 31536000)} years"
    else:
        crack_time = "Over 100 years"

    # Final score adjustments
    if seconds_to_crack < 86400:  # Less than a day
        score = min(score, 40)
    elif seconds_to_crack > 31536000:  # More than a year
        score = max(score, 60)

    # Final score categorization
    if score < 40:
        recommendations.insert(0, "❗ This password is very weak and needs significant improvement")
    elif score < 60:
        recommendations.insert(0, "This password needs improvement")
    elif score < 80:
        recommendations.insert(0, "This is a decent password but could be stronger")

    # Add general recommendations if score isn't perfect
    if score < 100:
        recommendations.append("Consider using a random password generator")
        recommendations.append("Mix uppercase, lowercase, numbers, and special characters more evenly")

    return jsonify({
        'score': round(score),
        'length_analysis': length_analysis,
        'char_analysis': char_analysis,
        'pattern_analysis': pattern_analysis,
        'crack_time': f"Estimated time to crack: {crack_time}",
        'recommendations': recommendations
    })


@app.route('/email_generator', methods=['GET', 'POST'])
def email_generator():
    email = None
    error_message = None

    # Common first names
    first_names = [
        'james', 'john', 'robert', 'michael', 'william', 'david',
        'emma', 'olivia', 'ava', 'sophia', 'isabella', 'mia',
        'alexander', 'benjamin', 'daniel', 'ethan', 'henry', 'jacob',
        'charlotte', 'amelia', 'harper', 'evelyn', 'abigail', 'emily',
        'liam', 'noah', 'oliver', 'elijah', 'lucas', 'mason',
        'sophia', 'isabella', 'emma', 'olivia', 'ava', 'mia',
        'aiden', 'owen', 'gabriel', 'caleb', 'nathan', 'isaac',
        'elizabeth', 'sofia', 'victoria', 'madison', 'luna', 'grace'
    ]
    
    # Common last names
    last_names = [
        'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia',
        'miller', 'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez',
        'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson',
        'martin', 'lee', 'perez', 'thompson', 'white', 'harris',
        'sanchez', 'clark', 'ramirez', 'lewis', 'robinson', 'walker',
        'young', 'allen', 'king', 'wright', 'scott', 'torres',
        'nguyen', 'hill', 'flores', 'green', 'adams', 'nelson',
        'baker', 'hall', 'rivera', 'campbell', 'mitchell', 'carter'
    ]

    if request.method == 'POST':
        try:
            domain = request.form['domain']
            
            # Different email styles
            style = random.choice([
                'first.last',        # e.g., john.smith42
                'first_initial.last',  # e.g., j.smith123
                'firstlast',         # e.g., johnsmith789
                'last.first'         # e.g., smith.john456
            ])
            
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            
            if style == 'first.last':
                prefix = f"{first_name}.{last_name}"
            elif style == 'first_initial.last':
                prefix = f"{first_name[0]}.{last_name}"
            elif style == 'firstlast':
                prefix = f"{first_name}{last_name}"
            else:  # last.first
                prefix = f"{last_name}.{first_name}"

            # Add a random number (2-3 digits to keep it realistic)
            suffix = str(random.randint(10, 999))
            
            # Ensure the email looks clean and professional
            email = f"{prefix}{suffix}@{domain}"
            
            # Convert to lowercase and replace spaces with dots
            email = email.lower().replace(' ', '.')
            
        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('email_generator.html', email=email, error_message=error_message)
if __name__ == '__main__':
    app.run(debug=True)
