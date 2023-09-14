from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
import random
import string

app = Flask(__name__)

@app.route('/')
def home():
    data_policy = "Our mission is to provide you with the tools and knowledge you need to safeguard your online presence."
    return render_template('home.html')


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
            prefix = ''.join(random.choices(string.ascii_lowercase, k=3))
            suffix = ''.join(random.choices(string.digits, k=3))
            username = prefix + suffix
        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('username_generator.html', username=username, error_message=error_message)

@app.route('/email_generator', methods=['GET', 'POST'])
def email_generator():
    email = None
    error_message = None

    if request.method == 'POST':
        try:
            domain = request.form['domain']
            prefix = ''.join(random.choices(string.ascii_lowercase, k=5))
            suffix = ''.join(random.choices(string.digits, k=3))
            email = prefix + suffix + "@" + domain
        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = "An unexpected error occurred. Please try again."

    return render_template('email_generator.html', email=email, error_message=error_message)
if __name__ == '__main__':
    app.run(debug=True)
