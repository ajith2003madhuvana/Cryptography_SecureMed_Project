import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64

# Function to pad data for AES encryption
def pad(data):
    block_size = 16
    return data + b"\0" * (block_size - len(data) % block_size)

# Function to encrypt the image
def encrypt_image(key, image_data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(image_data)
    encrypted_data = cipher.encrypt(padded_data)
    return iv, encrypted_data

# Generate RSA key pair
if "private_key" not in st.session_state:
    rsa_key = RSA.generate(2048)
    st.session_state.private_key = rsa_key.export_key()
    st.session_state.public_key = rsa_key.publickey().export_key()

st.title("Image Encryption with AES, RSA, and HMAC")
st.sidebar.header("Key Management")
st.sidebar.download_button(
    "Download Private Key",
    st.session_state.private_key,
    "rsa_private_key.pem",
    mime="application/octet-stream"
)
st.sidebar.text_area("Public Key (Share this for decryption):", 
                     st.session_state.public_key.decode(), height=150)

# File uploader
uploaded_file = st.file_uploader("Upload an image to encrypt", type=["jpg", "png", "jpeg"])

if uploaded_file is not None:
    image_data = uploaded_file.read()
    st.image(image_data, caption="Original Image", use_column_width=True)

    if st.button("Encrypt Image"):
        # Generate AES key
        aes_key = get_random_bytes(16)

        # Encrypt AES key with RSA public key
        recipient_key = RSA.import_key(st.session_state.public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Encrypt image data with AES
        iv, encrypted_data = encrypt_image(aes_key, image_data)

        # Generate HMAC for data integrity
        hmac = HMAC.new(aes_key, iv + encrypted_data, SHA256).digest()

        # Bundle the encrypted data
        output = {
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "hmac": base64.b64encode(hmac).decode(),
        }

        st.text_area("Encrypted Data Bundle:", str(output), height=200)
        st.download_button("Download Encrypted Data", str(output).encode(), "encrypted_data.txt")
