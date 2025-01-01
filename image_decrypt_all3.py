import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
import base64
import ast

# Function to decrypt the image
def decrypt_image(key, iv, encrypted_data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.rstrip(b"\0")

st.title("Image Decryption with AES, RSA, and HMAC")
st.sidebar.header("Provide the Private Key")

# File uploader for private key
private_key_file = st.sidebar.file_uploader("Upload your private key (PEM format):")

# Encrypted data input
encrypted_data_input = st.text_area("Paste the encrypted data bundle:")

if st.button("Decrypt Image") and private_key_file and encrypted_data_input:
    try:
        # Load private key
        private_key = RSA.import_key(private_key_file.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Parse the encrypted data bundle
        data_bundle = ast.literal_eval(encrypted_data_input)
        encrypted_key = base64.b64decode(data_bundle["encrypted_key"])
        iv = base64.b64decode(data_bundle["iv"])
        encrypted_data = base64.b64decode(data_bundle["encrypted_data"])
        hmac_received = base64.b64decode(data_bundle["hmac"])

        # Decrypt AES key
        aes_key = cipher_rsa.decrypt(encrypted_key)

        # Verify HMAC
        hmac = HMAC.new(aes_key, iv + encrypted_data, SHA256)
        hmac.verify(hmac_received)

        # Decrypt image data
        decrypted_data = decrypt_image(aes_key, iv, encrypted_data)

        st.image(decrypted_data, caption="Decrypted Image", use_column_width=True)
        st.download_button("Download Decrypted Image", decrypted_data, "decrypted_image.png")

    except Exception as e:
        st.error(f"Decryption or HMAC verification failed: {e}")
