from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import cv2
import numpy as np
import pickle
import os
import zipfile
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# RSA key pairs
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()

def add_watermark(image, text="ENCRYPTED"):
    h, w = image.shape[:2]
    
    # Create a copy of the image
    watermarked = image.copy()
    
    # Calculate diagonal length
    diagonal_length = int(np.sqrt(h*h + w*w))
    
    # Calculate font scale based on image size (adjust for larger text)
    font_scale = diagonal_length / 500  # Increased from 1000 to 500 for larger text
    thickness = max(2, int(font_scale * 2))
    
    # Use a simpler font for better readability
    font = cv2.FONT_HERSHEY_SIMPLEX
    
    # Get text size
    (text_width, text_height), baseline = cv2.getTextSize(text, font, font_scale, thickness)
    
    # Create a blank image for the text
    text_overlay = np.zeros((h, w, 3), dtype=np.uint8)
    
    # Calculate center position
    text_x = (w - text_width) // 2
    text_y = (h + text_height) // 2
    
    # Draw text in light grey (200, 200, 200)
    cv2.putText(text_overlay, text, (text_x, text_y), font, font_scale, (200, 200, 200), thickness)
    
    # Calculate rotation matrix for diagonal placement
    angle = np.arctan2(h, w) * 180 / np.pi
    rotation_matrix = cv2.getRotationMatrix2D((w/2, h/2), angle, 1.0)
    
    # Rotate the text overlay
    rotated_text = cv2.warpAffine(text_overlay, rotation_matrix, (w, h))
    
    # Blend the rotated text with the original image
    alpha = 0.3  # Transparency level (0.3 = 30% opacity)
    watermarked = cv2.addWeighted(watermarked, 1, rotated_text, alpha, 0)
    
    return watermarked

def encrypt_image(image_path, output_dir='encrypted_files', watermark_text="By Harbir :)"):
    os.makedirs(output_dir, exist_ok=True)
    image = cv2.imread(image_path)
    watermarked_image = add_watermark(image, watermark_text)
    
    _, img_bytes = cv2.imencode('.png', watermarked_image)
    aes_key = get_random_bytes(16)
    
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    encrypted_image, tag = cipher_aes.encrypt_and_digest(img_bytes.tobytes())
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    encrypted_data = {
        'image': encrypted_image,
        'aes_key': encrypted_aes_key,
        'nonce': nonce,
        'tag': tag
    }
    
    encrypted_file_path = os.path.join(output_dir, 'encrypted_image.bin')
    private_key_path = os.path.join(output_dir, 'private_key.pem')
    public_key_path = os.path.join(output_dir, 'public_key.pem')
    
    with open(encrypted_file_path, 'wb') as f:
        pickle.dump(encrypted_data, f)
    
    with open(public_key_path, 'wb') as f:
        f.write(public_key.export_key())
    with open(private_key_path, 'wb') as f:
        f.write(rsa_key.export_key())
    
    return encrypted_file_path, private_key_path

def decrypt_image(encrypted_file, private_key_file, output_file='decrypted_image.jpg'):
    with open(encrypted_file, 'rb') as f:
        data = pickle.load(f)
    
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(data['aes_key'])
    
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=data['nonce'])
    decrypted_bytes = cipher_aes.decrypt_and_verify(data['image'], data['tag'])
    
    img_array = np.frombuffer(decrypted_bytes, np.uint8)
    image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    
    cv2.imwrite(output_file, image)
    return output_file

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        if 'image' not in request.files:
            return render_template('index.html', message='No image uploaded', message_type='error')
        
        image = request.files['image']
        watermark = request.form.get('watermark', 'By Harbir :)')
        
        if image.filename == '':
            return render_template('index.html', message='No image selected', message_type='error')
        
        filename = secure_filename(image.filename)
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(image_path)
        
        encrypted_path, private_key_path = encrypt_image(image_path, ENCRYPTED_FOLDER, watermark)
        
        # Create a ZIP file in memory
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            # Add encrypted image file
            zf.write(encrypted_path, 'encrypted_image.bin')
            # Add private key file
            zf.write(private_key_path, 'private_key.pem')
        
        # Seek to the beginning of the BytesIO object
        memory_file.seek(0)
        
        # Return the ZIP file
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='encrypted_package.zip'
        )
    
    except Exception as e:
        return render_template('index.html', message=f'Error: {str(e)}', message_type='error')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'encrypted_file' not in request.files or 'private_key' not in request.files:
            return render_template('index.html', message='Missing required files', message_type='error')
        
        encrypted_file = request.files['encrypted_file']
        private_key = request.files['private_key']
        
        encrypted_path = os.path.join(UPLOAD_FOLDER, secure_filename(encrypted_file.filename))
        private_key_path = os.path.join(UPLOAD_FOLDER, secure_filename(private_key.filename))
        
        encrypted_file.save(encrypted_path)
        private_key.save(private_key_path)
        
        output_path = os.path.join(UPLOAD_FOLDER, 'decrypted_image.jpg')
        decrypted_path = decrypt_image(encrypted_path, private_key_path, output_path)
        
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name='decrypted_image.jpg'
        )
    
    except Exception as e:
        return render_template('index.html', message=f'Error: {str(e)}', message_type='error')

if __name__ == '__main__':
    app.run(debug=True)