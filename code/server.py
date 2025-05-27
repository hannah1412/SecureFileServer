from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Set the directory where uploaded files will be saved
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    keys = request.form.get('keys')
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Saving encrypyted symmetric keys on server
        # keys_path = os.path.join(KEY_FOLDER, f"{file.filename}.keys.json")
        # with open(keys_path, 'w') as key_file:
        #     key_file.write(keys)
            
        return jsonify({"message": f"File '{file.filename}' uploaded successfully"}), 200
    if not file.filename.endswith('.enc'):
        return jsonify({"error" :  "Please encrypt your file before uploading! Correct file format ends with '.enc"}) , 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
