import os

from functions import preprocess_data, result_jsons

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

MODEL_PATH = ""
#model = pickle.load(open(MODEL_PATH, "rb"))

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload_apk', methods=['POST'])
def upload_apk_and_get_data():

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    df = preprocess_data(file_path, filename)
    result_json = result_jsons(df, file_path, "benign")
    
    return jsonify({'results': result_json})

if __name__ == '__main__':
    app.run(debug=True)

