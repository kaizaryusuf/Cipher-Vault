from flask import Flask, request, render_template, redirect, url_for, flash, jsonify # type: ignore
import subprocess
import os
import sys

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Needed for flashing messages

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_tkinter', methods=['POST'])
def run_tkinter():
    # Get the message from the form
    message = request.form.get('message', '')

    # Check if the message is empty
    if not message:
        return jsonify({'status': 'error', 'message': 'Please enter a message'}), 400

    try:
        # Get the Python executable path
        python_exe = sys.executable
        
        # Call the Tkinter script with the provided message
        process = subprocess.Popen([python_exe, 'mini.py', message], 
                                 creationflags=subprocess.CREATE_NEW_CONSOLE)
        
        return jsonify({'status': 'success', 'message': 'Tkinter app launched successfully!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error launching Tkinter app: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(debug=True)