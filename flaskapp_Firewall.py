from flask import Flask, render_template, request, jsonify
import subprocess
import os
import mysql.connector
from scapy.all import *
import csv

app = Flask(__name__)

last_packet_time = {}


# Initialize IDS status, mode, and process
ids_status = False
ids_mode = "normal"  # Possible values: "aggressive", "normal", "detection"
ids_process = None

ufw_commands = {
    'Home': 'allow 443',
    'Work': 'allow 80',
    'Default': 'allow 22',
    'Cafe': 'allow 80',
    'Public Network': 'default deny',
    'AI Suggested': 'limit 22/tcp',
}



@app.route('/')
def index():
    return render_template('ids.html')

@app.route('/firewall.html')
def firewall():
    return render_template('firewall.html')
    
    
    
    
@app.route('/enable-Custom-firewall', methods=['POST'])
def enable_Custom_firewall():
    try:
        # Your implementation to enable the firewall (e.g., using subprocess)
        subprocess.run(['ufw', 'enable'], check=True)
        return {"status": "Firewall enabled"}  # Return a success message or any relevant data
    except Exception as e:
        return {"error": str(e)}  # Return an error message in case of failure

# Function to disable UFW firewall
@app.route('/disable-Custom-firewall', methods=['POST'])
def disable_Cusom_firewall():
    try:
        # Your implementation to disable the firewall (e.g., using subprocess)
        subprocess.run(['ufw', 'disable'], check=True)
        return {"status": "Firewall disabled"}  # Return a success message or any relevant data
    except Exception as e:
        return {"error": str(e)}  # Return an error message in case of failure




@app.route('/enable-firewall', methods=['POST'])
def enable_firewall():
    try:
        # Your implementation to enable the firewall (e.g., using subprocess)
        subprocess.run(['ufw', 'enable'], check=True)
        return {"status": "Firewall enabled"}  # Return a success message or any relevant data
    except Exception as e:
        return {"error": str(e)}  # Return an error message in case of failure

# Function to disable UFW firewall
@app.route('/disable-firewall', methods=['POST'])
def disable_firewall():
    try:
        # Your implementation to disable the firewall (e.g., using subprocess)
        subprocess.run(['ufw', 'disable'], check=True)
        return {"status": "Firewall disabled"}  # Return a success message or any relevant data
    except Exception as e:
        return {"error": str(e)}  # Return an error message in case of failure


        

# Route to toggle UFW status
@app.route('/toggle_ufw_status', methods=['POST'])
def toggle_ufw_status():
    global ufw_enabled
    if ufw_enabled:
        # Disable UFW
        subprocess.run(['ufw', 'disable'], check=True)
    else:
        # Enable UFW
        subprocess.run(['ufw', 'enable'], check=True)
    
    ufw_enabled = not ufw_enabled
    return jsonify({"message": "UFW status updated."})

# Route to get the UFW status
@app.route('/ufw_status')
def get_ufw_status():
    return jsonify({"enabled": ufw_enabled})

@app.route('/activate-firewall/<mode>', methods=['POST'])
def activate_firewall(mode):
    if mode in ufw_commands:
        command = ufw_commands[mode]

        # Execute the ufw command with the specific parameters using subprocess
        import subprocess
        result = subprocess.run(['ufw', command], shell=True, text=True, capture_output=True)

        if result.returncode == 0:
            return jsonify({
                'message': f'Firewall mode "{mode}" activated successfully.',
                'command_output': result.stdout
            })
        else:
            return jsonify({
                'message': f'Failed to activate firewall mode "{mode}": {result.stderr}',
                'command_output': result.stdout
            }), 500

    return jsonify({'message': 'Invalid mode specified'}), 400

@app.route('/disable-firewall/<mode>', methods=['POST'])
def disable_firewall_mode(mode):
    if mode in ufw_commands:
        command = ufw_commands[mode]

        # Execute the ufw command to disable the specific mode
        import subprocess
        result = subprocess.run(['ufw delete', command], shell=True, text=True, capture_output=True)

        if result.returncode == 0:
            return jsonify({
                'message': f'Firewall mode "{mode}" disabled successfully.',
                'command_output': result.stdout
            })
        else:
            return jsonify({
                'message': f'Failed to disable firewall mode "{mode}": {result.stderr}',
                'command_output': result.stdout
            }), 500

    return jsonify({'message': 'Invalid mode specified'}), 400


@app.route('/IDS_set_mode', methods=['POST'])
def IDS_set_mode():
    global ids_mode
    new_mode = request.form.get('mode')
    ids_mode = new_mode
    return jsonify({"message": "IDS mode updated."})

@app.route('/IDS_toggle_status', methods=['POST'])
def toggle_status():
    global ids_status, ids_process
    if ids_status:
        # If the IDS is currently running, terminate the process
        if ids_process is not None:
            ids_process.terminate()
            ids_process = None
    else:
        # Start the IDS process (you should replace 'your_ids_script.py' with the actual script)
        ids_process = subprocess.Popen(['python', 'Cybervault_Capture.py'])
    
    ids_status = not ids_status
    return jsonify({"message": "IDS status updated."})

@app.route('/IDS_get_mode')
def IDS_get_mode():
    return jsonify({"mode": ids_mode})
    
@app.route('/IDS_get_status')
def IDS_get_status():
    return jsonify({"status": ids_status, "mode": ids_mode})
    
@app.route('/get_latest_ids_entry')
def get_latest_ids_entry():
    try:
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="kali",
            database="CyberVault"
        )

        cursor = db_connection.cursor()

        # Retrieve the latest entry from the IDS table
        query = "SELECT attackType, actionTaken FROM IDS ORDER BY eventID DESC LIMIT 1"
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            # Format the result as a dictionary
            latest_entry = {
                "attackType": result[0],
                "actionTaken": result[1]
            }

            return jsonify(latest_entry)

    except Exception as e:
        return jsonify({"error": str(e)})

    finally:
        cursor.close()
        db_connection.close()    

if __name__ == '__main__':
    app.run(debug=True)
