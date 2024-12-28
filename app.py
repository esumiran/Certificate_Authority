import logging
from flask import Flask, render_template, request, redirect, url_for

import pymongo, random

from pymongo import MongoClient

from config import Config



# Ivans code

## Import all the necessary libraries for the code
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from pymongo.errors import ServerSelectionTimeoutError


app = Flask(__name__, template_folder='templates', static_folder='static')

app.static_folder = 'static'


##############################################################################
#connecting to Mongo Atlas
def check_mongo_connection(uri):
    try:
        # Create a MongoClient instance
        cluster = MongoClient(uri, serverSelectionTimeoutMS=5000)  # 5 seconds timeout
        # Try to fetch the server information
        cluster.server_info()
        print("MongoDB connection is successful!")
        app.logger.info('MongoDB connection is successful!')

    except ServerSelectionTimeoutError as err:
        # Handle the exception if the connection fails
        app.logger.critical(f"Connection to MongoDB failed: {err}")

# Example usage

cluster = MongoClient("mongodb+srv://mailpranavbhatia:cJpqw2xlfpa8T7SX@cluster0.nmzxj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

db = cluster["Certificate_Authority"]
collection = db["StudentData"]

testData = {"_id": 0, "name": "Pranav", "email": "mail.pranavbhatia@gmail.com", "password": "Pranav123"}

# collection.insert_one(testData)

# Configure Flask logging
app.logger.setLevel(logging.INFO)  # Set log level to INFO
handler = logging.FileHandler('app.log')  # Log to a file
app.logger.addHandler(handler)

################################################################################

#Decrytion
def decrypt_message_with_private_key(encrypted_message, pr_key_hex):
    """
    Decrypts a message using a private key in hex format.
    
    :param encrypted_message: The encrypted message (base64 encoded ciphertext)
    :param pr_key_hex: The private key in hex format
    :return: The decrypted message (plaintext)
    """
    # Step 1: Deserialize the private key from hex
    private_key_bytes = bytes.fromhex(pr_key_hex)
    private_key = serialization.load_der_private_key(
        private_key_bytes,
        password=None
    )

    # Step 2: Decrypt the message using the private key
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),  # Decode from base64 to bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted.decode('utf-8')

# Function to serialize public key and convert to hex
def serialize_public_key_to_hex(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes.hex()

# Verifying the digitally Sighned student_id 
def verify_signature_with_public_key(message, signature, pb_key_hex):
    """
    Verifies a digital signature using a public key in hex format.
    
    :param message: The original message that was signed
    :param signature: The Base64-encoded signature to verify
    :param pb_key_hex: The public key in hex format
    :return: True if the signature is valid, False otherwise
    """
    try:
        # Step 1: Deserialize the public key from hex
        public_key_bytes = bytes.fromhex(pb_key_hex)
        public_key = serialization.load_der_public_key(public_key_bytes)

        # Step 2: Verify the signature
        public_key.verify(
            base64.b64decode(signature),  # Decode Base64 signature to bytes
            message.encode('utf-8'),  # Convert message to bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False


#Hashing

def get_text_hash(text: str) -> str:
    # Create a SHA-256 hash object
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    # Update the hash object with the bytes of the text
    digest.update(text.encode('utf-8'))
    
    # Finalize the hash and get the digest
    hash_bytes = digest.finalize()
    
    # Convert the hash bytes to a hexadecimal string
    return hash_bytes.hex()

###################################################################################



###################################################################################


def generate_student_id():
    return str(random.randint(10000000, 99999999))  # Generates a random 8-digit number

def add_student_to_db(studentName):
    # Check if student already exists in the collection
    existing_student = collection.find_one({"student_name": studentName})

    if existing_student: 
        studentId = existing_student.get('student_id')
        return {'student_id':studentId, 'flag': True}

    else:

        studentId = generate_student_id()
        studentId_hash = get_text_hash(studentId)

        new_student = {
            "student_name": studentName,
            "verified": False,
            "student_id": studentId,
            "hash_value": studentId_hash
        }

        collection.insert_one(new_student)

        return {'student_id':studentId, 'flag': False}

def store_student_public_key(student_id, student_public_key):
    # Check if student_id exists
    existing_student = collection.find_one({"student_id": student_id})
    
    # If the student exists, update the public key; else, insert new student data
    if existing_student:
        # Update the existing student document with the new public key
        collection.update_one(
            {"student_id": student_id},
            {"$set": {"student_public_key": student_public_key}}
        )
        return "Public key updated successfully"
    else: 
        print("Student ID does not exists")


def get_student_public_key_by_hash(hash_value):

    student = collection.find_one(
        {"hash_value": hash_value},
        {"_id": 0, "student_id": 1, "student_name": 1, "student_public_key": 1, "verified": 1}
        )
    
    if student:
        # Return both the student ID and public key if found
        student_id = student.get("student_id")
        public_key = student.get("student_public_key")
        student_name = student.get("student_name")

        print("HASH VALUE EXISTS-- Student ID:", student_id, "Public Key:", public_key)
        return {"student_id": student_id, "public_key": public_key,"student_name":student_name}

    else:
        # Return None if no matching hash is found
        return None
    
###################################################################################


###################################################################################

# Route for the home page, displaying both forms (Step 1 and Step 2)
@app.route('/')
def index():

    check_mongo_connection("mongodb+srv://mailpranavbhatia:cJpqw2xlfpa8T7SX@cluster0.nmzxj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

    return render_template('home.html')

@app.route('/generateStudentId', methods=['POST'])
def generate_id():
    student_name = request.form.get('studentName')
   
    if student_name:

        data = add_student_to_db(student_name)
        return render_template('studentIdGenerated.html', student_name=student_name, id=data['student_id'], flag=data['flag'])
   
    else:
        return "Please enter a student name.", 400
    

@app.route('/step1')
def firstStepPage():
    return render_template('firstStep.html')

# Step 1: Handle the first form submission (Student ID encrypted with CA public key and student's public key)
@app.route('/submit_step1', methods=['POST'])
def submit_step1():
    try:
        # Retrieve form data
        student_id_ca = request.form.get('student_id_ca')
        student_public_key = request.form.get('student_public_key')

        # Attempt to decrypt the student ID
        student_id = decrypt_message_with_private_key(student_id_ca, Config.ca_private_key)
        
        # Log the decrypted student ID and public key
        print("Student ID: ", student_id)
        print("student_public_key:", student_public_key)

        # Store the student's public key in the database
        store_student_public_key(student_id, student_public_key)

        # Redirect to step 2 if everything is successful
        return redirect(url_for('secondStep'))

    except Exception as e:
        # Log the error and return an error message to the user
        return redirect(url_for('failed'), source ='A')

@app.route('/step2')
def secondStep():
    return render_template('secondStep.html')

# Step 2: Handle the second form submission (Student ID encrypted with student's private key and hash value)
@app.route('/submit_step2', methods=['POST'])
def submit_step2():
    encrypted_student_private = request.form.get('encrypted_student_private')
    hash_value = request.form.get('hash_value')


    try:
        result = get_student_public_key_by_hash(hash_value)

        student_id = result.get("student_id")
        public_key = result.get("public_key")
        student_name = result.get("student_name")
        print(student_name)

    except Exception as e:
        
        print(f"An error occurred: {e}")  
        return redirect(url_for('failed', source ='A'))
    

    #check the digital signature using - Stundent_id, Public_key & hash_value
    sign_ver = verify_signature_with_public_key(student_id, encrypted_student_private, public_key)
    if sign_ver:
        collection.update_one(
            {"student_id": student_id},
            {"$set":{"verified": True}})
        
        #return redirect(url_for('success'))
        return redirect(url_for(
            'success',
            student_id=student_id,
            student_name=student_name,
            public_key=public_key
        ))


    else:
        return redirect(url_for('failed'), source ='A')


#Route for student validate page
@app.route('/student_validation',methods=['POST'])
def student_validation():
    return render_template('studentvalidation.html')



@app.route('/submit_studentvalidation',methods=['POST'])
def submit_studentvalidation():
    student_id = request.form.get('student_id')

    try:
    
        student_data = collection.find_one(
            {"student_id": student_id},
            {"_id": 0, "student_id": 1, "student_name": 1, "student_public_key": 1, "verified": 1}
        )

        if student_data is None:
            return redirect(url_for('failed', source='C'))

        if student_data.get('verified'):
            return redirect(url_for(
                'success',
                student_id=student_data.get('student_id'),
                student_name=student_data.get('student_name'),
                public_key=student_data.get('student_public_key')
            ))
        else:
            return redirect(url_for('failed', source='B', student_id=student_data))

    except Exception as e:
        print(f"An error occurred: {e}")
        
        return redirect(url_for('failed', source='C'))




@app.route('/success')
def success():

    student_id = request.args.get('student_id')
    student_name = request.args.get('student_name')
    public_key = request.args.get('public_key')
    
    return render_template('success.html', student_id=student_id, student_name=student_name, public_key=public_key)


@app.route('/failed')
def failed():
    source = request.args.get('source')
    student_id = request.args.get('student_id')
    return render_template('failed.html', source=source, student_id=student_id)




if __name__ == "__main__":
    app.run(debug=False)
