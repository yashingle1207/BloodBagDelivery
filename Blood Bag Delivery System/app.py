from datetime import datetime
from bson import ObjectId
import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pymongo import MongoClient
import uuid
import requests
import base64
import json
import jsons
import hashlib
import shortuuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pytz


app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.urandom(24)

# app.config['SESSION_COOKIE_SAMESITE'] = 'None'
# # app.config['SESSION_COOKIE_SECURE'] = True


######################## MongoDB configuration for the remote #####################################
atlas_uri = "mongodb+srv://yashingle007:YASHsteyr124@clusterbb.uyk8mkp.mongodb.net/"

# Create a MongoClient instance using the Atlas URI
client = MongoClient(atlas_uri)

db = client['BloodBag']  # Update with your database name
HospUser = db['HospitalUsers']  # Collection for storing user data
BBUser = db['BloodBankUsers']  # Collection for storing user data
BloodStockAdd = db['BloodStock']
Searchbb = db['BloodStock']
Order = db['Orders']
PatientUser = db['PatientUsers']
PatientSearchBB = db['BloodStock']
pricing_collection = db['pricing']

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_FROM = 'transfusiotrack@gmail.com'
EMAIL_PASSWORD = 'engv kjsl qjrn eroa '


####################### Payment PhonePe #######################


def calculate_sha256_string(input_string):
    # Create a hash object using the SHA-256 algorithm
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # Update hash with the encoded string
    sha256.update(input_string.encode('utf-8'))
    # Return the hexadecimal representation of the hash
    return sha256.finalize().hex()


def base64_encode(input_dict):
    # Convert the dictionary to a JSON string
    json_data = jsons.dumps(input_dict)
    # Encode the JSON string to bytes
    data_bytes = json_data.encode('utf-8')
    # Perform Base64 encoding and return the result as a string
    return base64.b64encode(data_bytes).decode('utf-8')


@app.route("/make_payment", methods=['POST'])
def pay():
    # Calculate total amount
    total_amt = session.get("quantity") * session.get("blood_product_price")*0.010

    # Determine the merchantUserId based on which user is logged in
    patient_reg_no1 = session.get('_id')
    hosp_reg_no1 = session.get('hosp_reg_no')
    
    if patient_reg_no1:
        merchantUserId = patient_reg_no1
    elif hosp_reg_no1:
        merchantUserId = hosp_reg_no1
    else:
        raise ValueError("No user is logged in")

    # Define the MAINPAYLOAD with the correct merchantUserId
    MAINPAYLOAD = {
        "merchantId": "M22S8FP278KQA",
        "merchantTransactionId": shortuuid.uuid(),
        "merchantUserId": merchantUserId,
        "amount": total_amt,
        "redirectUrl": "https://www.transfusiotrack.com/payment_response",
        "redirectMode": "POST",
        "callbackUrl": "https://www.transfusiotrack.com/payment_response",
        "mobileNumber": "9518920645",
        "paymentInstrument": {
            "type": "PAY_PAGE"
        }
    }

    # API endpoint and details
    INDEX = "1"
    ENDPOINT = "/pg/v1/pay"
    SALTKEY = "cfaaec9b-b797-4e15-b14b-ac8cd11ac8f2"

    # Convert MAINPAYLOAD to base64 string
    base64String = base64.b64encode(json.dumps(MAINPAYLOAD).encode()).decode()

    # Calculate checksum
    mainString = base64String + ENDPOINT + SALTKEY
    sha256Val = hashlib.sha256(mainString.encode()).hexdigest()
    checkSum = sha256Val + '###' + INDEX

    # Define headers
    headers = {
        'Content-Type': 'application/json',
        'X-VERIFY': checkSum,
        'accept': 'application/json',
    }

    # Define request payload
    json_data = {
        'request': base64String,
    }

    # Make the API request
    response = requests.post('https://api.phonepe.com/apis/hermes/pg/v1/pay', headers=headers, json=json_data)
    responseData = response.json();
    return redirect(responseData['data']['instrumentResponse']['redirectInfo']['url'])

@app.route("/payment_response", methods=['POST'])
def payment_response():
    # Constants
    INDEX = "1"
    SALTKEY = "cfaaec9b-b797-4e15-b14b-ac8cd11ac8f2"

    # Retrieve form data
    form_data = request.form
    form_data_dict = dict(form_data)

    # Retrieve transaction ID from the request
    transaction_id = request.form.get('transactionId')

    if transaction_id:
        # Determine user ID based on the session
        if 'hosp_reg_no' in session:
            # Hospital user is logged in
            user_id = session['hosp_reg_no']
            template_name = 'map.html'
            # Fetch hospital email from database
            hospital_email = HospUser.find_one({'reg_num': user_id})['email']
        elif '_id' in session:
            # Patient user is logged in
            user_id = session['_id']
            template_name = 'Patientmap.html'
            # Fetch patient email from database
            patient_email = PatientUser.find_one({'_id': user_id})['email']
        else:
            # Neither hospital user nor patient user is logged in
            print("No user logged in.")
            return render_template('error.html', message='No user logged in')

        # Fetch blood bank email from database
        blood_bank_id = session.get('bb_reg_no')
        blood_bank_email = BBUser.find_one({'reg_num': blood_bank_id})['email']

        # Construct the request URL
        request_url = f'https://api.phonepe.com/apis/hermes/pg/v1/status/M22S8FP278KQA/{transaction_id}'

        # Construct the checksum string
        sha256_pay_load_string = f'/pg/v1/status/M22S8FP278KQA/{transaction_id}{SALTKEY}'
        sha256_val = calculate_sha256_string(sha256_pay_load_string)
        checksum = f'{sha256_val}###{INDEX}'

        # Set the request headers
        headers = {
            'Content-Type': 'application/json',
            'X-VERIFY': checksum,
            'X-MERCHANT-ID': 'M22S8FP278KQA',  # Merchant ID should be your merchant ID
            'accept': 'application/json',
        }

        # Make the GET request to the API
        response = requests.get(request_url, headers=headers)

        # Process the response
        if response.status_code == 200:
            response_data = response.json()

            # Log the response data for debugging
            print("Response Data:", response_data)

            # Check if the payment was successful
            if response_data.get('success') and response_data.get('code') == 'PAYMENT_SUCCESS':
                # Payment successful
                phonepe_transaction_id = response_data.get('data', {}).get('transactionId')

                # Extract order details from session
                req_type = session.get('req_type')
                fname = session.get('fname')
                mname = session.get('mname')
                lname = session.get('lname')
                age = session.get('age')
                ward = session.get('ward')
                bedno = session.get('bedno')
                gender = session.get('gender')
                blood_group = session.get('blood_group')
                blood_component = session.get('blood_component_code')
                requested_quantity = session.get('quantity')
                blood_bank_id = session.get('bb_reg_no')

                # Calculate total amount
                total_amt = session.get("quantity") * session.get("blood_product_price")

                bb_price = session.get("blood_product_price")

                # Convert timestamp to Indian Standard Time (IST)
                ist_timezone = pytz.timezone('Asia/Kolkata')
                ist_timestamp = datetime.now(pytz.utc).astimezone(ist_timezone)

                # Create order data
                order_data = {
                    'User_ID': user_id,
                    'BloodBank_Id': blood_bank_id,
                    'BloodGrp': blood_group,
                    'BloodComp': blood_component,
                    'BloodQuantity': requested_quantity,
                    'req_type': req_type,
                    'fname': fname,
                    'mname': mname,
                    'lname': lname,
                    'age': age,
                    'ward': ward,
                    'bedno': bedno,
                    'gender': gender,
                    'timestamp': ist_timestamp,  # IST timestamp
                    'status': 'undelivered',
                    'phonepe_transaction_id': phonepe_transaction_id,  # Add PhonePe transaction ID
                    'total_amount': total_amt  # Add total amount paid
                }

                # Insert order data into MongoDB
                inserted_order = Order.insert_one(order_data)

                # Get the inserted order ID
                order_id = inserted_order.inserted_id

                # Update blood bag quantity in the database
                print("Updating blood bag quantity...")
                print("Blood Bank ID:", blood_bank_id)
                print("Blood Group:", blood_group)
                print("Blood Component:", blood_component)
                print("Requested Quantity:", requested_quantity)

                blood_bags = Searchbb.find({'reg_num': blood_bank_id,
                                            'blood_group': blood_group,
                                            'blood_component': blood_component})

                # Update the quantity of each blood bag
                for blood_bag in blood_bags:
                    print("inside the for loop")
                    available_quantity = blood_bag.get('quantity', 0)
                    new_quantity = available_quantity - requested_quantity
                    # Update the quantity in the database
                    Searchbb.update_one(
                        {'_id': blood_bag['_id']},
                        {'$set': {'quantity': new_quantity}}
                    )
                    print("Blood bag quantity updated successfully.")

                # Send email to hospital/patient
                if 'hosp_reg_no' in session:
                    request_by = HospUser.find_one({'reg_num': user_id})['facility_name']
                    send_email(hospital_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'user',request_by)
                elif '_id' in session:
                    request_by = PatientUser.find_one({'_id': user_id})['patient_name']
                    send_email(patient_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'user',request_by)
                send_email(blood_bank_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'bloodbank',' ')

                # Redirect to the success page
                return render_template(template_name,
                                       order_id=order_id,
                                       phonepe_transaction_id=phonepe_transaction_id,
                                       total_amt=total_amt,
                                       timestamp=ist_timestamp,
                                       blood_group=blood_group,
                                       blood_component=blood_component,
                                       requested_quantity=requested_quantity,
                                       bb_price=bb_price)

            else:
                # Payment failed, log and redirect to payment failure page
                print("Payment failed. Response:", response_data)
                return render_template('payment_failed.html', form_data=form_data_dict, message=response_data.get('message', 'Unknown error occurred during payment initiation'))

        else:
            # Log and handle unexpected status code
            print("Unexpected response status code:", response.status_code)
            return render_template('error.html', message=f'Error during request: Unexpected response status code {response.status_code}')

    # Handle case where transaction ID is missing or invalid
    print("Missing or invalid transaction ID.")
    return render_template('error.html', message='Transaction ID missing or invalid')

def send_email(recipient_email, order_id, phonepe_transaction_id, total_amt, timestamp, blood_group, blood_component, requested_quantity, bb_price,request_type,request_by):
    # Email subject
    subject = "Blood Order Details"
    if request_type == 'user':
        body = render_template('email_body.html', order_id=order_id, phonepe_transaction_id=phonepe_transaction_id, total_amt=total_amt, timestamp=timestamp, blood_group=blood_group, blood_component=blood_component, requested_quantity=requested_quantity, bb_price=bb_price)
    elif request_type == 'bloodbank':
        body = render_template('email_bodybb.html', order_id=order_id, phonepe_transaction_id=phonepe_transaction_id, total_amt=total_amt, timestamp=timestamp, blood_group=blood_group, blood_component=blood_component, requested_quantity=requested_quantity, bb_price=bb_price,request_by=request_by)

    # Prepare message
    msg = MIMEText(body, 'html')  # Specify content type as HTML
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient_email

    try:
        # Connect to Gmail's SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()

        # Login to the email account
        server.login(EMAIL_FROM, EMAIL_PASSWORD)

        # Send the email
        server.sendmail(EMAIL_FROM, recipient_email, msg.as_string())  # Convert message to string

        # Close the connection
        server.quit()

        # Log email sent
        print(f"Email sent to {recipient_email}.")

    except Exception as e:
        # Log error if email sending fails
        print(f"Error sending email: {e}")



@app.route('/payment_invoice', methods=['POST'])
def payment_invoice():
    if request.method == 'POST':
        # Get form data
        req_type = request.form.get('reqtype')
        fname = request.form.get('fname')
        mname = request.form.get('mname')
        lname = request.form.get('lname')
        gender = request.form.get('gender')
        age = request.form.get('age')
        ward = request.form.get('ward')
        bedno = request.form.get('bedno')

        # Store form data in session
        session['req_type'] = req_type
        session['fname'] = fname
        session['mname'] = mname
        session['lname'] = lname
        session['gender'] = gender
        session['age'] = age
        session['ward'] = ward
        session['bedno'] = bedno

        # Check if the user is a patient or hospital
        patient_reg_no = session.get('_id')
        hosp_reg_no = session.get('hosp_reg_no')

        if hosp_reg_no:
            return render_template('payment_details.html', hosp_reg_no=hosp_reg_no)
        elif patient_reg_no:
            return render_template('payment_details.html', patient_reg_no=patient_reg_no)

    # Handle case where request method is not POST
    return render_template('error.html', message='Invalid request method.')



###############################################################



################# Login Session##########################
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()

    # Redirect to the home page
    return redirect(url_for('home'))

# Home route
@app.route('/')
def home():
    return render_template('home.html')




@app.route('/HospSignIn', methods=['POST'])
def HospsignIn():
    if request.method == 'POST':
        hosp_email = request.form.get('hospEmailId')
        hosp_password = request.form.get('hospPassword')

        existing_user = HospUser.find_one({'email': hosp_email, 'password': hosp_password})
        if existing_user:
            hosp_reg_no = existing_user.get('reg_num')

            # Set the registration number in the session
            session['hosp_reg_no'] = hosp_reg_no 

            # Redirect to the hospital dashboard
            # return redirect(url_for('HospDashboard'))
            return render_template('HospitalDashboard.html',  hosp_reg_no=hosp_reg_no )

        else:
            return render_template('LoginUnsuccessful.html')

    response = app.make_response(render_template('HospitalSignIn.html'))

    return response



@app.route('/BBSignIn', methods=['POST', 'GET'])
def BBsignIn():
    if request.method == 'POST':
        # Get user input from the login form
        bb_email = request.form.get('BBemail1')
        bb_password = request.form.get('BBpass1')

        # Check if the user exists in the database
        existing_user = BBUser.find_one({'email': bb_email, 'password': bb_password})
        if existing_user:
            bb_reg_no = existing_user.get('reg_num')
            session['bb_reg_no'] = bb_reg_no

            return redirect(url_for('BBDashboard'))

        else:
            return render_template('LoginUnsuccessful.html')

    # Create the response for the GET request
    response = app.make_response(render_template('BloodBankSignIn.html'))
    return response


@app.route('/PatientSignIn', methods=['POST','GET'])
def PsignIn():
    if request.method == 'POST':
        # Get user input from the login form
        p_email = request.form.get('patientEmailId1')
        p_password = request.form.get('patientPassword1')

        # Check if the user exists in the database
        existing_user = PatientUser.find_one({'email': p_email, 'password': p_password})
        if existing_user:
            patient_reg_no = str(existing_user.get('email'))

            # Set the registration number in the session
            session['_id'] = patient_reg_no

            return redirect(url_for('PatientDashboard'))

        else:
            return render_template('LoginUnsuccessful.html')

    response = app.make_response(render_template('PatientSignIn.html'))

    return response



# @app.route('/HospSignUp', methods=['POST'])
# def Hospsignup():
#     if request.method == 'POST':
#         # Get user input from the signup form
#         facility_name = request.form.get('facilityName')
#         facility_email = request.form.get('facilityEmailId')
#         facility_password = request.form.get('facilityPassword')
#         facility_contact_num = request.form.get('facilityContactNum')
#         facility_address = request.form.get('facilityAddress')
#         facility_reg_num = request.form.get('facilityRegNum')

#         # Check if the email already exists
#         existing_user = HospUser.find_one({'reg_num': facility_reg_num})
#         if existing_user:
#             return render_template('AlreadyExistHosp.html')

#         # Create a new user document
#         new_user = {
#             'facility_name': facility_name,
#             'email': facility_email,
#             'password': facility_password,
#             'contact_num': facility_contact_num,
#             'address': facility_address,
#             'reg_num': facility_reg_num
#         }

#         # Insert the new user into the MongoDB collection
#         HospUser.insert_one(new_user)

#     return render_template('HospitalDashboard.html')


@app.route('/HospSignUp', methods=['GET', 'POST'])
def Hospsignup():
    if request.method == 'POST':
        # Get user input from the signup form
        facility_name = request.form.get('facilityName')
        facility_email = request.form.get('facilityEmailId')
        facility_password = request.form.get('facilityPassword')
        facility_contact_num = request.form.get('facilityContactNum')
        facility_address = request.form.get('facilityAddress')
        facility_reg_num = request.form.get('facilityRegNum')

        # Check if the email already exists
        existing_user = HospUser.find_one({'email': facility_email})
        if existing_user:
            return render_template('AlreadyExistHosp.html')

        # Generate a random verification token
        verification_token = secrets.token_urlsafe(16)

        # Create a new user document with email verification status
        new_user = {
            'facility_name': facility_name,
            'email': facility_email,
            'password': facility_password,
            'contact_num': facility_contact_num,
            'address': facility_address,
            'reg_num': facility_reg_num,
            'email_verified': False,
            'verification_token': verification_token
        }

        # Insert the new user into the MongoDB collection
        HospUser.insert_one(new_user)

        # Send email verification
        send_hosp_email_verification(facility_email, verification_token)

        return render_template('VerifyEmail.html', email=facility_email)

    return render_template('HospitalSignUp.html')


def send_hosp_email_verification(email, token):
    subject = 'Email Verification'
    body = f'To verify your email, please click the following link: <a href="{url_for("verify_email", token=token, _external=True)}">Verify Email</a>'
    message = MIMEMultipart()
    message['From'] = EMAIL_FROM
    message['To'] = email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'html'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_FROM, EMAIL_PASSWORD)
    server.sendmail(EMAIL_FROM, email, message.as_string())
    server.quit()


@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = HospUser.find_one({'verification_token': token})
    if user:
        # Mark email as verified
        HospUser.update_one({'verification_token': token}, {'$set': {'email_verified': True}})
        return render_template('EmailVerified.html')
    else:
        return render_template('InvalidToken.html')


@app.route('/Patientsignup', methods=['GET', 'POST'])
def Psignup():
    if request.method == 'POST':
        # Get user input from the signup form
        patient_name = request.form.get('patientName')
        patient_email = request.form.get('patientEmailId')
        patient_password = request.form.get('patientPassword')
        contact_num = request.form.get('patientContactNum')
        address = request.form.get('patientAddress')
        p_city = request.form.get('patientCity')

        # Check if the email already exists
        existing_user = PatientUser.find_one({'email': patient_email})
        if existing_user:
            return render_template('AlreadyExistPatient.html')

        # Generate a random verification token
        verification_token = secrets.token_urlsafe(16)

        # Create a new user document with email verification status
        new_user = {
            'patient_name': patient_name,
            'email': patient_email,
            'password': patient_password,
            'contact_num': contact_num,
            'address': address,
            'p_city': p_city,
            'email_verified': False,
            'verification_token': verification_token
        }

        # Insert the new user into the MongoDB collection
        PatientUser.insert_one(new_user)

        # Send email verification
        send_paitent_email_verification(patient_email, verification_token)

        return render_template('VerifyEmailPatient.html', email=patient_email)

    return render_template('PatientSignUp.html')


def send_paitent_email_verification(email, token):
    subject = 'Email Verification'
    body = f'To verify your email, please click the following link: <a href="{url_for("verify_email_patient", token=token, _external=True)}">Verify Email</a>'
    message = MIMEMultipart()
    message['From'] = EMAIL_FROM
    message['To'] = email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'html'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_FROM, EMAIL_PASSWORD)
    server.sendmail(EMAIL_FROM, email, message.as_string())
    server.quit()


@app.route('/verify_email_patient/<token>', methods=['GET'])
def verify_email_patient(token):
    user = PatientUser.find_one({'verification_token': token})
    if user:
        # Mark email as verified
        PatientUser.update_one({'verification_token': token}, {'$set': {'email_verified': True}})
        return render_template('EmailVerifiedPatient.html')
    else:
        return render_template('InvalidTokenPatient.html')


@app.route('/Patientsignup', methods=['POST'])
# def Psignup():
#     if request.method == 'POST':
#         # Get user input from the signup form
#         patient_name = request.form.get('patientName')
#         patient_email = request.form.get('patientEmailId')
#         patient_password = request.form.get('patientPassword')
#         contact_num = request.form.get('patientContactNum')
#         address = request.form.get('patientAddress')
#         p_city = request.form.get('patientCity')

#         # Check if the email already exists
#         existing_user = PatientUser.find_one({'email': patient_email})
#         if existing_user:
#             return render_template('AlreadyExistPatient.html')

#         # Create a new user document
#         new_user = {
#             'patient_name': patient_name,
#             'email': patient_email,
#             'password': patient_password,
#             'contact_num': contact_num,
#             'address': address,
#             'p_city': p_city
#         }

#         # Insert the new user into the MongoDB collection
#         PatientUser.insert_one(new_user)

#         return render_template('PatientDashboard.html')



@app.route('/BBSignUp', methods=['POST'])
def BBsignup():
    if request.method == 'POST':
        # Get user input from the signup form
        bb_name = request.form.get('BBName')
        bb_email = request.form.get('BBEmail')
        bb_password = request.form.get('BBPass')
        contact_num = request.form.get('ContactNum')
        address = request.form.get('Address')
        reg_num = request.form.get('RegNum')

        # Check if the email already exists
        existing_user = BBUser.find_one({'reg_num': reg_num})
        if existing_user:
            return render_template('AlreadyExistBB.html')

        # Create a new user document
        new_user = {
            'bb_name': bb_name,
            'email': bb_email,
            'password': bb_password,
            'contact_num': contact_num,
            'address': address,
            'reg_num': reg_num
        }

        # Insert the new user into the MongoDB collection
        BBUser.insert_one(new_user)

    return render_template('BB_verification.html')




########################################### payment end#############################


def update_delivery_status(order_id):
    # Update the status to 'delivered'
    current_datetime = datetime.now()
    Order.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'delivered', 'timestamp': current_datetime}}
    )


@app.route('/initiate_delivery', methods=['POST'])
def initiate_delivery():
    if request.method == 'POST':
        order_id = request.form.get('selected_order')

        # Assuming you have a function to update the status in your MongoDB collection
        update_delivery_status(order_id)

        return render_template('dispatched.html')

####################################################################################

@app.route('/ViewStock')
def viewstock():
    # Query MongoDB to fetch all blood bags
    blood_bags = Searchbb.find({'reg_num': session.get('bb_reg_no')})

    # Initialize a dictionary to organize the data
    results = {}

    # Populate the dictionary with blood components, blood groups, and quantities
    for bag in blood_bags:
        blood_component = bag.get('blood_component')
        blood_group = bag.get('blood_group')
        quantity = bag.get('quantity')

        if blood_component not in results:
            results[blood_component] = {
                'O+': 0,
                'O-': 0,
                'A+': 0,
                'A-': 0,
                'B+': 0,
                'B-': 0,
                'AB+': 0,
                'AB-': 0,
                'Oh+': 0,
                'Oh-': 0,
            }

        results[blood_component][blood_group] += quantity

    # Render the template with the organized results
    return render_template('ViewStock.html', results=results)

####################################

@app.route('/delorder', methods=['GET'])
def bloodbank_completed_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id':session.get('bb_reg_no'),'status': 'delivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id'),
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),

            'timestamp': order.get('timestamp')
        })

    return render_template('DeliveredBags.html', orders=order_list)


@app.route('/delorder1', methods=['GET'])
def hosp_received_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID': 'Reg1234', 'status': 'delivered'})

  

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id'),
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),
            'timestamp': order.get('timestamp')
        })

    return render_template('Receivedbags.html', orders=order_list)


@app.route('/delorder2', methods=['GET'])
def patient_received_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID': session.get('_id'),'status': 'delivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id'),
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),
            'timestamp': order.get('timestamp')
        })

    return render_template('PatientReceivedbags.html', orders=order_list)

################################################################

@app.route('/BBNewReq', methods=['GET'])
def Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id':session.get('bb_reg_no'),'status': 'undelivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id') ,
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),
            'timestamp': order.get('timestamp')
        })

    return render_template('BBNewReq.html', orders=order_list)

##############################################

@app.route('/Hosp_Pending_Req', methods=['GET'])
def Hosp_Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID':session.get('hosp_reg_no'),'status': 'undelivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id') ,
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),
            'timestamp': order.get('timestamp')
        })

    return render_template('HospitalPendingReq.html', orders=order_list)


#########

@app.route('/Patient_Pending_Req', methods=['GET'])
def Patient_Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID':session.get('_id'),'status': 'undelivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        order_list.append({

            '_id': order.get('_id'),
            'User_ID': order.get('User_ID'),
            'BloodBank_Id': order.get('BloodBank_Id') ,
            'BloodGrp': order.get('BloodGrp'),
            'BloodComp': order.get('BloodComp'),
            'BloodQuantity': order.get('BloodQuantity'),


            'req_type': order.get('req_type'),
            'fname': order.get('fname'),
            'mname': order.get('mname'),
            'lname': order.get('lname'),
            'age': order.get('age'),
            'ward': order.get('ward'),
            'bedno': order.get('bedno'),
            'gender': order.get('gender'),
            'timestamp': order.get('timestamp')
        })

    return render_template('PatientPendingReq.html', orders=order_list)



# @app.route('/Psubmit_req', methods=['POST'])
# def Patient_sr():
#     if request.method == 'POST':
#         # Get user input from the form
#         req_type = session['req_type']
#         fname = session['fname']
#         mname = session['mname']
#         lname = session['lname']
#         age = session['age']
#         ward = session['ward']
#         bedno = session['bedno']
#         gender = session['gender']
#
#
#         # Decrease the quantity of blood bags in MongoDB
#
#         blood_group = session.get('blood_group')
#         blood_component = session.get('blood_component')
#         requested_quantity = int(session.get('quantity'))
#
#         # Create a dictionary with the form data
#         form_data = {
#             'User_ID': session.get('_id'),
#             'BloodBank_Id': session.get('bb_reg_no'),
#             'BloodGrp': blood_group,
#             'BloodComp':blood_component,
#             'BloodQuantity': requested_quantity,
#             'req_type': req_type,
#             'fname': fname,
#             'mname': mname,
#             'lname': lname,
#             'age': age,
#             'ward': ward,
#             'bedno': bedno,
#             'gender': gender,
#             'timestamp': datetime.now(),
#             'status': 'undelivered'
#         }
#
#         # Insert the form data into the Order collection in MongoDB
#         Order.insert_one(form_data)
#
#
#
#         # Find the relevant blood bags in the database
#         blood_bags = BloodStockAdd.find({'reg_num':session.get('bb_reg_no'),'blood_group': blood_group, 'blood_component': blood_component})
#
#         # Update the quantity of each blood bag
#         for blood_bag in blood_bags:
#             available_quantity = blood_bag.get('quantity', 0)
#             if available_quantity >= requested_quantity:
#                 new_quantity = available_quantity - requested_quantity
#                 # Update the quantity in the database
#                 BloodStockAdd.update_one(
#                     {'_id': blood_bag['_id']},
#                     {'$set': {'quantity': new_quantity}}
#                 )
#             else:
#                 # Handle insufficient quantity error
#                 return render_template('error.html', message='Insufficient quantity of blood bags.')
#
#     return render_template('map.html')



##################################################
@app.route('/submit_order', methods=['POST'])
def submit_order():
    blood_type = request.form['blood_type']
    quantity = request.form['quantity']
    # Here, you can process the order, save it to a database, etc.
    return f"Order placed: Blood Type - {blood_type}, Quantity - {quantity}"




from flask import session

# @app.route('/searchbb', methods=['POST'])
# def search_blood_bag():
#     if request.method == 'POST':
#         # Get user input from the form
#         blood_group = request.form.get('bloodgrp')
#         blood_component = request.form.get('comptype')
#         quantity = int(request.form.get('quantity'))

#         # Retrieve hosp_reg_no from the session
#         hosp_reg_no= session.get('hosp_reg_no')

#         # Query MongoDB to find matching blood bags
#         blood_bags = Searchbb.find({
#             'blood_group': blood_group,
#             'blood_component': blood_component,
#             'quantity': {'$gte': quantity}  # Filter bags with quantity greater than or equal to user input
#         })

#         # Prepare the results to be displayed or processed further
#         results = []
#         for bag in blood_bags:
#             # Fetch additional details from the users table using reg_num
#             blood_bank_user = BBUser.find_one({'reg_num': bag['reg_num']})

#             results.append({
#                 'bb_reg_no': bag['reg_num'],
#                 'blood_group': bag['blood_group'],
#                 'blood_component': bag['blood_component'],
#                 'quantity': bag['quantity'],
#                 'bb_name': blood_bank_user['bb_name'],  # Assuming the field name is 'bb_name' in your users table
#                 'address': blood_bank_user['address'],  # Assuming the field name is 'address' in your users table
#             })

#         # Store the values in the user's session
#         session['blood_group'] = blood_group
#         session['blood_component'] = blood_component
#         session['quantity'] = quantity

#         # Return the results to the template along with hosp_reg_no
#         return render_template('SearchResults.html', results=results, hosp_reg_no=hosp_reg_no)

#     return render_template('SearchResults.html')


@app.route('/searchbb_hosp', methods=['POST'])
def search_blood_bag():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp')
        blood_component = request.form.get('comptype')
        quantity = int(request.form.get('quantity'))

        # Retrieve hosp_reg_no from the session
        hosp_reg_no= session.get('hosp_reg_no')

        # Query MongoDB to find matching blood bags
        blood_bags = Searchbb.find({
            'blood_group': blood_group,
            'blood_component': blood_component,
            'quantity': {'$gte': quantity}  # Filter bags with quantity greater than or equal to user input
        })

        # Prepare the results to be displayed or processed further
        results = []
        for bag in blood_bags:
            # Fetch additional details from the users table using reg_num
            blood_bank_user = BBUser.find_one({'reg_num': bag['reg_num']})

            results.append({
                'bb_reg_no': bag['reg_num'],
                'blood_group': bag['blood_group'],
                'blood_component': bag['blood_component'],
                'quantity': bag['quantity'],
                'bb_name': blood_bank_user['bb_name'],  # Assuming the field name is 'bb_name' in your users table
                'address': blood_bank_user['address'],  # Assuming the field name is 'address' in your users table
            })

        # Store the values in the user's session
        session['blood_group'] = blood_group
        session['blood_component_code'] = blood_component
        session['quantity'] = quantity

        # Return the results to the template along with hosp_reg_no
        return render_template('SearchResults.html', results=results, hosp_reg_no=hosp_reg_no)

    return render_template('SearchResults.html', results=results, hosp_reg_no=hosp_reg_no)



@app.route('/PatientSearchBB', methods=['POST'])
def PsearchBB():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp1')
        blood_component = request.form.get('comptype1')
        quantity = int(request.form.get('quantity1'))

        # Retrieve the patient ID from the session
        patient_reg_no = session.get('_id')

        # Query MongoDB to find matching blood bags
        blood_bags = PatientSearchBB.find({
            'blood_group': blood_group,
            'blood_component': blood_component,
            'quantity': {'$gte': quantity}  # Filter bags with quantity greater than or equal to user input
        })

        # Prepare the results to be displayed or processed further
        results = []
        for bag in blood_bags:
            # Fetch additional details from the users table using reg_num
            blood_bank_user = BBUser.find_one({'reg_num': bag['reg_num']})

            results.append({
                'bb_reg_no': bag['reg_num'],
                'blood_group': bag['blood_group'],
                'blood_component': bag['blood_component'],
                'quantity': bag['quantity'],
                'bb_name': blood_bank_user['bb_name'],  # Assuming the field name is 'bb_name' in your users table
                'address': blood_bank_user['address'],  # Assuming the field name is 'address' in your users table
            })

        # Store the values in the user's session
        session['blood_group'] = blood_group
        session['blood_component_code'] = blood_component
        session['quantity'] = quantity

        # Return the results to the template along with patient ID
        return render_template('PatientSearchResult.html', results=results, patient_reg_no=patient_reg_no)

    return render_template('PatientSearchResult.html',results=results, patient_reg_no=patient_reg_no)



####################################################################
@app.route('/set_selected_blood_bank', methods=['POST'])
def set_selected_blood_bank():
    if request.method == 'POST':
        selected_blood_bank_reg_num = request.form.get('selected_blood_bank')

        # Fetch the price of the selected blood product from the database
        selected_blood_product = session.get('blood_component_code')
        blood_product_price = get_blood_product_price(selected_blood_product)

        # Check if a hospital or patient is logged in
        if 'hosp_reg_no' in session:
            # Set the selected blood bank reg_num and blood product price in the session for a hospital
            session['bb_reg_no'] = selected_blood_bank_reg_num
            session['blood_product_price'] = blood_product_price
            return render_template('BloodBagRequestForm.html')  # Redirect to the hospital's request form

        elif '_id' in session:
            # Set the selected blood bank reg_num and blood product price in the session for a patient
            session['bb_reg_no'] = selected_blood_bank_reg_num
            session['blood_product_price'] = blood_product_price
            return render_template('PatientBBreqform.html')  # Redirect to the patient's request form

    # Redirect to a default page or handle the case where the user type is not identified
    return render_template('error.html', message='User type not identified.')


def get_blood_product_price(blood_product_name):
    # Query the MongoDB collection 'pricing' to fetch the price of the given blood product
    blood_product = pricing_collection.find_one({'code': blood_product_name})
    if blood_product:
        session["blood_component"] = blood_product['name']
        return blood_product['price']
    else:
        # Return a default price or handle the case where the price is not found
        return None




##################################################################

@app.route('/addbb', methods=['POST'])
def add_blood_bag():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp')
        blood_component = request.form.get('comptype')
        quantity = int(request.form.get('quantity'))

        # Check if a record with the same blood group and blood component exists
        existing_record = BloodStockAdd.find_one({'reg_num':session.get('bb_reg_no'),'blood_group': blood_group, 'blood_component': blood_component})

        if existing_record:
            # If the record exists, update the quantity
            new_quantity = existing_record['quantity'] + quantity
            # Update the existing record with the new quantity
            BloodStockAdd.update_one(
                {'blood_group': blood_group, 'blood_component': blood_component},
                {'$set': {'quantity': new_quantity, 'timestamp': datetime.now()}}
            )
        else:
            # If the record does not exist, create a new record
            blood_bag_info = {
                'reg_num': session.get('bb_reg_no'),
                'blood_group': blood_group,
                'blood_component': blood_component,
                'quantity': quantity,
                'timestamp': datetime.now()
            }
            # Insert the blood bag information into MongoDB
            BloodStockAdd.insert_one(blood_bag_info)

    return render_template('StockAddSuccessful.html')

#################################################################################################
@app.route('/removebb', methods=['POST'])
def remove_blood_bag():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp1')
        blood_component = request.form.get('comptype1')
        quantity_to_remove = int(request.form.get('quantity1'))

        # Check if a record with the same blood group and blood component exists
        existing_record = BloodStockAdd.find_one({'blood_group': blood_group, 'blood_component': blood_component})

        if existing_record:
            current_quantity = existing_record['quantity']
            if quantity_to_remove >= current_quantity:
                # If the requested quantity to remove is greater or equal to the current quantity, delete the record
                BloodStockAdd.delete_one({'_id': existing_record['_id']})
            else:
                # Subtract the requested quantity from the current quantity
                new_quantity = current_quantity - quantity_to_remove
                # Update the existing record with the new quantity
                BloodStockAdd.update_one(
                    {'blood_group': blood_group, 'blood_component': blood_component},
                    {'$set': {'quantity': new_quantity, 'timestamp': datetime.now()}}
                )

    return render_template('StockAddSuccessful.html')





##############################################################################

@app.route('/HospDashboard')
def HospDashboard():
    # Retrieve the registration number from the session
    hosp_reg_no = session.get('hosp_reg_no')

    # Check if the user is logged in
    if hosp_reg_no:
        return render_template('HospitalDashboard.html', hosp_reg_no=hosp_reg_no)
    else:
        # Redirect to the login page if not logged in
         return render_template('HospSignup.html')



@app.route('/PatientDashboard')
def PatientDashboard():
    # Retrieve the registration number from the session
    patient_reg_no = session.get('_id')

    # Check if the user is logged in
    if patient_reg_no:
        return render_template('PatientDashboard.html', patient_reg_no=patient_reg_no)
    else:
        # Redirect to the patient sign-in page if not logged in
        return render_template('PatientLogin.html')


@app.route('/BBDashboard')
def BBDashboard():
    # Retrieve the registration number from the session
    bb_reg_no = session.get('bb_reg_no')

    # Check if the user is logged in
    if bb_reg_no:
        return render_template('BloodBankDashboard.html', bb_reg_no=bb_reg_no)
    else:
        # Redirect to the login page if not logged in
        return render_template('BBSignup.html')


@app.route('/HospSign')
def Hospsign():
    return render_template('HospSignup.html')

@app.route('/BBSign')
def BBsign1():
    return render_template('BBSignup.html')

@app.route('/PatientSign')
def Psign1():
    return render_template('PatientLogin.html')



@app.route('/AddBB')
def addbb():
    return render_template('AddBloodBags.html')

@app.route('/Stockadded')
def stockadd():
    return render_template('StockAddSuccessful.html')


@app.route('/SearchResults')
def searchres():
    return render_template('SearchResults.html')


@app.route('/SearchBlood')
def searchblood():
    return render_template('SearchBloodBag.html')
  

@app.route('/PatientSearchBB')
def Psearchbb():
    return render_template('PatientSearchBB.html')

@app.route('/Blood order')
def reqform():
    return render_template('BloodBagRequestForm.html')

@app.route('/Patient_BBorder')
def Preqform():
    return render_template('BloodBagRequestForm.html')


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contact')
def contactus():
    return render_template('contactus.html')


@app.route('/map', methods=['POST'])
def map():
    return render_template('map.html')

# @app.route('/dispatch')
# def dispatch():
#     return render_template('dispatched.html')



@app.route('/LoginUnsuccessful')
def faillogin():
    return render_template('LoginUnsuccessful.html')

@app.route('/privacy')
def privacyfun():
    return render_template('privacypolicy.html')

@app.route('/terms')
def TnC():
    return render_template('T&C.html')

@app.route('/refund')
def refund():
    return render_template('Return_Refund_policy.html')

@app.route('/pricing')
def price():
    return render_template('PricingPolicy.html')


@app.route('/guide')
def guidemanual():
    return render_template('guideManual.html')




# Decorator to handle CORS headers
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

app.after_request(add_cors_headers)

@app.route('/update_location', methods=['GET'])
def update_location():
    data = request.json  # Assuming the data is sent as JSON
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # Store or process the location data as needed

    return jsonify({'status': 'Location updated successfully'})




if __name__ == '__main__':
    app.run(debug=True)
