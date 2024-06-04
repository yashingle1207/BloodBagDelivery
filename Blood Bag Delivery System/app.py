from datetime import datetime
from bson import ObjectId
import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for,flash
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
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pytz
from collections import defaultdict

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
admin_collection = db['Admin']

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
    total_amt = session.get("quantity") * session.get("blood_product_price")*0.10

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
            patient_email = PatientUser.find_one({'email': user_id})['email']
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
                gender = session.get('gender')
                docname =  session.get('docname')
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
                    'gender': gender,
                    'docname':docname,
                    'timestamp': str(ist_timestamp),  # IST timestamp
                    'status': 'undelivered',
                    'phonepe_transaction_id': phonepe_transaction_id,  # Add PhonePe transaction ID
                    'total_amount': total_amt,  # Add total amount paid
                    'settlement_status':False
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
                    request_by_address = HospUser.find_one({'reg_num': user_id})['address']
                    request_by_contact = HospUser.find_one({'reg_num': user_id})['contact_num']
                    print("request by:",request_by)
                    send_email(hospital_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'user',request_by,request_by_address,request_by_contact)
                elif '_id' in session:
                    request_by = PatientUser.find_one({'email': user_id})['patient_name']
                    request_by_address = PatientUser.find_one({'email': user_id})['address']
                    request_by_contact = PatientUser.find_one({'email': user_id})['contact_num']
                    print("request by:",request_by)
                    send_email(patient_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'user',request_by,request_by_address,request_by_contact)
                send_email(blood_bank_email, order_id, phonepe_transaction_id, total_amt, ist_timestamp, blood_group, blood_component, requested_quantity, bb_price,'bloodbank',request_by,request_by_address,request_by_contact)

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

def send_email(recipient_email, order_id, phonepe_transaction_id, total_amt, timestamp, blood_group, blood_component, requested_quantity, bb_price,request_type,request_by,request_by_address,request_by_contact):
    # Email subject
    subject = "Blood Order Details"
    if request_type == 'user':
        body = render_template('email_body.html', order_id=order_id, phonepe_transaction_id=phonepe_transaction_id, total_amt=total_amt, timestamp=timestamp, blood_group=blood_group, blood_component=blood_component, requested_quantity=requested_quantity, bb_price=bb_price)
    elif request_type == 'bloodbank':
        body = render_template('email_bodybb.html', order_id=order_id, phonepe_transaction_id=phonepe_transaction_id, total_amt=total_amt, timestamp=timestamp, blood_group=blood_group, blood_component=blood_component, requested_quantity=requested_quantity, bb_price=bb_price,request_by=request_by,request_by_address = request_by_address,request_by_contact = request_by_contact)

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
        docname = request.form.get('docname')
 

        # Store form data in session
        session['req_type'] = req_type
        session['fname'] = fname
        session['mname'] = mname
        session['lname'] = lname
        session['gender'] = gender
        session['age'] = age
        session['docname'] = docname
    

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



################# Settle Payment #############################
@app.route('/settle_payment', methods=['POST'])
def settle_payment():
    transaction_id = request.form.get('selected_transaction')

    if transaction_id:
        # Update the settlement status of the selected transaction in the 'Orders' collection
        Order.update_one(
            {'_id': ObjectId(transaction_id)},
            {'$set': {'settlement_status': True}}
        )
        flash("Payment settled successfully.", "success")
    else:
        flash("No transaction selected.", "danger")

    return redirect(url_for('admin_dashboard'))


################# Settled Payments Admin #############################
@app.route('/settled')
def settlepayments():
    # Fetch orders where settlement_status is True
    orders = list(Order.find({'settlement_status': True}))

    # Organize orders by blood bank and blood component
    organized_orders = defaultdict(lambda: defaultdict(list))
    for order in orders:
        blood_bank_id = order['BloodBank_Id']
        component = order['BloodComp']
        organized_orders[blood_bank_id][component].append(order)

    # Prepare the transactions data for the template
    transactions = []
    for blood_bank_id, components in organized_orders.items():
        blood_bank = BBUser.find_one({'reg_num': blood_bank_id})
        for component, orders in components.items():
            quantity_sold = sum(order['BloodQuantity'] for order in orders)
            price_per_unit = orders[0]['total_amount'] / orders[0]['BloodQuantity']  # Assuming total_amount is for the quantity sold
            total_amount_per_component = quantity_sold * price_per_unit
            total_amount_payable = sum(order['total_amount'] for order in orders)

            transactions.append({
                'blood_bank_name': blood_bank['bb_name'],
                'address': blood_bank['address'],
                'contact_no': blood_bank['contact_num'],
                'component': component,
                'quantity_sold': quantity_sold,
                'price_per_unit': price_per_unit,
                'total_amount_per_component': total_amount_per_component,
                'total_amount_payable': total_amount_payable,
                '_id': str(orders[0]['_id'])  # Assuming each order has a unique '_id'
            })

    return render_template('AdminSettled_payments.html', transactions=transactions)

################# Admin Login ############################

@app.route('/AdminSignIn', methods=['POST'])
def adminsignIn():
    if request.method == 'POST':
        admin_email = request.form.get('adminEmailId')
        admin_password = request.form.get('adminPassword')

        existing_admin = admin_collection.find_one({'email': admin_email, 'password': admin_password})
        if existing_admin:
            # Set the email in the session if needed
            session['admin_email'] = admin_email
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('LoginUnsuccessful.html')

    return render_template('AdminLogin.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Fetch orders of the current day
    start_of_day = datetime.combine(datetime.today(), datetime.min.time())
    end_of_day = datetime.combine(datetime.today(), datetime.max.time())

    orders = list(Order.find({'$and': [{'timeofdelivery': {'$gte': start_of_day, '$lte': end_of_day}},
                                       {'settlement_status': False }]}))

    # Organize orders by blood bank and blood component
    organized_orders = defaultdict(lambda: defaultdict(list))
    for order in orders:
        blood_bank_id = order['BloodBank_Id']
        component = order['BloodComp']
        organized_orders[blood_bank_id][component].append(order)

    # Prepare the transactions data for the template
    transactions = []
    for blood_bank_id, components in organized_orders.items():
        blood_bank = BBUser.find_one({'reg_num': blood_bank_id})
        for component, orders in components.items():
            quantity_sold = sum(order['BloodQuantity'] for order in orders)
            price_per_unit = orders[0]['total_amount'] / orders[0]['BloodQuantity']  # Assuming total_amount is for the quantity sold
            total_amount_per_component = quantity_sold * price_per_unit
            total_amount_payable = sum(order['total_amount'] for order in orders)

            transactions.append({
                'blood_bank_name': blood_bank['bb_name'],
                'address': blood_bank['address'],
                'contact_no': blood_bank['contact_num'],
                'component': component,
                'quantity_sold': quantity_sold,
                'price_per_unit': price_per_unit,
                'total_amount_per_component': total_amount_per_component,
                'total_amount_payable': total_amount_payable,
                '_id': str(orders[0]['_id'])  # Assuming each order has a unique '_id'
            })

    return render_template('AdminDashboard.html', transactions=transactions)


######## ###

@app.route('/HospSignIn', methods=['POST'])
def HospsignIn():
    if request.method == 'POST':
        hosp_email = request.form.get('hospEmailId')
        hosp_password = request.form.get('hospPassword')

        # Check if the user exists and their email is verified
        existing_user = HospUser.find_one({'email': hosp_email, 'password': hosp_password, 'email_verified': True})
        
        if existing_user:
            hosp_reg_no = existing_user.get('reg_num')

            # Set the registration number in the session
            session['hosp_reg_no'] = hosp_reg_no 

            # Redirect to the hospital dashboard or render a template
            # return redirect(url_for('HospDashboard'))
            return render_template('HospitalDashboard.html',  hosp_reg_no=hosp_reg_no )

        else:
            # If user login is unsuccessful due to unverified email
            return render_template('LoginUnsuccessful.html')

    # If the request method is not POST, render the login page
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
        existing_user = PatientUser.find_one({'email': p_email, 'password': p_password, 'email_verified': True})
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
    subject = 'Email Verification for Authentication'
    body = f'''<p>Dear User,</p>
        <p>Welcome to TransfusioTrack!</p>
        <p>TransfusioTrack is India's first blood bag order placing and delivery system, innovating seamless blood delivery through advanced technology.</p>
        <p>To verify your email and unlock the full features of our platform, please click the following link:</p>
        <p><a href="{url_for("verify_email", token=token, _external=True)}">Verify Email</a></p>
        <p>This verification is crucial to protect your account from any unauthorized access or theft. Once verified, you will gain access to blood bag order placing and smooth delivery services.</p>
        <p>If you did not request this verification or suspect any unauthorized activity, please report it to us immediately at <a href="mailto:transfusiotrack@gmail.com">transfusiotrack@gmail.com</a>. Do not verify the link until you confirm its legitimacy.</p>
        <p>In case of any issues with verification or further assistance, please feel free to contact us at the provided email address.</p>
        <p>Thank you for choosing TransfusioTrack!</p>
        <p>Regards,</p>
        <p>TransfusioTrack Team</p>'''

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
    subject = 'Email Verification for Authentication'
    body = f'''<p>Dear User,</p>
        <p>Welcome to TransfusioTrack!</p>
        <p>TransfusioTrack is India's first blood bag order placing and delivery system, innovating seamless blood delivery through advanced technology.</p>
        <p>To verify your email and unlock the full features of our platform, please click the following link:</p>
        <p><a href="{url_for("verify_email_patient", token=token, _external=True)}">Verify Email</a></p>
        <p>This verification is crucial to protect your account from any unauthorized access or theft. Once verified, you will gain access to blood bag order placing and smooth delivery services.</p>
        <p>If you did not request this verification or suspect any unauthorized activity, please report it to us immediately at <a href="mailto:transfusiotrack@gmail.com">transfusiotrack@gmail.com</a>. Do not verify the link until you confirm its legitimacy.</p>
        <p>In case of any issues with verification or further assistance, please feel free to contact us at the provided email address.</p>
        <p>Thank you for choosing TransfusioTrack!</p>
        <p>Regards,</p>
        <p>TransfusioTrack Team</p>'''

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
############################################ Otp Validation ############################################
# @app.route('/verify_otp', methods=['POST'])
# def verify_otp():
#     if request.method == 'POST':
#         # Get the entered OTP from the form
#         entered_otp = request.form.get('otp')

#         # Retrieve the order ID from the request or session, assuming it's stored as 'order_id'
#         order_id = request.form.get('order_id')

#         # Retrieve the order details from the backend MongoDB collection
#         order = Order.find_one({'_id': ObjectId(order_id)})

#         if order:
#             # Retrieve the stored OTP from the order details
#             stored_otp = order.get('otp')

#             # Check if the entered OTP matches the stored OTP
#             if entered_otp == stored_otp:
#                 # Convert current time to Kolkata timezone
#                 ist_timezone = pytz.timezone('Asia/Kolkata')
#                 current_datetime = datetime.now(pytz.utc).astimezone(ist_timezone)

#                 # Update the order with timeofdelivery and status delivered
#                 Order.update_one(
#                     {'_id': ObjectId(order_id)},
#                     {'$set': {'status': 'delivered', 'timeofdelivery': current_datetime}}
#                 )

#                 # Render a success template with the appropriate message
#                 return render_template('otpsuccess.html', message="Blood bag delivered successfully.")
#             else:
#                 # Render an error template with the appropriate message
#                 return render_template('otperror.html', message="Invalid OTP. Please try again.")
#         else:
#             # Render an error template with the appropriate message
#             return render_template('error.html', message="Order not found.")

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        # Get the entered OTP from the form
        entered_otp = request.form.get('otp')

        # Retrieve the order ID from the request or session, assuming it's stored as 'order_id'
        order_id = request.form.get('order_id')

        # Retrieve the order details from the backend MongoDB collection
        order = Order.find_one({'_id': ObjectId(order_id)})

        if order:
            # Retrieve the stored OTP from the order details
            stored_otp = order.get('otp')

            # Get patient details
            patient_fname = order.get('fname')
            patient_mname = order.get('pmname')
            patient_lname = order.get('lname')

            # Get additional details
            blood_grp = order.get('BloodGrp')
            blood_comp = order.get('BloodComp')
            blood_quantity = order.get('BloodQuantity')

            if entered_otp == stored_otp:
                # Convert current time to Kolkata timezone
                ist_timezone = pytz.timezone('Asia/Kolkata')
                current_datetime = datetime.now(pytz.utc).astimezone(ist_timezone)

                # Update the order with timeofdelivery and status delivered
                Order.update_one(
                    {'_id': ObjectId(order_id)},
                    {'$set': {'status': 'delivered', 'timeofdelivery': str(current_datetime)}}
                )
                
                # Prepare email content
                subject_patient = f"Order Delivered - {patient_fname} {patient_mname} {patient_lname}"
                subject_blood_bank = f"You have successfully Delivered Blood Bag - {patient_fname} {patient_mname} {patient_lname}"
                user_email = ''
                hospital_name = ''
                bb_email = ''
                bb_name = ''
                hospital_user = HospUser.find_one({'reg_num': order['User_ID']})
                if hospital_user:
                    user_email = hospital_user['email']
                    hospital_name = hospital_user['facility_name']
            
                patient_user = PatientUser.find_one({'email': order['User_ID']})
                if patient_user:
                    user_email = patient_user['email']

                bb_user = BBUser.find_one({'reg_num': order['BloodBank_Id']})
                if bb_user:
                    bb_email = bb_user['email']
                    bb_name = bb_user['bb_name']
                    
                body_patient = f"<p style='margin-bottom: 20px;'>Your blood bag has been successfully delivered.</p>"\
                   f"<h2 style='margin-top: 20px; margin-bottom: 10px;'>Order Details:</h2>"\
                   f"<table style='border-collapse: collapse; width: 100%;'>"\
                   f"<tr style='background-color: #f2f2f2;'>"\
                   f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Attribute</th>"\
                   f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Value</th>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Order ID</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_id}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Name</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_fname} {patient_mname} {patient_lname}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Group</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_grp}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Component</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_comp}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Quantity</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_quantity}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Bank Name</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{bb_name}</td>"\
                   f"</tr>"\
                   f"<tr>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Time of Delivery</td>"\
                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{current_datetime.strftime('%Y-%m-%d %H:%M:%S')}</td>"\
                   f"</tr>"\
                   f"</table>"

                body_blood_bank = f"<p style='margin-bottom: 20px;'>You have successfully delivered the blood bag.</p>"\
                                  f"<h2 style='margin-top: 20px; margin-bottom: 10px;'>Order Details:</h2>"\
                                  f"<table style='border-collapse: collapse; width: 100%;'>"\
                                  f"<tr style='background-color: #f2f2f2;'>"\
                                  f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Attribute</th>"\
                                  f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Value</th>"\
                                  f"</tr>"\
                                  f"<tr>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Order ID</td>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_id}</td>"\
                                  f"</tr>"\
                                  f"<tr>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Name</td>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_fname} {patient_mname} {patient_lname}</td>"\
                                  f"</tr>"\
                                  f"<tr>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Group</td>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_grp}</td>"\
                                  f"</tr>"\
                                  f"<tr>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Component</td>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_comp}</td>"\
                                  f"</tr>"\
                                  f"<tr>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Quantity</td>"\
                                  f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_quantity}</td>"\
                                  f"</tr>"
                
                if hospital_user:
                    body_blood_bank += f"<tr>"\
                                       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Hospital Name</td>"\
                                       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{hospital_name}</td>"\
                                       f"</tr>"
                
                body_blood_bank += f"<tr>"\
                                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Time of Delivery</td>"\
                                   f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{current_datetime.strftime('%Y-%m-%d %H:%M:%S')}</td>"\
                                   f"</tr>"\
                                   f"</table>"

                
                
                # Send email to hospital/patient
                send_delivery_email(recipient_email=user_email, subject=subject_patient, body=body_patient)

                # Send email to blood bank
                send_delivery_email(recipient_email=bb_email, subject=subject_blood_bank, body=body_blood_bank)

                # Render a success template with the appropriate message and patient details
                return render_template('otpsuccess.html', message="Blood bag delivered successfully.",
                                       patient_fname=patient_fname, patient_mname=patient_mname,
                                       patient_lname=patient_lname, blood_grp=blood_grp,
                                       blood_comp=blood_comp, blood_quantity=blood_quantity)
            else:
                # Render an error template with the appropriate message and patient details
                return render_template('otperror.html', message="Invalid OTP. Please try again.",
                                       patient_fname=patient_fname, patient_mname=patient_mname,
                                       patient_lname=patient_lname, blood_grp=blood_grp,
                                       blood_comp=blood_comp, blood_quantity=blood_quantity)
        else:
            # Render an error template with the appropriate message
            return render_template('error.html', message="Order not found.")
            

def send_delivery_email(recipient_email, subject, body):
    # Prepare message
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient_email

    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, recipient_email, msg.as_string())
        server.quit()

        # Log email sent
        print(f"Email sent to {recipient_email} with subject: {subject}")

    except Exception as e:
        # Log error if email sending fails
        print(f"Error sending email: {e}")




# @app.route('/otp_verification', methods=['GET', 'POST'])
# def otp_verification():
#     if request.method == 'GET':
#         order_id = request.args.get('order_id')
#         return render_template('delivery_otp_verification.html', order_id=order_id)


@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'GET':
        order_id = request.args.get('order_id')
        
        # Check if order_id is provided
        if order_id:
            # Retrieve the order details from the backend MongoDB collection
            order = Order.find_one({'_id': ObjectId(order_id)})
            
            if order:
                # Fetch patient and order details
                patient_fname = order.get('fname')
                patient_lname = order.get('lname')
                blood_grp = order.get('BloodGrp')
                blood_comp = order.get('BloodComp')
                blood_quantity = order.get('BloodQuantity')

                return render_template('delivery_otp_verification.html', order_id=order_id,
                                       patient_fname=patient_fname, patient_lname=patient_lname,
                                       blood_grp=blood_grp, blood_comp=blood_comp, blood_quantity=blood_quantity)
            else:
                # Order not found
                return render_template('error.html', message="Order not found.")
        else:
            # No order_id provided
            return render_template('error.html', message="Invalid request. Please provide an order_id.")
    
    # Method is not GET
    return render_template('error.html', message="Invalid request method.")



# @app.route('/otp_verification', methods=['GET', 'POST'])
# def otp_verification():
#     if request.method == 'GET':
#         order_id = request.args.get('order_id')

#         # Check if order_id is provided
#         if order_id:
#             # Check the status of the order
#             order = Order.find_one({'_id': ObjectId(order_id), 'BloodBank_Id': session.get('bb_reg_no')})
            
#             if order:
#                 status = order.get('status')
#                 if status == 'delivered':
#                     # Fetch patient details and time of delivery
#                     patient_fname = order.get('fname')
#                     patient_lname = order.get('lname')
#                     time_of_delivery = order.get('timeofdelivery').strftime("%Y-%m-%d %H:%M:%S")

#                     return render_template('BBalreadyDel.html', order_id=order_id,
#                                            patient_fname=patient_fname, patient_lname=patient_lname,
#                                            time_of_delivery=time_of_delivery)
#                 elif status == 'dispatched':
#                     # Fetch patient and order details
#                     patient_fname = order.get('fname')
#                     patient_lname = order.get('lname')
#                     blood_grp = order.get('BloodGrp')
#                     blood_comp = order.get('BloodComp')
#                     blood_quantity = order.get('BloodQuantity')

#                     return render_template('delivery_otp_verification.html', order_id=order_id,
#                                            patient_fname=patient_fname, patient_lname=patient_lname,
#                                            blood_grp=blood_grp, blood_comp=blood_comp, blood_quantity=blood_quantity)
#             else:
#                 # Order not found
#                 return render_template('error.html', message="Order not found.")
#         else:
#             # No order_id provided
#             return render_template('error.html', message="Invalid request. Please provide an order_id.")
    
#     # Method is not GET
#     return render_template('error.html', message="Invalid request method.")





    

def update_delivery_status(order_id):
    # Generate 4-digit OTP
    otp = ''.join(random.choices('0123456789', k=4))

    # Convert current time to IST
    ist_timezone = pytz.timezone('Asia/Kolkata')
    current_datetime_ist = datetime.now(ist_timezone)

    # Update the status to 'dispatched', add timestamp for time of dispatch (in IST), and store OTP
    Order.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'dispatched', 'timeofdispatch': str(current_datetime_ist), 'otp': otp}}
    )

    user_id = Order.find_one({'_id': ObjectId(order_id)})['User_ID']

    # Define a callback function to be called after sending dispatch email
    def callback():
        blood_bank_id = Order.find_one({'_id': ObjectId(order_id)})['BloodBank_Id']
        blood_bank_email = BBUser.find_one({'reg_num': blood_bank_id})['email']
        send_otp_verification_email(blood_bank_email, order_id)
        
    # Find user email
    hospital_user = HospUser.find_one({'reg_num': user_id})
    if hospital_user:
        send_dispatch_email(hospital_user['email'], otp, order_id, callback)
        return

    # Find user email in PatientUser collection
    patient_user = PatientUser.find_one({'email': user_id})
    if patient_user:
        send_dispatch_email(patient_user['email'], otp, order_id, callback)
        return    
    

def send_otp_verification_email(recipient_email, order_id):
    # Fetch order details from the database using the order ID
    order_details = Order.find_one({'_id': ObjectId(order_id)})
    if not order_details:
        print(f"Order with ID {order_id} not found.")
        return

    # Extract relevant order information
    patient_name = f"{order_details['fname']} {order_details['mname']} {order_details['lname']}"
    patient_address = ''
    patient_contact = ''
    hospital_name = ''
    hospital_address = ''
    hospital_contact = ''
    hospital_user = HospUser.find_one({'reg_num': order_details['User_ID']})
    if hospital_user:
        hospital_name = hospital_user['facility_name']
        hospital_address = hospital_user['address']
        hospital_contact = hospital_user['contact_num']

    patient_user = PatientUser.find_one({'email': order_details['User_ID']})
    if patient_user:
        patient_address = patient_user['address']
        patient_contact = patient_user['contact_num']

    # Construct the OTP verification link
    otp_verification_link = f"http://www.transfusiotrack.com/otp_verification?order_id={order_id}"

    # Construct email content
    subject = f"Blood Bag Dispatched - Patient: {patient_name}"
    body = f"<p style='margin-bottom: 20px;'>To confirm receipt and verify delivery, please click the following link and enter the OTP provided by the patient - Blood Receiver:</p>"\
       f"<p><a href='{otp_verification_link}' style='display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;'>Verify Delivery</a></p>"\
       f"<h2 style='margin-top: 20px; margin-bottom: 10px;'>Order Details:</h2>"\
       f"<table style='border-collapse: collapse; width: 100%;'>"\
       f"<tr style='background-color: #f2f2f2;'>"\
       f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Attribute</th>"\
       f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Value</th>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Order ID</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_id}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Name</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_name}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Group</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodGrp']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Component</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodComp']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Quantity</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodQuantity']}</td>"\
       f"</tr>"

    if hospital_name:
        body += f"<tr>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Hospital Name</td>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{hospital_name}</td>"\
                f"</tr>"\
                f"<tr>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Hospital Address</td>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{hospital_address}</td>"\
                f"</tr>"\
                f"<tr>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Hospital Contact No.</td>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{hospital_contact}</td>"\
                f"</tr>"
    else:
        body += f"<tr>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Address</td>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_address}</td>"\
                f"</tr>"\
                f"<tr>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Contact No.</td>"\
                f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_contact}</td>"\
                f"</tr>"
    
    body += f"</table>"

    # Prepare message
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient_email

    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, recipient_email, msg.as_string())
        server.quit()

        # Log email sent
        print(f"Dispatch email sent to {recipient_email} for Order ID: {order_id}")

    except Exception as e:
        # Log error if email sending fails
        print(f"Error sending dispatch email: {e}")



def send_dispatch_email(recipient_email, otp, order_id, callback=None):
    # Fetch order details from the database
    print("order_id type:", type(order_id))
    print("order_id value:", order_id)
    order_details = Order.find_one({'_id': ObjectId(order_id)})
    if not order_details:
        print("Order details not found.")
        return

    patient_name = f"{order_details['fname']} {order_details['mname']} {order_details['lname']}"
    blood_bank_id = Order.find_one({'_id': ObjectId(order_id)})['BloodBank_Id']
    blood_bank_name = BBUser.find_one({'reg_num': blood_bank_id})['bb_name']
    blood_bank_address = BBUser.find_one({'reg_num': blood_bank_id})['address']
    blood_bank_contact = BBUser.find_one({'reg_num': blood_bank_id})['contact_num']
    # Construct email content
    subject = f"Blood Bag Dispatched - Patient: {patient_name}"
    body = f"<h2 style='margin-top: 20px; margin-bottom: 10px;'>Blood Bag Dispatched</h2>"\
       f"<p style='margin-bottom: 20px;'>Your blood bag has been dispatched. Please expect delivery soon.</p>"\
       f"<p style='margin-bottom: 20px;'>Kindly share the OTP ({otp}) with the delivery person to receive the blood bag.</p>"\
       f"<h3 style='margin-top: 20px; margin-bottom: 10px;'>Order Details:</h3>"\
       f"<table style='border-collapse: collapse; width: 100%;'>"\
       f"<tr style='background-color: #f2f2f2;'>"\
       f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Attribute</th>"\
       f"<th style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Value</th>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Order ID</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['_id']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Patient Name</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{patient_name}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Group</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodGrp']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Component</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodComp']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Quantity</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{order_details['BloodQuantity']}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Bank Name</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_bank_name}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Bank Address</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_bank_address}</td>"\
       f"</tr>"\
       f"<tr>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>Blood Bank Contact No.</td>"\
       f"<td style='border: 1px solid #dddddd; text-align: left; padding: 8px;'>{blood_bank_contact}</td>"\
       f"</tr>"\
       f"</table>"

    # Prepare message
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient_email

    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, recipient_email, msg.as_string())
        server.quit()

        # Log email sent
        print(f"Dispatch email sent to {recipient_email} with OTP: {otp}")

        # Execute callback function if provided
        if callback:
            callback()

    except Exception as e:
        # Log error if email sending fails
        print(f"Error sending dispatch email: {e}")


@app.route('/initiate_delivery', methods=['POST'])
def initiate_delivery():
    if request.method == 'POST':
        order_id = request.form.get('selected_order')

        # Assuming you have a function to update the status in your MongoDB collection
        update_delivery_status(order_id)

        # Query MongoDB to get the specific order
        order = Order.find_one({'_id': ObjectId(order_id)})
        if order:
            user_id = order.get('User_ID')
            user_details = None

            # Search for user details in the hospital collection
            hospital_details = HospUser.find_one({'reg_num': user_id})
            if hospital_details:
                user_details = hospital_details
            else:
                # Search for user details in the patient collection
                patient_details = PatientUser.find_one({'email': user_id})
                if patient_details:
                    user_details = patient_details

            if user_details:
                formatted_order = {
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
                    'docname': order.get('docname'),
                    'gender': order.get('gender'),
                    'user_name': user_details.get('facility_name') or user_details.get('patient_name'),
                    'user_address': user_details.get('address'),
                    'phone_number': user_details.get('contact_num')
                }

                # Handle timestamps, split to remove milliseconds if present
                if 'timestamp' in order:
                    formatted_order['timestamp'] = order['timestamp'].split('.')[0]

                if 'timeofdispatch' in order:
                    formatted_order['timeofdispatch'] = order['timeofdispatch'].split('.')[0]

                # Pass the order details to the template
                return render_template('dispatched.html', order=formatted_order)

    return render_template('dispatched.html', order=None)





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

#################################### order fetching logic #####################

@app.route('/delorder', methods=['GET'])
def bloodbank_completed_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id': session.get('bb_reg_no'), 'status': 'delivered'})

    # Prepare the results to be displayed
    order_list = []
    ist_timezone = pytz.timezone('Asia/Kolkata')

    for order in orders:
        user_id = order.get('User_ID')
        user_details = None

        # Search for user details in the hospital collection
        hospital_details = HospUser.find_one({'reg_num': user_id})
        if hospital_details:
            user_details = hospital_details
        else:
            # Search for user details in the patient collection
            patient_details = PatientUser.find_one({'email': user_id})
            if patient_details:
                user_details = patient_details

        if user_details:
            formatted_order = {
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
                'docname': order.get('docname'),
                'gender': order.get('gender'),
                'user_name': user_details.get('facility_name') or user_details.get('patient_name'),
                'user_address': user_details.get('address'),
                'phone_number': user_details.get('contact_num')
            }

            # Format timestamps if they exist
            if 'timestamp' in order:
                utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
                ist_timestamp = utc_timestamp.astimezone(ist_timezone)
                formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdispatch' in order:
                utc_timeofdispatch = order['timeofdispatch'].replace(tzinfo=pytz.utc)
                ist_timeofdispatch = utc_timeofdispatch.astimezone(ist_timezone)
                formatted_order['timeofdispatch'] = ist_timeofdispatch.strftime('%Y-%m-%d %H:%M:%S')

            if 'timeofdelivery' in order:
                utc_timeofdelivery = order['timeofdelivery'].replace(tzinfo=pytz.utc)
                ist_timeofdelivery = utc_timeofdelivery.astimezone(ist_timezone)
                formatted_order['timeofdelivery'] = ist_timeofdelivery.strftime('%Y-%m-%d %H:%M:%S')

            order_list.append(formatted_order)

    return render_template('DeliveredBags.html', orders=order_list)


@app.route('/dispatched', methods=['GET'])
def bloodbank_dispatched_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id': session.get('bb_reg_no'), 'status': 'dispatched'})

    # Prepare the results to be displayed
    order_list = []
    ist_timezone = pytz.timezone('Asia/Kolkata')

    for order in orders:
        user_id = order.get('User_ID')
        user_details = None

        # Search for user details in the hospital collection
        hospital_details = HospUser.find_one({'reg_num': user_id})
        if hospital_details:
            user_details = hospital_details
        else:
            # Search for user details in the patient collection
            patient_details = PatientUser.find_one({'email': user_id})
            if patient_details:
                user_details = patient_details

        if user_details:
            formatted_order = {
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
                'docname': order.get('docname'),
                'gender': order.get('gender'),
                'user_name': user_details.get('facility_name') or user_details.get('patient_name'),
                'user_address': user_details.get('address'),
                'phone_number': user_details.get('contact_num')
            }

            # Format timestamps if they exist
            if 'timestamp' in order:
                utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
                ist_timestamp = utc_timestamp.astimezone(ist_timezone)
                formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdispatch' in order:
                utc_timeofdispatch = order['timeofdispatch'].replace(tzinfo=pytz.utc)
                ist_timeofdispatch = utc_timeofdispatch.astimezone(ist_timezone)
                formatted_order['timeofdispatch'] = ist_timeofdispatch.strftime('%Y-%m-%d %H:%M:%S')

            order_list.append(formatted_order)

    return render_template('BBDispatch.html', orders=order_list)
    

@app.route('/delorder1', methods=['GET'])
def hosp_received_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id': session.get('bb_reg_no'), 'status': 'delivered'})

    # Prepare the results to be displayed
    order_list = []
    ist_timezone = pytz.timezone('Asia/Kolkata')

    for order in orders:
        # Query blood bank details
        blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})
        
        if blood_bank_details:
            formatted_order = {
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
                'docname': order.get('docname'),
                'gender': order.get('gender'),
                'user_name': blood_bank_details.get('bb_name'),
                'user_address': blood_bank_details.get('address'),
                'phone_number': blood_bank_details.get('contact_num')
            }

            # Format timestamps if they exist
            if 'timestamp' in order:
                utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
                ist_timestamp = utc_timestamp.astimezone(ist_timezone)
                formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdispatch' in order:
                utc_timeofdispatch = order['timeofdispatch'].replace(tzinfo=pytz.utc)
                ist_timeofdispatch = utc_timeofdispatch.astimezone(ist_timezone)
                formatted_order['timeofdispatch'] = ist_timeofdispatch.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdelivery' in order:
                utc_timeofdelivery = order['timeofdelivery'].replace(tzinfo=pytz.utc)
                ist_timeofdelivery = utc_timeofdelivery.astimezone(ist_timezone)
                formatted_order['timeofdelivery'] = ist_timeofdelivery.strftime('%Y-%m-%d %H:%M:%S')
            
            order_list.append(formatted_order)

    return render_template('Receivedbags.html', orders=order_list)


@app.route('/delorder2', methods=['GET'])
def patient_received_orders():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID': session.get('_id'), 'status': 'delivered'})

    # Prepare the results to be displayed
    order_list = []
    ist_timezone = pytz.timezone('Asia/Kolkata')
    
    for order in orders:
        # Query blood bank details
        blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})
        
        if blood_bank_details:
            formatted_order = {
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
                'docname': order.get('docname'),
                'gender': order.get('gender'),
                'user_name': blood_bank_details.get('bb_name'),
                'user_address': blood_bank_details.get('address'),
                'phone_number': blood_bank_details.get('contact_num')
            }

            # Format timestamps if they exist
            if 'timestamp' in order:
                utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
                ist_timestamp = utc_timestamp.astimezone(ist_timezone)
                formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdispatch' in order:
                utc_timeofdispatch = order['timeofdispatch'].replace(tzinfo=pytz.utc)
                ist_timeofdispatch = utc_timeofdispatch.astimezone(ist_timezone)
                formatted_order['timeofdispatch'] = ist_timeofdispatch.strftime('%Y-%m-%d %H:%M:%S')
                
            if 'timeofdelivery' in order:
                utc_timeofdelivery = order['timeofdelivery'].replace(tzinfo=pytz.utc)
                ist_timeofdelivery = utc_timeofdelivery.astimezone(ist_timezone)
                formatted_order['timeofdelivery'] = ist_timeofdelivery.strftime('%Y-%m-%d %H:%M:%S')

            order_list.append(formatted_order)

    return render_template('PatientReceivedbags.html', orders=order_list)

################################################################

# @app.route('/BBNewReq', methods=['GET'])
# def Blood_bag_inProgress():
#     # Query MongoDB to get all orders
#     orders = Order.find({'BloodBank_Id': session.get('bb_reg_no'), 'status': 'undelivered'})

#     # Prepare the results to be displayed
#     order_list = []
#     for order in orders:
#         user_id = order.get('User_ID')
#         user_details = None

#         # Search for user details in the hospital collection
#         hospital_details = HospUser.find_one({'reg_num': user_id})
#         if hospital_details:
#             user_details = hospital_details
#         else:
#             # Search for user details in the patient collection
#             patient_details = PatientUser.find_one({'email': user_id})
#             if patient_details:
#                 user_details = patient_details

#         if user_details:
#             # Convert timestamp to Indian Standard Time (IST) and format it
#             ist_timezone = pytz.timezone('Asia/Kolkata')
#             timestamp = order.get('timestamp')
#             if timestamp:
#                 utc_timestamp = timestamp.replace(tzinfo=pytz.utc)
#                 ist_timestamp = utc_timestamp.astimezone(ist_timezone)
#                 formatted_timestamp = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')
#             else:
#                 formatted_timestamp = None

#             order_list.append({
#                 '_id': order.get('_id'),
#                 'User_ID': user_id,
#                 'BloodBank_Id': order.get('BloodBank_Id'),
#                 'BloodGrp': order.get('BloodGrp'),
#                 'BloodComp': order.get('BloodComp'),
#                 'BloodQuantity': order.get('BloodQuantity'),
#                 'req_type': order.get('req_type'),
#                 'fname': order.get('fname'),
#                 'mname': order.get('mname'),
#                 'lname': order.get('lname'),
#                 'age': order.get('age'),
#                 'docname': order.get('docname'),
#                 'gender': order.get('gender'),
#                 'timestamp': formatted_timestamp,
#                 'user_name': user_details.get('facility_name') or user_details.get('patient_name'),
#                 'user_address': user_details.get('address'),
#                 'phone_number': user_details.get('contact_num')
#             })

#     return render_template('BBNewReq.html', orders=order_list)



@app.route('/BBNewReq', methods=['GET'])
def Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'BloodBank_Id': session.get('bb_reg_no'), 'status': 'undelivered'})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        user_id = order.get('User_ID')
        user_details = None

        # Search for user details in the hospital collection
        hospital_details = HospUser.find_one({'reg_num': user_id})
        if hospital_details:
            user_details = hospital_details
        else:
            # Search for user details in the patient collection
            patient_details = PatientUser.find_one({'email': user_id})
            if patient_details:
                user_details = patient_details

        if user_details:
            # Handle the timestamp, remove milliseconds
            timestamp = order.get('timestamp', '')
            formatted_timestamp = timestamp.split('.')[0] if timestamp else None

            order_list.append({
                '_id': order.get('_id'),
                'User_ID': user_id,
                'BloodBank_Id': order.get('BloodBank_Id'),
                'BloodGrp': order.get('BloodGrp'),
                'BloodComp': order.get('BloodComp'),
                'BloodQuantity': order.get('BloodQuantity'),
                'req_type': order.get('req_type'),
                'fname': order.get('fname'),
                'mname': order.get('mname'),
                'lname': order.get('lname'),
                'age': order.get('age'),
                'docname': order.get('docname'),
                'gender': order.get('gender'),
                'timestamp': formatted_timestamp,
                'user_name': user_details.get('facility_name') or user_details.get('patient_name'),
                'user_address': user_details.get('address'),
                'phone_number': user_details.get('contact_num')
            })

    return render_template('BBNewReq.html', orders=order_list)


##############################################

# @app.route('/Hosp_Pending_Req', methods=['GET'])
# def Hosp_Blood_bag_inProgress():
#     # Query MongoDB to get all orders
#     orders = Order.find({'User_ID': session.get('hosp_reg_no')})

#     # Prepare the results to be displayed
#     order_list = []
#     for order in orders:
#         # Query blood bank details
#         blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})

#         # Convert timestamps to Indian Standard Time (IST) and format them
#         ist_timezone = pytz.timezone('Asia/Kolkata')
#         formatted_order = {
#             '_id': order.get('_id'),
#             'User_ID': order.get('User_ID'),
#             'BloodBank_Id': order.get('BloodBank_Id'),
#             'BloodGrp': order.get('BloodGrp'),
#             'BloodComp': order.get('BloodComp'),
#             'BloodQuantity': order.get('BloodQuantity'),
#             'req_type': order.get('req_type'),
#             'fname': order.get('fname'),
#             'mname': order.get('mname'),
#             'lname': order.get('lname'),
#             'age': order.get('age'),
#             'docname': order.get('docname'),
#             'gender': order.get('gender'),
#             'user_name': blood_bank_details.get('bb_name'),
#             'user_address': blood_bank_details.get('address'),
#             'phone_number': blood_bank_details.get('contact_num'),
#             'status': order.get('status')
#         }

#         # Format timestamps if they exist
#         if 'timestamp' in order:
#             utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
#             ist_timestamp = utc_timestamp.astimezone(ist_timezone)
#             formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')

#         order_list.append(formatted_order)

#     return render_template('HospitalPendingReq.html', orders=order_list)


@app.route('/Hosp_Pending_Req', methods=['GET'])
def Hosp_Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID': session.get('hosp_reg_no')})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        # Query blood bank details
        blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})

        formatted_order = {
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
            'docname': order.get('docname'),
            'gender': order.get('gender'),
            'user_name': blood_bank_details.get('bb_name') if blood_bank_details else None,
            'user_address': blood_bank_details.get('address') if blood_bank_details else None,
            'phone_number': blood_bank_details.get('contact_num') if blood_bank_details else None,
            'status': order.get('status'),
            'timestamp': order.get('timestamp', '').split('.')[0] if 'timestamp' in order else None
        }

        order_list.append(formatted_order)

    return render_template('HospitalPendingReq.html', orders=order_list)


##############################

# @app.route('/Patient_Pending_Req', methods=['GET'])
# def Patient_Blood_bag_inProgress():
#     # Query MongoDB to get all orders
#     orders = Order.find({'User_ID': session.get('_id')})

#     # Prepare the results to be displayed
#     order_list = []
#     for order in orders:
#         # Query blood bank details
#         blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})
        
#         if blood_bank_details:
#             # Convert timestamp to Indian Standard Time (IST) and format them
#             ist_timezone = pytz.timezone('Asia/Kolkata')

#             formatted_order = {
#                 '_id': order.get('_id'),
#                 'User_ID': order.get('User_ID'),
#                 'BloodBank_Id': order.get('BloodBank_Id'),
#                 'BloodGrp': order.get('BloodGrp'),
#                 'BloodComp': order.get('BloodComp'),
#                 'BloodQuantity': order.get('BloodQuantity'),
#                 'req_type': order.get('req_type'),
#                 'fname': order.get('fname'),
#                 'mname': order.get('mname'),
#                 'lname': order.get('lname'),
#                 'age': order.get('age'),
#                 'docname': order.get('docname'),
#                 'gender': order.get('gender'),
#                 'user_name': blood_bank_details.get('bb_name'),
#                 'user_address': blood_bank_details.get('address'),
#                 'phone_number': blood_bank_details.get('contact_num'),
#                 'status': order.get('status')
#             }

#             # Format timestamps if they exist
#             if 'timestamp' in order:
#                 utc_timestamp = order['timestamp'].replace(tzinfo=pytz.utc)
#                 ist_timestamp = utc_timestamp.astimezone(ist_timezone)
#                 formatted_order['timestamp'] = ist_timestamp.strftime('%Y-%m-%d %H:%M:%S')

#             order_list.append(formatted_order)

#     return render_template('PatientPendingReq.html', orders=order_list)


@app.route('/Patient_Pending_Req', methods=['GET'])
def Patient_Blood_bag_inProgress():
    # Query MongoDB to get all orders
    orders = Order.find({'User_ID': session.get('_id')})

    # Prepare the results to be displayed
    order_list = []
    for order in orders:
        # Query blood bank details
        blood_bank_details = BBUser.find_one({'reg_num': order.get('BloodBank_Id')})

        formatted_order = {
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
            'docname': order.get('docname'),
            'gender': order.get('gender'),
            'user_name': blood_bank_details.get('bb_name'),
            'user_address': blood_bank_details.get('address'),
            'phone_number': blood_bank_details.get('contact_num'),
            'status': order.get('status'),
            'timestamp': order.get('timestamp', '').split('.')[0] if 'timestamp' in order else None
        }

        
        order_list.append(formatted_order)

    return render_template('PatientPendingReq.html', orders=order_list)



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


@app.route('/admindash')
def admindashboard():
    return render_template('AdminDashboard.html')


@app.route('/AdminLogin')
def adminL():
    return render_template('AdminLogin.html')






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
