from datetime import datetime
from bson import ObjectId
import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pymongo import MongoClient
import razorpay

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.urandom(24)


# MongoDB configuration
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

####################### Payment Razorpay ###########################

razorpay_client = razorpay.Client(auth=("rzp_test_VwLhATIx3XC6MI", "RqdEsP8mak311TwNRBxYQZZA"))

@app.route('/hosp_payment', methods=['POST'])
def Hosp_initiate_payment():
    # Process requisition form data and calculate the payment amount
    amount = 1000  # Replace with the actual amount

    # Create a Razorpay order
    order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': '1'})

    # Store the order details in the session
    session['razorpay_order_id'] = order['id']
    session['order_amount'] = order['amount']

    return render_template('HospPayment.html', order=order)

####### blood bank####
@app.route('/BB_payment', methods=['POST'])
def Blood_bank_initiate_payment():
    # Process requisition form data and calculate the payment amount
    amount = 1000  # Replace with the actual amount

    # Create a Razorpay order
    order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': '1'})

    # Store the order details in the session
    session['razorpay_order_id'] = order['id']
    session['order_amount'] = order['amount']

    return render_template('BBPayment.html', order=order)
#################


def update_requisition_status(order_id, param):
    pass


@app.route('/payment/success', methods=['POST'])
def payment_success():
    # Handle success callback from Razorpay
    razorpay_payment_id = request.form['razorpay_payment_id']
    razorpay_order_id = request.form['razorpay_order_id']
    razorpay_signature = request.form['razorpay_signature']

    # Verify the payment signature
    # Replace 'your_api_secret' with your actual Razorpay API secret
    is_valid_signature = razorpay_client.utility.verify_payment_signature({
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }, 'RqdEsP8mak311TwNRBxYQZZA')

    if is_valid_signature:
        # Payment success, update the requisition status in the database
        update_requisition_status(session.get('razorpay_order_id'), 'paid')
        return render_template('map.html')
    else:
        # Invalid signature, handle accordingly (e.g., redirect to try again page)
        return render_template('payment_try_again.html')


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
    orders = Order.find({'User_ID': session.get('hosp_reg_no'),'status': 'delivered'})

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

    return render_template('ReceivedBags.html', orders=order_list)


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

################################################

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if request.method == 'POST':
        # Get user input from the form
        req_type = request.form.get('reqtype')
        fname = request.form.get('fname')
        mname = request.form.get('mname')
        lname = request.form.get('lname')
        age = int(request.form.get('age'))
        ward = request.form.get('ward')
        bedno = request.form.get('bedno')
        gender = request.form.get('gender')

        # Decrease the quantity of blood bags in MongoDB
        blood_group = session.get('blood_group')
        blood_component = session.get('blood_component')
        requested_quantity = int(session.get('quantity'))

        # Create a dictionary with the form data
        form_data = {
            'User_ID': session.get('hosp_reg_no'),
            'BloodBank_Id': session.get('bb_reg_no'),
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
            'timestamp': datetime.now(),
            'status': 'undelivered'
        }

        # Insert the form data into the Order collection in MongoDB
        order_insert_result = Order.insert_one(form_data)
        order_id = order_insert_result.inserted_id  # Get the inserted order ID

        # Find the relevant blood bags in the database
        blood_bags = BloodStockAdd.find({'reg_num': session.get('bb_reg_no'),
                                         'blood_group': blood_group,
                                         'blood_component': blood_component})

        # Update the quantity of each blood bag
        for blood_bag in blood_bags:
            available_quantity = blood_bag.get('quantity', 0)
            if available_quantity >= requested_quantity:
                new_quantity = available_quantity - requested_quantity
                # Update the quantity in the database
                BloodStockAdd.update_one(
                    {'_id': blood_bag['_id']},
                    {'$set': {'quantity': new_quantity}}
                )
            else:
                # Handle insufficient quantity error
                return render_template('error.html', message='Insufficient quantity of blood bags.')

        # Assume you receive payment details from Razorpay success callback
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = str(order_id)  # Convert order ID to string
        # Add other relevant payment details you want to store in the database

        # Update the order status and store payment details in the database
        Order.update_one(
            {'_id': ObjectId(razorpay_order_id)},
            {
                '$set': {
                    'status': 'delivered',
                    'payment_id': razorpay_payment_id,
                    # Add other payment details here
                }
            }
        )

    return render_template('map.html')
#############################################


@app.route('/Psubmit_req', methods=['POST'])
def Patient_sr():
    if request.method == 'POST':
        # Get user input from the form
        req_type = request.form.get('reqtype')
        fname = request.form.get('fname')
        mname = request.form.get('mname')
        lname = request.form.get('lname')
        age = int(request.form.get('age'))
        ward = request.form.get('ward')
        bedno = request.form.get('bedno')
        gender = request.form.get('gender')


        # Decrease the quantity of blood bags in MongoDB

        blood_group = session.get('blood_group')
        blood_component = session.get('blood_component')
        requested_quantity = int(session.get('quantity'))

        # Create a dictionary with the form data
        form_data = {
            'User_ID': session.get('_id'),
            'BloodBank_Id': session.get('bb_reg_no'),
            'BloodGrp': blood_group,
            'BloodComp':blood_component,
            'BloodQuantity': requested_quantity,
            'req_type': req_type,
            'fname': fname,
            'mname': mname,
            'lname': lname,
            'age': age,
            'ward': ward,
            'bedno': bedno,
            'gender': gender,
            'timestamp': datetime.now(),
            'status': 'undelivered'
        }

        # Insert the form data into the Order collection in MongoDB
        Order.insert_one(form_data)



        # Find the relevant blood bags in the database
        blood_bags = BloodStockAdd.find({'reg_num':session.get('bb_reg_no'),'blood_group': blood_group, 'blood_component': blood_component})

        # Update the quantity of each blood bag
        for blood_bag in blood_bags:
            available_quantity = blood_bag.get('quantity', 0)
            if available_quantity >= requested_quantity:
                new_quantity = available_quantity - requested_quantity
                # Update the quantity in the database
                BloodStockAdd.update_one(
                    {'_id': blood_bag['_id']},
                    {'$set': {'quantity': new_quantity}}
                )
            else:
                # Handle insufficient quantity error
                return render_template('error.html', message='Insufficient quantity of blood bags.')

    return render_template('Patientmap.html')



##################################################
@app.route('/submit_order', methods=['POST'])
def submit_order():
    blood_type = request.form['blood_type']
    quantity = request.form['quantity']
    # Here, you can process the order, save it to a database, etc.
    return f"Order placed: Blood Type - {blood_type}, Quantity - {quantity}"


from flask import render_template, request, session

from flask import session

@app.route('/searchbb', methods=['POST'])
def search_blood_bag():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp')
        blood_component = request.form.get('comptype')
        quantity = int(request.form.get('quantity'))

        # Retrieve hosp_reg_no from the session
        hosp_reg_no = session.get('hosp_reg_no')

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
        session['blood_component'] = blood_component
        session['quantity'] = quantity

        # Return the results to the template along with hosp_reg_no
        return render_template('SearchResults.html', results=results, hosp_reg_no=hosp_reg_no)

    return render_template('SearchResults.html')



####################################################################
@app.route('/set_selected_blood_bank', methods=['POST'])
def set_selected_blood_bank():
    if request.method == 'POST':
        selected_blood_bank_reg_num = request.form.get('selected_blood_bank')

        # Check if a hospital or patient is logged in
        if 'hosp_reg_no' in session:
            # Set the selected blood bank reg_num in the session for a hospital
            session['bb_reg_no'] = selected_blood_bank_reg_num
            return render_template('BloodBagRequestForm.html')  # Redirect to the hospital's request form

        elif '_id' in session:
            # Set the selected blood bank reg_num in the session for a patient
            session['bb_reg_no'] = selected_blood_bank_reg_num
            return render_template('PatientBBreqform.html')  # Redirect to the patient's request form

    # Redirect to a default page or handle the case where the user type is not identified
    return render_template('error.html', message='User type not identified.')


###################################################################

@app.route('/PatientSearchBB', methods=['POST'])
def PsearchBB():
    if request.method == 'POST':
        # Get user input from the form
        blood_group = request.form.get('bloodgrp1')
        blood_component = request.form.get('comptype1')
        quantity = int(request.form.get('quantity1'))

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
        session['blood_component'] = blood_component
        session['quantity'] = quantity

        # Return the results to the template
        return render_template('PatientSearchResult.html', results=results)

    return render_template('PatientSearchResult.html')
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






###########################################

@app.route('/HospSignUp', methods=['POST'])
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
        existing_user = HospUser.find_one({'reg_num': facility_reg_num})
        if existing_user:
            return render_template('AlreadyExistHosp.html')

        # Create a new user document
        new_user = {
            'facility_name': facility_name,
            'email': facility_email,
            'password': facility_password,
            'contact_num': facility_contact_num,
            'address': facility_address,
            'reg_num': facility_reg_num
        }

        # Insert the new user into the MongoDB collection
        HospUser.insert_one(new_user)

    return render_template('HospitalDashboard.html')


@app.route('/HospSignIn', methods=['POST', 'GET'])
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
            
            return redirect(url_for('HospDashboard'))

        else:
            return render_template('LoginUnsuccessful.html')

    response = app.make_response(render_template('HospitalSignIn.html'))
 

    return response




@app.route('/PatientSign', methods=['POST'])
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

                        # You can redirect to the blood bank dashboard or render a template
            return render_template('PatientDashboard.html', p_email=p_email)
        else:
            return render_template('LoginUnsuccessful.html')

    return render_template('PatientDashboard.html')  # Update with the correct template name


@app.route('/HospDashboard')
def HospDashboard():
    # Retrieve the registration number from the session
    hosp_reg_no = session.get('hosp_reg_no')

    # Check if the user is logged in
    if hosp_reg_no:
        return render_template('HospitalDashboard.html', hosp_reg_no=hosp_reg_no)
    else:
        # Redirect to the login page if not logged in
        return redirect(url_for('HospsignIn'))


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


@app.route('/BBSignIn', methods=['POST'])
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

            # You can redirect to the blood bank dashboard or render a template
            return render_template('BloodBankDashboard.html', bb_email=bb_email)
        else:
            return render_template('LoginUnsuccessful.html')

    return render_template('BloodBankDashboard.html')  # Update with the correct template name

##############################################################################



@app.route('/Patientsignup', methods=['POST'])
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

        # Create a new user document
        new_user = {
            'patient_name': patient_name,
            'email': patient_email,
            'password': patient_password,
            'contact_num': contact_num,
            'address': address,
            'p_city': p_city
        }

        # Insert the new user into the MongoDB collection
        PatientUser.insert_one(new_user)

        return render_template('PatientDashboard.html')





##################################

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/PDashboard')
def pdash():
    return render_template('PatientDashboard.html')

@app.route('/HDashboard')
def hdash():
    return render_template('HospitalDashboard.html')


@app.route('/BBDashboard')
def bbdash():
    return render_template('BloodBankDashboard.html')

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


@app.route('/map')
def map():
    return render_template('map.html')

# @app.route('/dispatch')
# def dispatch():
#     return render_template('dispatched.html')


@app.route('/HospSign')
def Hospsign():
    return render_template('HospSignup.html')

@app.route('/BBSign')
def BBsign():
    return render_template('BBSignup.html')

@app.route('/PatientSign')
def Psign():
    return render_template('PatientLogin.html')

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
