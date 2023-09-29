from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/HospDashboard')
def teacher():
    return render_template('HospitalDashboard.html')

@app.route('/BBDashboard')
def price():
    return render_template('BloodBankDashboard.html')

@app.route('/BBNewReq')
def review():
    return render_template('BBNewReq.html')

@app.route('/SearchBlood')
def searchblood():
    return render_template('SearchBloodBag.html')

@app.route('/Blood order')
def contact():
    return render_template('BloodBagRequestForm.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/map')
def contactus():
    return render_template('map.html')

@app.route('/HospSign')
def Hospsignup():
    return render_template('HospSignup.html')

@app.route('/BBSign')
def BBsignup():
    return render_template('BBSignup.html')




if __name__ == '__main__':
    app.run()

@app.route('/submit_order', methods=['POST'])
def submit_order():
    blood_type = request.form['blood_type']
    quantity = request.form['quantity']
    # Here, you can process the order, save it to a database, etc.
    return f"Order placed: Blood Type - {blood_type}, Quantity - {quantity}"

if __name__ == '__main__':
    app.run(debug=True)
