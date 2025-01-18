Blood Bag Order Placing and Delivery System
An innovative platform that streamlines blood bag ordering and delivery processes between hospitals, individual patients, and blood banks. This system is designed to ensure timely and secure delivery of blood bags, reducing critical turnaround time in healthcare services.
Table of Contents
1.	Overview
2.	Key Features
3.	Tech Stack
4.	Architecture and Planning
5.	Installation and Setup
6.	Usage and Implementation Details
7.	Database Structure
8.	Payment Gateway Integration
9.	Future Enhancements
10.	License
________________________________________

Overview
The Blood Bag Order Placing and Delivery System was initially created as a final-year project, later evolving into a startup delivering up to 50 blood bags per month. It addresses the challenge of ensuring prompt and efficient blood availability for healthcare providers and individuals in need.
Objectives:
•	Streamline the ordering and dispatch process of blood bags.
•	Facilitate secure, real-time payment transactions (PhonePe).
•	Offer reliable tracking for blood bag requests, dispatch, and deliveries.
________________________________________

Key Features
1.	Hospital and Patient User Roles
o	Patient Login: Individuals can request blood bags, track orders, and complete transactions.
o	Hospital Login: Hospitals can place bulk orders and manage deliveries.

2.	Blood Bank Module
o	Inventory Management: Track available blood groups and components.
o	Order Processing: Accept, dispatch, and confirm deliveries.

3.	Real-Time Notifications
o	Status Updates: Users and hospitals receive updates at every stage—placed, dispatched, delivered.
o	Email/SMS Alerts (Optional): For added reliability.

4.	PhonePe Payment Gateway
o	Secure Transactions: Payment data is encrypted, ensuring safe exchanges.
o	Multiple Payment Options: Users can utilize PhonePe UPI or other payment options for convenience.

5.	IST Timestamp Conversion
o	Automatically converts UTC timestamps to IST using pytz and astimezone.
________________________________________

Tech Stack
•	Backend: Flask (Python microframework)
•	Database: MongoDB (Cloud or local)
•	Payment Gateway: PhonePe
•	Frontend: HTML5, CSS3, JavaScript, Font Awesome
•	Additional Libraries:
o	pytz for timezone handling.
o	datetime for date/time operations.

________________________________________
Architecture and Planning
1.	Data Flow
o	Hospitals/Patients place requests → Flask Backend processes orders → MongoDB stores order details → Blood Bank sees new requests → Order dispatches with updated status → Payment processes via PhonePe.
2.	User Roles
o	Patient: Sign up/sign in, place order, track order, pay securely.
o	Hospital: Sign up/sign in, bulk order, track shipments, manage administrative details.
o	Blood Bank: Update inventory, manage requests, dispatch deliveries.
3.	Security Considerations
o	User Authentication: Protect user data and order information.
o	HTTPS: Recommended for secure endpoints.
o	Payment Gateway: PhonePe ensures encrypted transactions.


Usage and Implementation Details

    Sign-Up and Login
        Patients and Hospitals can create accounts, providing relevant details.
        A Blood Bank logs in to manage inventory.

    Placing Orders
        Patients/Hospitals specify blood type, quantity, and relevant patient info.
        Orders appear on the Blood Bank dashboard, awaiting dispatch.

    Dispatch and Delivery
        Blood Bank updates the dispatch status once a courier is arranged.
        A final delivery status is updated upon successful handover.

    Payment Process
        PhonePe integrated flow for secure payment.
        Transaction status updates in the system.

    IST Timestamps
        All order timestamps are converted from UTC to IST with pytz.
        Displayed in YYYY-MM-DD HH:MM:SS format in the UI.

Database Structure

    Users Collection
        {"_id", "name", "email", "password", "role", ...}
    Orders Collection
        {"_id", "User_ID", "BloodBank_Id", "BloodGrp", "BloodComp", "quantity", "status", "timestamp", "timeofdispatch", "timeofdelivery", ...}
    BloodBank Collection
        {"_id", "reg_num", "bb_name", "address", "contact_num", ...}

Payment Gateway Integration

    PhonePe Initialization
        Integrate PhonePe SDK or use APIs for secure transactions.
        Store transaction data in Orders collection with relevant statuses.
    Callback Handling
        PhonePe notifies your Flask endpoint after the payment is processed.
        Update the order with a success or failure status.

Future Enhancements

    Automatic Courier Assignment: Integrate logistics API to automate shipping for quick dispatch.
    Email/SMS Notifications: Send real-time status notifications to users.
    Analytics Dashboard: Provide metrics on successful deliveries, average time, etc.

