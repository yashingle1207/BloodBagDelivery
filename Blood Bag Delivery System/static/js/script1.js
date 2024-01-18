const signUpButton = document.getElementById('signUp');
const signInButton = document.getElementById('signIn');
const container = document.getElementById('container');

signUpButton.addEventListener('click', () => {
	container.classList.add("right-panel-active");
});

signInButton.addEventListener('click', () => {
	container.classList.remove("right-panel-active");
});

// validation.js - for Blood bank login

function validateForm() {
    var phoneNumberInput = document.getElementById('ContactNum') ||
                           document.getElementById('facilityContactNum') ||
                           document.getElementById('patientContactNum');
    var phoneNumber = phoneNumberInput.value.trim();

    var emailInput = document.getElementById('BBEmail') ||
                     document.getElementById('facilityEmailId') ||
                     document.getElementById('patientEmailId');
    var email = emailInput.value.trim();

    // Check if the phone number has exactly 10 digits
    var isPhoneNumberValid = /^\d{10}$/.test(phoneNumber);

    // Check if the email is valid (ends with @gmail.com or other valid domains)
    var isEmailValid = /^\S+@(gmail\.com|ac\.in|otherdomain\.com)$/.test(email);

    if (!isPhoneNumberValid) {
        alert('Please enter a valid 10-digit phone number.');
        phoneNumberInput.focus();
        return false;
    }

    if (!isEmailValid) {
        alert('Please enter a valid email address ending with @gmail.com, @ac.in, or other valid domains.');
        emailInput.focus();
        return false;
    }

    return true;
}
