const intRegex = /[0-9 -()+]+$/g;
function validateEmailOrMobile(emailOrMobile) {
    if (emailOrMobile === '') {
        alert("Please enter a valid email or mobile number");
        return false;
    }
    if (intRegex.test(emailOrMobile)) {
        // mobile number entered
        if (emailOrMobile.length != 10) {
            alert('Please enter a valid 10-digit mobile number.');
            return false;
        }
        return true;
    } else {

        var emailReg = /^([w-.]+@([w-]+.)+[w-]{2,4})?$/;
        // email entered
        if (!emailReg.test(emailOrMobile)) {
            alert('Please enter a valid email address.');
            return false;
        }
        return true;
    }
}


function handleEmailOrMobile(emailOrMobile, successCallback, errorCallback) {
    if (emailOrMobile === '') {
        errorCallback(1, "Please enter a valid email or mobile number");
        return;
    }
    if (!isNaN(emailOrMobile) && !isNaN(parseFloat(emailOrMobile))) {
        // mobile number entered
        if (emailOrMobile.length != 10) {
            errorCallback(2, 'Please enter a valid 10-digit mobile number.');
        } else {
            successCallback(true);
        }
    } else {

        var reg = /^([A-Za-z0-9_\-\.])+\@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$/;
        // email entered
        if (!reg.test(emailOrMobile)) {
            errorCallback(3, 'Please enter a valid email address.' + emailOrMobile);
        } else {
            successCallback(false);
        }
    }
}

function handleCountryCodeVisibility(countryCode, emailOrMobile) {
    const cc = document.getElementById(countryCode);
    const em = document.getElementById(emailOrMobile);
    em.oninput = callback;
    // em.onchange = callback;

    setTimeout(() => {
        em.style.visibility = 'visible';
        em.value = ''
    }, 1000);

    function callback(event) {
        action(event.target.value);
    }
    function action(value) {
        console.log(value);
        if (!isNaN(value) && !isNaN(parseFloat(value))) {
            cc.style.display = 'block';
        } else {
            cc.style.display = 'none';
        }
    }

    function appendInvisibleInputToForm(form, name, value) {
        
    }

}