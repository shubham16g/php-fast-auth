const intRegex = /[0-9 -()+]+$/;    
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
        if (intRegex.test(em.value)) {
            cc.style.display = 'block';
        } else {
            cc.style.display = 'none';
        }
    }
    
}