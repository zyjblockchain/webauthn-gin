function registerUser() {

    username = $("#username").val()
    if (username === "") {
        alert("please enter a username");
        return;
    }

    let state = "register.begin";

    $.get(
        '/register/begin/' + username,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialCreationOptions) => {
            state = "register.options.challenge"
            credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
            state = "register.options.userID"
            credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
            state = "register.options.excludeCredentials"
            if (credentialCreationOptions.publicKey.excludeCredentials) {
                for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
                    credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
                }
            }

            state = "register.options.create"
            console.log("register begin: ", credentialCreationOptions)
            return navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey
            })
        })
        .then((credential) => {
            state = "register.credential.finish"
            let attestationObject = credential.response.attestationObject;
            let clientDataJSON = credential.response.clientDataJSON;
            let rawId = credential.rawId;
            $.post(
                '/register/finish/' + username,
                JSON.stringify({
                    id: credential.id,
                    rawId: bufferEncode(rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferEncode(attestationObject),
                        clientDataJSON: bufferEncode(clientDataJSON),
                    },
                }),
                function (data) {
                    return data
                },
                'json')
                .fail(function (response) {
                    console.log(response.responseText);
                    alert("error: " + response.responseText);
                })
                .then((success) => {
                    alert("successfully registered " + username + "!")
                })
        })
        .catch((error) => {
            console.log(error)
            alert("failed to register " + username + " state: " + state + " Error: " + error)
        })
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
    let s = window.atob(value.replace(/-/g, '+').replace(/_/g, '/'))
    let bytes = Uint8Array.from(s, c => c.charCodeAt(0))
    return bytes.buffer
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    let s = String.fromCharCode.apply(null, new Uint8Array(value))
    return window.btoa(s).replace(/\+/g, '-').replace(/\//g, '_');
}

function loginUser() {

    username = $("#username").val()
    if (username === "") {
        alert("please enter a username");
        return;
    }

    $.get(
        '/login/begin/' + username,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialRequestOptions) => {
            credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
            credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
                listItem.id = bufferDecode(listItem.id)
            });

            return navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey
            })
        })
        .then((assertion) => {
            let authData = assertion.response.authenticatorData;
            let clientDataJSON = assertion.response.clientDataJSON;
            let rawId = assertion.rawId;
            let sig = assertion.response.signature;
            let userHandle = assertion.response.userHandle;

            $.post(
                '/login/finish/' + username,
                JSON.stringify({
                    id: assertion.id,
                    rawId: bufferEncode(rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: bufferEncode(authData),
                        clientDataJSON: bufferEncode(clientDataJSON),
                        signature: bufferEncode(sig),
                        userHandle: bufferEncode(userHandle),
                    },
                }),
                function (data) {
                    return data
                },
                'json')
        })
        .then((success) => {
            alert("successfully logged in " + username + "!")
            return
        })
        .catch((error) => {
            console.log(error)
            alert("failed to register " + username)
        })
}
