// $(function () {
//     $('#btnEnroll').click(function () {
//         console.log("enroll");
//         fetch("/api/fido/enrollment/begin/", {
//             method: "POST"
//         }).then(function (response) {
//             response.json().then(beginEnrollment);
//         });
//     });
//     $('#btnLogin').click(function () {
//         fetch("/api/fido/login/begin/?username=" + $('#username').val(), {
//             method: "POST"
//         }).then(function (response) {
//             response.json().then(beginLogin);
//         });
//     });
//
//     function toArray(value) {
//         return Uint8Array.from(atob(value), c => c.charCodeAt(0));
//     }
//
//     function fromArray(value) {
//         return btoa(String.fromCharCode.apply(null, new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
//     }
//
//     function beginEnrollment(pkOptions) {
//         console.log(pkOptions);
//         pkOptions.publicKey.challenge = toArray(pkOptions.publicKey.challenge);
//         pkOptions.publicKey.user.id = toArray(pkOptions.publicKey.user.id);
//         ;
//         console.log(pkOptions);
//         navigator.credentials.create({
//             publicKey: pkOptions.publicKey
//         }).then(function (credential) {
//             console.log("Credential generated");
//             finishEnrollment(credential)
//         });
//     }
//
//     function completeEnrollment(credential) {
//         var clientDataJSON = fromArray(credential.response.clientDataJSON);
//         var attestationObject = fromArray(credential.response.attestationObject);
//         var rawId = fromArray(credential.rawId);
//         var payload = {
//             id: credential.id,
//             rawId: rawId,
//             type: credential.type,
//             response: {attestationObject, clientDataJSON}
//         }
//         console.log(payload);
//         fetch("/api/fido/enrollment/complete/", {
//             method: "POST",
//             body: JSON.stringify(payload),
//             headers: {'Content-Type': 'application/json'}
//         }).then(function (response) {
//             console.log(response);
//             response.json().then(function (v) {
//                 alert(JSON.stringify(v));
//             });
//         });
//     }
//
//     function beginLogin(pkOptions) {
//         console.log(pkOptions);
//         pkOptions.publicKey.challenge = toArray(pkOptions.publicKey.challenge);
//         console.log(pkOptions);
//         navigator.credentials.get({
//             publicKey: pkOptions.publicKey
//         }).then(function (credential) {
//             console.log("Credential read");
//             finishLogin(credential)
//         });
//     }
//
//     function completeLogin(credential) {
//         var clientDataJSON = fromArray(credential.response.clientDataJSON);
//         var authenticatorData = fromArray(credential.response.authenticatorData);
//         var rawId = fromArray(credential.rawId);
//         var signature = fromArray(credential.response.signature);
//         var userHandle = fromArray(credential.response.userHandle);
//         var payload = {
//             id: credential.id,
//             rawId: rawId,
//             type: credential.type,
//             response: {
//                 authenticatorData,
//                 clientDataJSON,
//                 signature,
//                 userHandle
//             }
//         }
//         console.log(payload);
//         var formValues = new FormData();
//         formValues.append("formValues", JSON.stringify(payload));
//         fetch("/api/fido/login/complete/", {
//             method: "POST",
//             body: formValues,
//         }).then(function (response) {
//             console.log(response);
//             response.json().then(function (v) {
//                 alert(JSON.stringify(v));
//             });
//         });
//     }
// });