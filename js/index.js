const serverID = "test server";
const generatorModifier = "generator modifier";
const privateKeyModifier = "private key modifier";
const clientVerifierModifier = "client verifier modifier";
const sessionKeyModifier = "session key modifier";
const sessionIVModifier = "session IV modifier";

let sodium = undefined;
window.sodium = {
    onload: function (sodium_) {
        sodium = sodium_;
    }
};

function credentials() {
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;
    return [username.trim(), password];
}

function craftBlindSaltRequest(username, password) {
    // generate blind salt
    let salt = sodium.crypto_generichash(64, sodium.from_string(password), sodium.from_string(serverID));
    salt = sodium.crypto_core_ristretto255_from_hash(salt);
    let mask = sodium.crypto_core_ristretto255_scalar_random();
    salt = sodium.crypto_scalarmult_ristretto255(mask, salt);
    mask = sodium.crypto_core_ristretto255_scalar_invert(mask);

    let request = {
        "salt": sodium.to_base64(salt),
        "username": username,
    };

    return [request, mask];
}

function deriveSecrets(password, mask, salt) {
    salt = sodium.from_base64(salt);
    if (!sodium.crypto_core_ristretto255_is_valid_point(salt)) {
        throw "invalid salt";
    }

    let blindSalt = sodium.crypto_scalarmult_ristretto255(mask, salt);
    blindSalt = sodium.crypto_generichash(sodium.crypto_pwhash_SALTBYTES, blindSalt, sodium.from_string(serverID));

    let keyMaterial = sodium.crypto_pwhash(64, sodium.from_string(password), blindSalt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, sodium.crypto_pwhash_ALG_DEFAULT);

    let generator = sodium.crypto_generichash(sodium.crypto_core_ristretto255_HASHBYTES,
        keyMaterial, sodium.from_string(generatorModifier));
    generator = sodium.crypto_core_ristretto255_from_hash(generator);

    let privateKey = sodium.crypto_generichash(sodium.crypto_core_ristretto255_HASHBYTES,
        keyMaterial, sodium.from_string(privateKeyModifier));
    privateKey = sodium.crypto_core_ristretto255_scalar_reduce(privateKey);

    sodium.memzero(keyMaterial);

    let publicKey = sodium.crypto_scalarmult_ristretto255(privateKey, generator);

    return {
        "generator": generator,
        "publicKey": publicKey,
        "privateKey": privateKey,
    };
}

function craftRegisterRequest(username, password, mask, salt, blob) {
    let secrets = deriveSecrets(password, mask, salt);
    return {
        "username": username,
        "generator": sodium.to_base64(secrets.generator),
        "publicKey": sodium.to_base64(secrets.publicKey),
        "blob": blob,
    };
}

function craftLoginRequest(username, password, mask, salt, blob, publicKey) {
    let serverPublicKey = sodium.from_base64(publicKey);
    if (!sodium.crypto_core_ristretto255_is_valid_point(serverPublicKey)) {
        throw "invalid ephemeral public key";
    }

    let secrets = deriveSecrets(password, mask, salt);
    let ephemeralSecret = sodium.crypto_core_ristretto255_scalar_random();
    let ephemeralPublic = sodium.crypto_scalarmult_ristretto255(ephemeralSecret, secrets.generator);
    let sharedSecret = new Uint8Array(sodium.crypto_core_ristretto255_BYTES * 2);

    let ephemeralToSeverStatic = sodium.crypto_scalarmult_ristretto255(ephemeralSecret, serverPublicKey);
    let userStaticToServerStatic = sodium.crypto_scalarmult_ristretto255(secrets.privateKey, serverPublicKey);

    sharedSecret.set(ephemeralToSeverStatic, 0);
    sharedSecret.set(userStaticToServerStatic, sodium.crypto_core_ristretto255_BYTES);
    sharedSecret = sodium.crypto_generichash(64, serverID, sharedSecret);

    let verifierC = sodium.crypto_generichash(32, clientVerifierModifier, sharedSecret);
    let sessionKey = sodium.crypto_generichash(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, sessionKeyModifier, sharedSecret);
    let sessionIV = sodium.crypto_generichash(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, sessionIVModifier, sharedSecret);

    let request = {
        "username": username,
        "blob": blob,
        "ephemeralPublic": sodium.to_base64(ephemeralPublic),
        "verifier": sodium.to_base64(verifierC),
    };

    return [request, sessionKey, sessionIV];
}

async function register(e) {
    e.preventDefault();
    document.getElementById('statusMessage').innerText = "";
    try {
        let [username, password] = credentials();
        let [request1, mask] = craftBlindSaltRequest(username, password)
        let resp = await fetch("/register/step1", {
            method: "POST",
            body: JSON.stringify(request1),
        });
        let respJson = await resp.json();
        let request2 = craftRegisterRequest(username, password, mask, respJson.salt, respJson.blob);
        resp = await fetch("/register/step2", {
            method: "POST",
            body: JSON.stringify(request2),
        });
        respJson = await resp.json();
        document.getElementById('statusMessage').innerText = respJson.status;
    } catch (e) {
        console.log(e);
        document.getElementById('statusMessage').innerText = "An error occurred";
    }
}

async function login(e) {
    e.preventDefault();
    document.getElementById('statusMessage').innerText = "";
    try {
        let [username, password] = credentials();
        let [request1, mask] = craftBlindSaltRequest(username, password)
        let resp = await fetch("/login/step1", {
            method: "POST",
            body: JSON.stringify(request1),
        });

        let respJson = await resp.json();
        let [request2, key, iv] = craftLoginRequest(username, password, mask, respJson.salt, respJson.blob, respJson.publicKey);

        resp = await fetch("/login/step2", {
            method: "POST",
            body: JSON.stringify(request2),
        });
        respJson = await resp.json();
        document.getElementById('statusMessage').innerText = respJson.status;
    } catch (e) {
        console.log(e);
        document.getElementById('statusMessage').innerText = "An error occurred";
    }
}

document.getElementById('register').addEventListener('click', register);
document.getElementById('login').addEventListener('click', login);