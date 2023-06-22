import bs_speke from './bs_speke.js';

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

let bsSpeke = undefined;
bs_speke().then((bsSpeke_) => {
    bsSpeke = bsSpeke_;
    console.log("bsSpeke loaded");
    console.log("Test", bsSpeke._bs_speke_size()) ;
});

function credentials() {
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;
    return [username.trim(), password];
}

function encodeBase64Bytes(ptr, size) {
    let bytes = new Uint8Array(bsSpeke.HEAPU8.buffer, ptr, size);
    return btoa(
        bytes.reduce((acc, current) => acc + String.fromCharCode(current), "")
    );
}

function base64ToArrayBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function newBSSpekeContext(serverID, username, password) {
    let ctx = bsSpeke._malloc(bsSpeke._bs_speke_size());
    let entropy = bsSpeke._malloc(64);
    window.crypto.getRandomValues(new Uint8Array(bsSpeke.HEAPU8.buffer, entropy, 64));
    bsSpeke.cwrap("bs_speke_init", "number", ["number", "string", "string", "string", "number"])(ctx, serverID, username, password, entropy);
    bsSpeke._free(entropy);
    return {
        ctx: ctx,
        username: username,
        free: () => bsSpeke._free(ctx)
    };
}

function craftBlindSaltRequest(ctx) {
    // generate blind salt
    let salt = bsSpeke._malloc(32);
    bsSpeke._bs_speke_get_salt(ctx.ctx, salt);
    let request = {
        "salt": encodeBase64Bytes(salt, 32),
        "username": ctx.username,
    };

    bsSpeke._free(salt);
    return request;
}

function deriveSecrets(ctx, salt) {
    const workArea = bsSpeke._malloc(470000*1024);
    const saltPtr = bsSpeke._malloc(32);
    bsSpeke.HEAPU8.set(base64ToArrayBuffer(salt), saltPtr);
    bsSpeke._bs_speke_derive_secret(ctx.ctx, saltPtr, workArea);
    bsSpeke._free(workArea);
}

function craftRegisterRequest(ctx, salt, blob) {
    deriveSecrets(ctx, salt);
    const buf = bsSpeke._malloc(64);
    bsSpeke._bs_speke_register(ctx.ctx, buf, buf+32); // gen, pk
    const request = {
        "username": ctx.username,
        "generator": encodeBase64Bytes(buf, 32),
        "publicKey": encodeBase64Bytes(buf+32, 32),
        "blob": blob,
    };
    bsSpeke._free(buf);
    return request;
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
    let [username, password] = credentials();
    let ctx = newBSSpekeContext(serverID, username, password);
    try {
        let request1 = craftBlindSaltRequest(ctx);
        let resp = await fetch("/register/step1", {
            method: "POST",
            body: JSON.stringify(request1),
        });

        let respJson = await resp.json();
        let request2 = craftRegisterRequest(ctx, respJson.salt, respJson.blob);
        resp = await fetch("/register/step2", {
            method: "POST",
            body: JSON.stringify(request2),
        });
        respJson = await resp.json();
        document.getElementById('statusMessage').innerText = respJson.status;
    } catch (e) {
        console.log(e);
        document.getElementById('statusMessage').innerText = "An error occurred";
    } finally {
        ctx.free();
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
        if (respJson.status === "OK") {
            window.location.href = "/";
        } else {
            document.getElementById('statusMessage').innerText = respJson.status;
        }
    } catch (e) {
        console.log(e);
        document.getElementById('statusMessage').innerText = "An error occurred";
    }
}

function logout(e) {
    e.preventDefault();
    fetch("/logout", {
        method: "POST",
        body: JSON.stringify({}),
    }).then(() => {
        window.location.href = "/";
    });
}

document.getElementById('logout')?.addEventListener('click', logout);
document.getElementById('register')?.addEventListener('click', register);
document.getElementById('login')?.addEventListener('click', login);