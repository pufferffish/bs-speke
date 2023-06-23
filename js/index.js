import bs_speke from './bs_speke.js';

const serverID = "test server";
const textEncoder = new TextEncoder();

let bsSpeke = undefined;
bs_speke().then((bsSpeke_) => {
    bsSpeke = bsSpeke_;
    console.log("BS-SPEKE module loaded");
    console.log("Test", bsSpeke._bs_speke_size());
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

function allocString(str) {
    const bytes = textEncoder.encode(str);
    const ptr = bsSpeke._malloc(bytes.length+1);
    bsSpeke.HEAPU8.set(bytes, ptr);
    bsSpeke.HEAPU8[ptr+bytes.length] = 0;
    return ptr;
}

function newBSSpekeContext(serverID, username, password) {
    const usernamePtr = allocString(username);
    const passwordPtr = allocString(password);
    const serverIDPtr = allocString(serverID);

    const ctx = bsSpeke._malloc(bsSpeke._bs_speke_size());
    const entropy = bsSpeke._malloc(64);
    window.crypto.getRandomValues(new Uint8Array(bsSpeke.HEAPU8.buffer, entropy, 64));
    bsSpeke._bs_speke_init(ctx, serverIDPtr, usernamePtr, passwordPtr, entropy);
    bsSpeke._free(entropy);
    return {
        ctx: ctx,
        username: username,
        free: () => {
            bsSpeke._free(ctx);
            bsSpeke._free(usernamePtr);
            bsSpeke._free(passwordPtr);
            bsSpeke._free(serverIDPtr);
        }
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
    const workArea = bsSpeke._malloc(100_000*1024);
    const saltPtr = bsSpeke._malloc(32);
    bsSpeke.HEAPU8.set(base64ToArrayBuffer(salt), saltPtr);
    const r = bsSpeke._bs_speke_derive_secret(ctx.ctx, saltPtr, workArea);
    bsSpeke._free(workArea);
    if (r !== 0) {
        throw new Error("got low order point");
    }
}

function craftRegisterRequest(ctx, salt, blob) {
    deriveSecrets(ctx, salt);
    const buf = bsSpeke._malloc(64);
    const r = bsSpeke._bs_speke_register(ctx.ctx, buf, buf+32); // gen, pk
    const request = {
        "username": ctx.username,
        "generator": encodeBase64Bytes(buf, 32),
        "publicKey": encodeBase64Bytes(buf+32, 32),
        "blob": blob,
    };
    bsSpeke._free(buf);
    if (r !== 0) {
        throw new Error("got low order point");
    }

    return request;
}

function craftLoginRequest(ctx, salt, blob, publicKey) {
    deriveSecrets(ctx, salt);
    const ephemeralPublic = bsSpeke._malloc(32);
    const verifier = bsSpeke._malloc(64);
    const publicKeyPtr = bsSpeke._malloc(32);
    bsSpeke.HEAPU8.set(base64ToArrayBuffer(publicKey), publicKeyPtr);
    const r = bsSpeke._bs_speke_login_key_exchange(ctx.ctx, ephemeralPublic, verifier, publicKeyPtr);

    let request = {
        "username": ctx.username,
        "blob": blob,
        "ephemeralPublic": encodeBase64Bytes(ephemeralPublic, 32),
        "verifier": encodeBase64Bytes(verifier, 64),
    };

    bsSpeke._free(ephemeralPublic);
    bsSpeke._free(verifier);
    if (r !== 0) {
        throw new Error("got low order point");
    }

    return request;
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
    let [username, password] = credentials();
    let ctx = newBSSpekeContext(serverID, username, password);
    try {
        let request1 = craftBlindSaltRequest(ctx);
        let resp = await fetch("/login/step1", {
            method: "POST",
            body: JSON.stringify(request1),
        });

        let respJson = await resp.json();
        let request2 = craftLoginRequest(ctx, respJson.salt, respJson.blob, respJson.publicKey);
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
    } finally {
        ctx.free();
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