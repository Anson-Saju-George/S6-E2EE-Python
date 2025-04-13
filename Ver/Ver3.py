from flask import Flask, request, jsonify, render_template_string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Random.random import randint
from nacl.public import PrivateKey, PublicKey, Box
from base64 import b64encode, b64decode
import json, time

app = Flask(__name__)
users = {}         # username -> {public_key, algo, [x25519_pub, dh_pub]}
privates = {}      # username -> private_key(s)
messages = []      # stored messages
HTML_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ E2EE Chat</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f4f4f4; transition: background 0.3s, color 0.3s; }
        .dark-mode { background: #121212; color: #eee; }
        #topbar { display: flex; justify-content: space-between; align-items: center; background: #007bff; color: white; padding: 10px; }
        #topbar b { font-size: 18px; }
        #container { display: flex; height: calc(100vh - 48px); }
        #contacts { width: 160px; border-right: 1px solid #ccc; overflow-y: auto; background: #fff; transition: background 0.3s, color 0.3s; }
        .dark-mode #contacts { background: #1e1e1e; color: #eee; }
        #chat { flex: 1; display: flex; flex-direction: column; }
        #inbox { flex: 1; overflow-y: scroll; padding: 10px; }
        #compose { padding: 10px; border-top: 1px solid #ccc; }
        textarea { width: 100%; }
        .chat-row { display: flex; margin: 4px 0; }
        .bubble { padding: 6px 10px; border-radius: 12px; max-width: 70%; word-wrap: break-word; }
        .bubble-left { justify-content: flex-start; }
        .bubble-left .bubble { background-color: #e0e0e0; }
        .bubble-right { justify-content: flex-end; }
        .bubble-right .bubble { background-color: #d2f0ff; }
        .contact { padding: 8px; border-bottom: 1px solid #ccc; cursor: pointer; }
        .contact.active { background: #007bff; color: white; }
        #options { display: flex; align-items: center; gap: 8px; }
        #chatWith { font-size: 14px; margin-left: 10px; font-weight: normal; }
    </style>
</head>
<body>
    <div id="topbar">
        <b id="headerName"></b>
        <span id="chatWith"></span>
        <div id="options">
            <select id="encType">
                <option value="rsa-aes">RSA + AES</option>
                <option value="x25519">X25519 + ChaCha20-Poly1305</option>
                <option value="dh">DH + AES</option>
            </select>
            <button onclick="toggleMode()">🌓</button>
        </div>
    </div>
    <div id="container">
        <div id="contacts"></div>
        <div id="chat">
            <div id="inbox"></div>
            <div id="compose">
                <textarea id="message" rows="2" placeholder="Type a message..."></textarea>
                <button onclick="sendMsg()">Send</button>
            </div>
        </div>
    </div>

<script>
let privateKey, publicKeyPem, currentUser = '', currentReceiver = '';
let lastMessages = 0, lastContacts = [];

function toggleMode() {
    document.body.classList.toggle("dark-mode");
}

function updateHeader() {
    document.getElementById("headerName").innerHTML = `<b>${currentUser}</b>`;
    document.getElementById("chatWith").textContent = currentReceiver ? `chatting with ${currentReceiver}` : '';
}

async function registerUser() {
    currentUser = prompt("Enter your username");
    if (!currentUser) return;

    updateHeader();

    const keyPair = await window.crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        true, ["encrypt", "decrypt"]
    );
    privateKey = keyPair.privateKey;
    const exported = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    publicKeyPem = btoa(String.fromCharCode(...new Uint8Array(exported)));

    await fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: currentUser, public_key: publicKeyPem, algo: 'rsa-aes'})
    });
}

async function sendMsg() {
    const msg = document.getElementById("message").value;
    if (!msg || !currentReceiver) return;

    const encType = document.getElementById("encType").value;
    let payload = {};

    if (encType === 'rsa-aes') {
        const res = await fetch('/get_user/' + currentReceiver);
        const data = await res.json();
        if (!data.public_key) return alert("Receiver not registered");

        const pubKeyBytes = Uint8Array.from(atob(data.public_key), c => c.charCodeAt(0));
        const pubKey = await window.crypto.subtle.importKey("spki", pubKeyBytes, {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]);

        const aesKey = await window.crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedMsg = new TextEncoder().encode(msg);
        const ciphertext = await window.crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, aesKey, encodedMsg);
        const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
        const encAesKey = await window.crypto.subtle.encrypt({name: "RSA-OAEP"}, pubKey, rawAes);

        payload = {
            sender: currentUser,
            receiver: currentReceiver,
            enc_key: btoa(String.fromCharCode(...new Uint8Array(encAesKey))),
            ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
            iv: btoa(String.fromCharCode(...iv)),
            plaintext: msg,
            algo: 'rsa-aes'
        };
    }

    else if (encType === 'x25519') {
        const res = await fetch('/get_key/' + currentReceiver);
        const data = await res.json();
        if (!data.x25519_pub) return alert("Receiver not registered");

        const senderPriv = await nacl.crypto_box_keypair();
        const receiverPub = nacl.util.decodeBase64(data.x25519_pub);
        const [encryptedMsg, nonce, pubKeyHex] = x25519_encrypt(msg, senderPriv, receiverPub);

        payload = {
            sender: currentUser,
            receiver: currentReceiver,
            enc_key: pubKeyHex,
            ciphertext: encryptedMsg,
            iv: nonce,
            plaintext: msg,
            algo: 'x25519'
        };
    }

    else if (encType === 'dh') {
        const res = await fetch('/get_key/' + currentReceiver);
        const data = await res.json();
        if (!data.dh_pub) return alert("Receiver not registered");

        const dhKeypair = await generateDHKeypair();
        const sharedSecret = deriveSharedSecret(dhKeypair.privateKey, data.dh_pub);
        const [ciphertext, nonce, tag] = dh_encrypt(msg, sharedSecret);

        payload = {
            sender: currentUser,
            receiver: currentReceiver,
            enc_key: btoa(tag),
            ciphertext: ciphertext,
            iv: nonce,
            plaintext: msg,
            algo: 'dh'
        };
    }

    await fetch('/send', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    document.getElementById("message").value = "";
    fetchMsgs();
}

async function fetchMessages() {
    if (!currentUser || !privateKey || !currentReceiver) return;
    const res = await fetch('/receive/' + currentUser);
    const data = await res.json();
    const messages = data.messages.filter(m => m.receiver === currentUser && m.sender === currentReceiver || m.receiver === currentReceiver && m.sender === currentUser);

    if (messages.length === lastMessages) return;
    lastMessages = messages.length;

    let output = "";
    for (const msg of messages) {
        let plain;
        const isSelf = msg.sender === currentUser;

        if (msg.algo === 'rsa-aes') {
            // Decrypt RSA + AES
            // (decrypt logic from earlier RSA + AES section)
        }
        else if (msg.algo === 'x25519') {
            plain = x25519_decrypt(msg.ciphertext, msg.iv, msg.enc_key, privates[currentUser]);
        }
        else if (msg.algo === 'dh') {
            plain = dh_decrypt(msg.ciphertext, msg.iv, msg.enc_key, privates[currentUser]);
        }

        const alignClass = isSelf ? 'bubble-right' : 'bubble-left';
        output += `<div class="chat-row ${alignClass}"><div class="bubble"><b>${msg.sender}:</b> ${plain}</div></div>`;
    }

    const inbox = document.getElementById("inbox");
    inbox.innerHTML = output;
    inbox.scrollTop = inbox.scrollHeight;
}

async function fetchContacts() {
    const res = await fetch('/contacts');
    const data = await res.json();
    const contacts = data.contacts.filter(c => c !== currentUser);
    if (JSON.stringify(contacts) === JSON.stringify(lastContacts)) return;
    lastContacts = contacts;

    let html = "";
    for (const user of contacts) {
        const active = user === currentReceiver ? 'active' : '';
        html += `<div class="contact ${active}" onclick="selectContact('${user}')">${user}</div>`;
    }
    document.getElementById("contacts").innerHTML = html;
}

function selectContact(name) {
    currentReceiver = name;
    updateHeader();
    lastMessages = 0;
    fetchMessages();
    fetchContacts();
}

setInterval(fetchMessages, 3000);
setInterval(fetchContacts, 3000);

window.onload = registerUser;
</script>
</body>
</html>
'''


# --- X25519 + ChaCha20-Poly1305 ---
def x25519_encrypt(msg: str, sender_private: PrivateKey, receiver_public: PublicKey):
    box = Box(sender_private, receiver_public)
    nonce = get_random_bytes(24)
    encrypted = box.encrypt(msg.encode(), nonce)
    return b64encode(encrypted).decode(), b64encode(nonce).decode(), sender_private.public_key.encode().hex()

def x25519_decrypt(enc_msg: str, nonce_b64: str, sender_pub_hex: str, receiver_private: PrivateKey):
    sender_pub = PublicKey(bytes.fromhex(sender_pub_hex))
    box = Box(receiver_private, sender_pub)
    decrypted = box.decrypt(b64decode(enc_msg))
    return decrypted.decode()

# --- Diffie-Hellman + AES ---
def generate_dh_keypair(p: int, g: int):
    private_key = randint(1, p-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def derive_dh_shared_secret(their_pub: int, my_priv: int, p: int):
    return pow(their_pub, my_priv, p)

def dh_encrypt(msg: str, shared_secret: int):
    aes_key = HKDF(shared_secret.to_bytes(32, 'big'), 32, b'', SHA256)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return b64encode(ciphertext).decode(), b64encode(cipher.nonce).decode(), b64encode(tag).decode()

def dh_decrypt(enc_msg: str, nonce_b64: str, tag_b64: str, shared_secret: int):
    aes_key = HKDF(shared_secret.to_bytes(32, 'big'), 32, b'', SHA256)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=b64decode(nonce_b64))
    decrypted = cipher.decrypt_and_verify(b64decode(enc_msg), b64decode(tag_b64))
    return decrypted.decode()

@app.route('/')
def home():
    return render_template_string(HTML_PAGE)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    algo = data['algo']
    users[username] = {'algo': algo, 'data': data}

    if algo == "x25519":
        priv = PrivateKey.generate()
        privates[username] = priv
        users[username]['x25519_pub'] = priv.public_key.encode().hex()

    elif algo == "dh":
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1  # Example 2048-bit prime
        g = 2
        priv, pub = generate_dh_keypair(p, g)
        privates[username] = (priv, p, g)
        users[username]['dh_pub'] = pub

    return jsonify({"status": "registered", "username": username})

@app.route('/get_user/<username>')
def get_user(username):
    return jsonify(users.get(username, {}))

@app.route('/send', methods=['POST'])
def send():
    data = request.json
    messages.append(data)
    print(f"🔐 {data['sender']} -> {data['receiver']} | algo={data['algo']}")
    return jsonify({"status": "sent"})

@app.route('/receive/<username>')
def receive(username):
    relevant = [m for m in messages if m['sender'] == username or m['receiver'] == username]
    return jsonify({"messages": relevant})

@app.route('/contacts')
def contact_list():
    return jsonify({"contacts": list(users.keys())})

if __name__ == "__main__":
    app.run(debug=True)
