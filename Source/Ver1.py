from flask import Flask, request, render_template_string, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json, time

app = Flask(__name__)
users = {}        # {username: public_key}
messages = []     # [{'sender':..., 'receiver':..., 'message':..., 'plaintext':...}]
contact_cache = {}  # For tracking active users

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ E2EE Chat</title>
    <style>
        body { font-family: Arial; margin: 0; padding: 0; background: #f4f4f4; transition: background 0.3s, color 0.3s; }
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
        .error { background-color: #fdd; color: #900; }
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
            <select id="encType"><option value="rsa-aes">RSA + AES</option></select>
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
        body: JSON.stringify({username: currentUser, public_key: publicKeyPem})
    });
}

async function sendMsg() {
    const msg = document.getElementById("message").value;
    if (!msg || !currentReceiver) return;

    const res = await fetch('/get_key/' + currentReceiver);
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

    const payload = {
        sender: currentUser,
        receiver: currentReceiver,
        enc_key: btoa(String.fromCharCode(...new Uint8Array(encAesKey))),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...iv)),
        plaintext: msg
    };

    await fetch('/send', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    document.getElementById("message").value = "";
    fetchMsgs();

    console.log("🔐 Sent:", msg);
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
        if (isSelf && msg.plaintext) {
            plain = msg.plaintext;
        } else {
            try {
                const encKeyBytes = Uint8Array.from(atob(msg.enc_key), c => c.charCodeAt(0));
                const aesKeyRaw = await window.crypto.subtle.decrypt({name: "RSA-OAEP"}, privateKey, encKeyBytes);
                const aesKey = await window.crypto.subtle.importKey("raw", aesKeyRaw, {name: "AES-GCM"}, false, ["decrypt"]);
                const iv = Uint8Array.from(atob(msg.iv), c => c.charCodeAt(0));
                const ct = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0));
                const decrypted = await window.crypto.subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, ct);
                plain = new TextDecoder().decode(decrypted);
            } catch (e) {
                plain = `⚠️ ${msg.sender}'s message could not be decrypted`;
            }
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
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    users[data['username']] = data['public_key']
    contact_cache[data['username']] = time.time()
    return jsonify({"status": "ok"})

@app.route('/get_key/<username>')
def get_key(username):
    return jsonify({"public_key": users.get(username)})

@app.route('/send', methods=['POST'])
def send():
    data = request.json
    messages.append(data)
    return jsonify({"status": "sent"})

@app.route('/receive/<username>')
def receive(username):
    return jsonify({"messages": [m for m in messages if m['receiver'] == username or m['sender'] == username]})

@app.route('/contacts')
def contacts():
    return jsonify({"contacts": list(users.keys())})

if __name__ == '__main__':
    app.run(debug=True)
