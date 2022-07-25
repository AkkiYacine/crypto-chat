// Public key : can be shared to everybody
// Private key : must be kept secret

// First use case
// original message => encrypt with public key => crypted message
// crypted message => decrypt with private key => original message

// Second use case
// message => sign with private key => signed message
// signed message => verify with public key => valid/invalid

// A => B
// A has B public key
// B has A public key
// A writes an original message => encrypt with B public key => sign with A private key => A sends signed crypted message to B
// B receives the signed crypted message => verify with A public key => decrypt the crypted message with B private key => B reads A original message

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

async function importPrivateKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

async function importPrivateKeyAuth(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-PSS",
      hash: "SHA-256",
    },
    true,
    ["sign"]
  );
}

async function importPublicKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["encrypt"]
  );
}

async function importPublicKeyAuth(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-PSS",
      hash: "SHA-256"
    },
    true,
    ["verify"]
  );
}

async function exportPrivateCryptoKey(key) {
  const exported = await window.crypto.subtle.exportKey(
    "pkcs8",
    key
  );
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;

  return pemExported
}

async function exportPublicCryptoKey(key) {
  const exported = await window.crypto.subtle.exportKey(
      "spki",
      key
  );
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  return pemExported;
}

const generateKeys = async () => {
  const RSAKeys = await crypto.subtle.generateKey({
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"},
    true,
    ["encrypt", "decrypt"])

  const privateKey = await exportPrivateCryptoKey(RSAKeys.privateKey)
  const publicKey = await exportPublicCryptoKey(RSAKeys.publicKey)

  localStorage.setItem('privateKey', privateKey)
  localStorage.setItem('publicKey', publicKey)

  return RSAKeys
}

const generateKeysAuth = async () => {
  const RSAKeys = await crypto.subtle.generateKey({
      name: "RSA-PSS",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"},
    true,
    ["sign", "verify"])

  const privateKey = await exportPrivateCryptoKey(RSAKeys.privateKey)
  const publicKey = await exportPublicCryptoKey(RSAKeys.publicKey)

  localStorage.setItem('privateKeySign', privateKey)
  localStorage.setItem('publicKeyVerify', publicKey)

  return RSAKeys
}

const getKeys = async () => {
  const pemPrivateKey = localStorage.getItem('privateKey')
  const pemPublicKey = localStorage.getItem('publicKey')

  if (!pemPrivateKey || !pemPublicKey) {
    return null;
  }

  const privateKey = await importPrivateKey(pemPrivateKey)
  const publicKey = await importPublicKey(pemPublicKey)

  return { privateKey, publicKey }
}

const getAuthKeys = async () => {
  const pemPrivateKey = localStorage.getItem('privateKeySign')
  const pemPublicKey = localStorage.getItem('publicKeyVerify')

  if (!pemPrivateKey || !pemPublicKey) {
    return null;
  }

  const privateKey = await importPrivateKeyAuth(pemPrivateKey)
  const publicKey = await importPublicKeyAuth(pemPublicKey)

  return { privateKey, publicKey }
}

// <-------------------------------------------------------------------------------------------------------------------->

let name; // = localStorage.getItem('username');
if (!name) {
  name = prompt("Please enter your name");
  localStorage.setItem('username', name)
}

let keys;
let authKeys;
(async () => {
  keys = await getKeys();
  authKeys = await getAuthKeys();

  // If no keys exist in localStorage
  if (!keys) {
    // Generate 2 pairs of RSA keys and save it in localStorage
    keys = await generateKeys()
    authKeys = await generateKeysAuth()
  }
})()


// <-------------------------------------------------------------------------------------------------------------------->


const encryptMessage = async (publicKey, message) => {
  const encryptedMessage = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    new TextEncoder().encode(message),
  )

  return ab2str(encryptedMessage)
}

const decryptMessage = async (encryptedMessage) => {
  const decryptedMessage = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    keys.privateKey,
    str2ab(encryptedMessage),
  )

  return new TextDecoder().decode(decryptedMessage)
}

const signMessage = async (encryptedMessage) => {
  const signature = await crypto.subtle.sign(
    { 
      name: 'RSA-PSS',
      saltLength: 32
    },
    authKeys.privateKey,
    str2ab(encryptedMessage)
  )

  return ab2str(signature)
}

const verifyMessage = async (publicKey, signature, encryptedMessage) => {
  const verifiedMessage = await crypto.subtle.verify(
    { 
      name: 'RSA-PSS',
      saltLength: 32
    },
    publicKey,
    str2ab(signature),
    str2ab(encryptedMessage),
  )

  return verifiedMessage
}

// <-------------------------------------------------------------------------------------------------------------------->

let activeUserId;
/** 
 * type User {
 *   id: string
 *   username: string
 *   messages: string[]
 * }
 */
const users = {}
const ws = new WebSocket('ws://localhost:5647');
const createMessage = (type, data) => JSON.stringify({ type, data });

ws.onopen = () => {
  const pemPublicKey = localStorage.getItem('publicKey')
  const pemPublicKeyVerify = localStorage.getItem('publicKeyVerify')
  
  if (!pemPublicKey || !pemPublicKeyVerify) {
    return;
  }

  $('form').submit(async (e) => {
    const message = $('#m').val()
    e.preventDefault();

    // Encrypt message before sending
    const encryptedMessage = await encryptMessage(users[activeUserId].publicKey, message)
    const signature = await signMessage(encryptedMessage)

    ws.send(createMessage('message', { 
      recipientId: activeUserId,
      message: encryptedMessage,
      signature,
    }));

    users[activeUserId].messages.push({ author: ws.id, message })
    $('#messages').append($('<li class="list">').text(`You: ${message}`));
    $('#m').val('');
    return false;
  });
  
  ws.onmessage = async ({data}) => {
    const event = JSON.parse(data)
    switch (event.type) {
      case 'auth':
        ws.id = event.data.id
        ws.send(
          createMessage('auth', { 
            username: name ?? 'Invité',
            publicKey: pemPublicKey,
            publicKeyVerify: pemPublicKeyVerify,
          })
        );
        break;
      case 'message': {
        const author = users[event.data.author]
        if (author) {
          // Verify signature of received message
          const valid = await verifyMessage(author.publicKeyVerify, event.data.signature, event.data.message)

          if (valid) {
            // Decrypt message once we know the signature is valid
            const message = await decryptMessage(event.data.message)

            // Add message to messages of author
            users[event.data.author].messages.push({ author: event.data.author, message });
            
            if (event.data.author === activeUserId) {
              // We currently are in the author tab
              $('#messages').append($('<li>').text(`${users[activeUserId].username}: ${message}`));
            }
          } else {
            // Should never happen: conversation was compromised or corrupted
            console.error('Invalid signature received for message', event.data)
          }
        }
        break;
      } 
      case 'users': 
        const others = event.data.users.filter(user => user.id !== ws.id)
        const othersIds = others.map(user => user.id)
        const existingUsers = Object.keys(users)
        const disconnectedUsers = existingUsers.filter(user => !othersIds.includes(user))
        disconnectedUsers.forEach(user => {
          delete users[user]
        })

        await Promise.all(
          others.map(async user => {
            if (!users[user.id] && user.publicKey && user.publicKeyVerify) {
              users[user.id] = {
                id: user.id,
                username: user.username,
                publicKey: await importPublicKey(user.publicKey),
                publicKeyVerify: await importPublicKeyAuth(user.publicKeyVerify),
                messages: [],
              }
            }
            return
          })
        );

        $('#userlist').empty().append(Object.values(users).map(user => `<li data-id="${user.id}">${user.username}</li>`).join(''))
        break;
    }
  };
}

$(document).on('click', '#userlist > li', (e) => {
  activeUserId = $(e.currentTarget).data('id')
  $('#messages').empty().append(
    users[activeUserId].messages.map(({author, message}) => 
    `<li${author === activeUserId ? '' : ' class="list"'}>${author === activeUserId ? users[activeUserId].username : 'You'}: ${message}</li>`
  ))
  $('#users').hide()
  $('#users-connected').hide()
  $('#chat').show()
})

$(document).on('click', '#close-button', () => {
  activeUserId = undefined
  $('#messages').empty()
  $('#chat').hide()
  $('#users').show()
  $('#users-connected').show()
})