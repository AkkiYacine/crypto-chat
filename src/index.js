import WebSocket, { WebSocketServer } from 'ws';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

const httpPort = 3001
const wsPort = 5647

const app = express()
app.use(express.static('public'))
app.listen(httpPort, () => {
  console.log(`🚀 Chat available on http://localhost:${httpPort}/`)
})

const wss = new WebSocketServer({ port: wsPort }, () => {
  console.log(`🚀 WS server listening on ${wsPort}/`)
});

const createMessage = (type, data) => JSON.stringify({ type, data });

wss.on('connection', function connection(ws) {
  ws.id = uuidv4();

  ws.send(createMessage('auth', { id: ws.id }))

  const broadcast = (message, self = true) => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN && (self || client !== ws)) {
        client.send(message);
      }
    });
  }

  ws.on('message', function message(data) {
    const event = JSON.parse(data)
    switch (event.type) {
      case 'auth':
        ws.username = event.data.username;
        ws.publicKey = event.data.publicKey;
        ws.publicKeyVerify = event.data.publicKeyVerify;

        broadcast(
          createMessage(
            'users',
            {
              users: Array.from(wss.clients)
                .filter(client => client.readyState === WebSocket.OPEN)
                .map(client => (
                  {
                    id: client.id,
                    username: client.username,
                    publicKey: client.publicKey,
                    publicKeyVerify: client.publicKeyVerify,
                  }
                )
              )
            }
          )
        )
        break;
      case 'message':
        const recipient = Array.from(wss.clients).find(client => client.id === event.data.recipientId)

        if (!recipient) {
          return;
        }

        recipient.send(createMessage('message', { author: ws.id, message: event.data.message, signature: event.data.signature }))
        break;
    }
  });
});

wss.on('close', function close() {
  console.log('terminated')
  broadcast(
    createMessage(
      'users',
      {
        users: Array.from(wss.clients)
          .filter(client => client.readyState === WebSocket.OPEN)
          .map(client => (
            {
              id: client.id,
              username: client.username,
              publicKey: client.publicKey,
              publicKeyVerify: client.publicKeyVerify,
            }
          )
        )
      }
    )
  )
});