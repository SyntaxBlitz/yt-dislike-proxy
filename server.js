const express = require('express');
const https = require('https');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const hkdf = require('futoin-hkdf');
const hkdf_tls = require('futoin-hkdf/tls');
const { Buffer } = require('buffer');
const { SmartBuffer } = require('smart-buffer');
const xor = require('buffer-xor');

const { HTTPParser } = require('http-parser-js');

// requires http 1.1. also tls 1.3
// SSLKEYLOGFILE=./ssllog.log curl --http1.1 --tlsv1.3 --tls--max 1.3 --proxy http://localhost:1080 https://youtubeanalytics.googleapis.com/v2/reports

const YT_API_HOSTNAME = 'youtubeanalytics.googleapis.com';

const TLS_PACKET_TYPES = {
  INVALID: 0,
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
};

const serverTLSBuffers = [];
const serverTLSPackets = [];

const parseServerTLSPacketsEncrypted = () => {
  const tlsBuffer = SmartBuffer.fromBuffer(Buffer.concat(serverTLSBuffers));

  while (tlsBuffer.remaining()) {
    const packet = {
      type: tlsBuffer.readUInt8(),
      protocolVersion: tlsBuffer.readUInt16BE(),
      length: tlsBuffer.readUInt16BE(),
    };

    // assert packet.protocolVersion === 0x0303;
  
    packet.fragment = tlsBuffer.readBuffer(packet.length);

    serverTLSPackets.push(packet);
  }
};

const deriveKeysFromTrafficSecret = (serverTrafficSecret) => {
  const HASH_FN = 'sha384';
  const serverWriteKey = hkdf_tls.expand_label(HASH_FN, hkdf.hash_length(HASH_FN), serverTrafficSecret, 32, 'tls13 key', Buffer.alloc(0));
  const serverWriteIV = hkdf_tls.expand_label(HASH_FN, hkdf.hash_length(HASH_FN), serverTrafficSecret, 12, 'tls13 iv', Buffer.alloc(0));
  return { serverWriteKey, serverWriteIV };
};

const decryptServerApplicationDataPackets = (allTLSPackets, serverTrafficSecret) => {
  const { serverWriteKey, serverWriteIV } = deriveKeysFromTrafficSecret(serverTrafficSecret);

  let sequenceNumber = 0;
  const decryptedApplicationData = allTLSPackets
    .filter(packet => packet.type === TLS_PACKET_TYPES.APPLICATION_DATA)
    .filter((_, i) => i !== 0) // first packet is handshake-related. I think. in the future if we get gcm working we can just check for a failed decryption (which would mean it's the handshake secret)
    .map(packet => decryptServerApplicationDataPacket(packet, sequenceNumber++, serverWriteKey, serverWriteIV))
    .filter(packet => packet.innerType === TLS_PACKET_TYPES.APPLICATION_DATA)
    .map(packet => packet.innerData);

  return Buffer.concat(decryptedApplicationData);
};

const decryptServerApplicationDataPacket = (packet, sequenceNumber, serverWriteKey, serverWriteIV) => {
  const seqBuf = Buffer.alloc(12);
  seqBuf.writeUInt32BE(sequenceNumber, 8);

  // GCM causes headaches so we decrypt as in CTR mode
  const iv = Buffer.concat([xor(serverWriteIV, seqBuf), Buffer.from([0, 0, 0, 2])]);
  const decipher = crypto.createDecipheriv('aes-256-ctr', serverWriteKey, iv);
  const plaintextBufs = [];
  plaintextBufs.push(decipher.update(packet.fragment));
  plaintextBufs.push(decipher.final());

  const fullBuffer = Buffer.concat(plaintextBufs);
  const _final16 = fullBuffer.slice(-16); // auth tag, according to wireshark logs
  const innerType = fullBuffer.slice(-17, -16).readUInt8(0); // spec allows for zero padding, we're just.. hoping that's not there. TODO

  return {
    innerType,
    innerData: fullBuffer.slice(0, -17),
  };
};



const proxyServer = https.createServer({
  key: fs.readFileSync('keys/privkey.pem'),
  cert: fs.readFileSync('keys/fullchain.pem'),
});
proxyServer.on('connect', (req, clientSocket, head) => {
  const { hostname } = new URL(`http://${req.url}`);
  if (hostname !== YT_API_HOSTNAME) {
    // TODO: error
    return;
  }
  const serverSocket = net.connect(443, YT_API_HOSTNAME, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
      '\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    serverSocket.on('data', (d) => {
      serverTLSBuffers.push(d);
    });
    serverSocket.on('close', () => {
      parseServerTLSPacketsEncrypted();
      // TODO: check whether alg matches
    });
    serverSocket.on('error', () => {
      // google servers seem to cause ECONNRESET after the req is over
      clientSocket.end();
    });
    clientSocket.on('error', () => {
      serverSocket.end();
    });
    clientSocket.pipe(serverSocket);
  });
});

proxyServer.listen(1998);


const webServer = express();
webServer.get('/key/:key', async (req, res) => {
  const ytResponse = decryptServerApplicationDataPackets(serverTLSPackets, Buffer.from(req.params.key, 'hex'));
  const ytResponseBodyBufs = [];
  const parser = new HTTPParser(HTTPParser.RESPONSE);
  parser.onBody = (buf, start, len) => {
    ytResponseBodyBufs.push(buf.slice(start, start + len));
  };
  parser.execute(ytResponse);
  
  // this appears async but is not actually (http-parser-js#26)
  const ytResponseBody = Buffer.concat(ytResponseBodyBufs).toString('utf8');
  console.log(ytResponseBody);

  console.log({ ytResponseBody: JSON.parse(ytResponseBody) });

  res.status(200).send('OK');
});

webServer.listen(1997);