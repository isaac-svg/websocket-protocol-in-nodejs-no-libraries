import { createServer } from "http";
import crypto from "crypto";
const WEB_SOCKET_MAGIC_STRING_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SEVEN_BIT_INTEGER_MARKER = 125;
const SIXTEEN_BIT_INTEGER_MARKER = 126;
const SIXTYFOUR_BIT_INTEGER_MARKER = 127;
const MASK_KEY_BYTE_LENGTH = 4;
const FIRST_BIT = 128;
const OPTCODE_TEXT = 0x01; //1 bit in binnary
const MAXIMUM_SIXTEEN_BIT_INTEGER = 2 ** 16; //65536
const server = createServer((req, res) => {
  res.writeHead(200);
  res.end("hello world");
}).listen(3999, () => console.log("server is connected"));

server.on("upgrade", onSocketUpgrade);

function onSocketUpgrade(req, socket, header) {
  const { "sec-websocket-key": clientSocketKey } = req.headers;
  const headers = prepareHandshakeHeaders(clientSocketKey);
  socket.write(headers);
  socket.on("readable", () => onSocketReadable(socket));
}
function onSocketReadable(socket) {
  // our data comes as a buffer

  // read the first byte  off [holds the optcode , fin, rsv1, etc]
  socket.read(1);
  //  the second byte  contains the mask indicator which is either 0 or 1 (1 bit) and the length of the data
  // 1 means the message is encrypted and 0 means the opposite but the client or browser always sends message  which are encrypted so we have to remove the mask indicator bit

  // read the second byte off
  const [MaskIndicatorAndPayloadLength] = socket.read(1);
  // subtruct one bit from the the second byte to obtain the the length of the data or payload
  const payloadLenghtInBits = MaskIndicatorAndPayloadLength - FIRST_BIT;

  let messageLength = 0;

  if (payloadLenghtInBits <= SEVEN_BIT_INTEGER_MARKER) {
    messageLength = payloadLenghtInBits;
  } else if (payloadLenghtInBits === SIXTEEN_BIT_INTEGER_MARKER) {
    // unsigned int 16-bits [0 - 65k] or 0 -  2**16
    messageLength = socket.read(2).readUint16BE(0);
  } else {
    throw new Error("message too long one");
  }
  // the  3rd to 6th inclusive byte holds the encryption or mask key so we must read that one too off
  const maskKey = socket.read(MASK_KEY_BYTE_LENGTH); // maskKey -> [array buffer with keys]
  console.log({ maskKey: maskKey });
  // now the remaining byte contains our data or payload
  const encoded = socket.read(messageLength);
  console.log(encoded);
  const decoded = unmask(encoded, maskKey);
  console.log(decoded);
  const recievedData = decoded.toString("utf8");

  const data = JSON.parse(recievedData);
  // console.log(data);
  const msg = JSON.stringify({ data });
  sendMessage(msg, socket);
}
function sendMessage(msg, socket) {
  const data = prepareMessage(msg);
  socket.write(data);
}
function prepareMessage(message) {
  const msg = Buffer.from(message);

  const messageSize = msg.length;

  let dataFrameBuffer;

  const firstByte = 0x80 | OPTCODE_TEXT; // 0x80 == '0x' + (128).toString(16)

  if (messageSize <= SEVEN_BIT_INTEGER_MARKER) {
    const bytes = [firstByte];
    dataFrameBuffer = Buffer.from(bytes.concat(messageSize));
  } else if (messageSize <= MAXIMUM_SIXTEEN_BIT_INTEGER) {
    const offsetFourBit = 4;
    const target = Buffer.allocUnsafe(offsetFourBit);
    target[0] = firstByte;
    target[1] = SIXTEEN_BIT_INTEGER_MARKER;
    target.writeUint16BE(messageSize, 2);
    dataFrameBuffer = target;
  } else throw new Error("message too long two");

  const totalLength = dataFrameBuffer.byteLength + messageSize;
  const dataFrameResponse = concat([dataFrameBuffer, msg], totalLength);
  return dataFrameResponse;
}
function concat(bufferList, totalLength) {
  const target = Buffer.allocUnsafe(totalLength);
  let offset = 0;
  for (const buffer of bufferList) {
    target.set(buffer, offset);
    offset += buffer.length;
  }
  return target;
}
function unmask(encodedBuffer, maskKey) {
  const finalBuffer = Buffer.from(encodedBuffer);

  /* maskKey[i % MASK_KEY_BYTE_LENGTH] results to maskKey[0 or 1 or 2 or 3]
                      lets take an example to clarify 
  finalBuffer[i] = encodedBuffer[i] ^ maskKey[i % MASK_KEY_BYTE_LENGTH];
  say encodedBuffer[i]  returns 70 and maskkKey[i % MASK_KEY_BYTE_LENGTH] returns  50
  then finalBuffer[i] = 70 ^50;
 70^50 = 123;
 String.fromCharCode(123) == "{"
 String.fromCharCode(113) == "q"
 String.fromCharCode(65) == "A"

*/
  for (let i = 0; i < encodedBuffer.length; i++) {
    finalBuffer[i] = encodedBuffer[i] ^ maskKey[i % MASK_KEY_BYTE_LENGTH];
  }
  return finalBuffer;
}

function prepareHandshakeHeaders(id) {
  const acceptKey = createSocketAccept(id);
  const headers = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept:${acceptKey}`,
    "",
  ]
    .map((line) => line.concat("\r\n"))
    .join("");
  return headers;
}

function createSocketAccept(id) {
  const sha_1 = crypto.createHash("sha1");
  sha_1.update(id + WEB_SOCKET_MAGIC_STRING_KEY);
  return sha_1.digest("base64");
}

// catch errors
["uncaughtException", "unhandledRejection"].forEach((ev) =>
  process.on(ev, () => console.log(`error mesg from ${ev}`))
);
