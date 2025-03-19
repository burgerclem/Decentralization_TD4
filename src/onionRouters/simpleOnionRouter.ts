import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, importSymKey, symDecrypt, exportSymKey } from "../crypto";
import axios from "axios";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  const { publicKey, privateKey } = await generateRsaKeyPair();
  const publicKeyBase64 = await exportPubKey(publicKey);
  const privateKeyBase64 = await exportPrvKey(privateKey);

  if (!privateKeyBase64) {
    console.error("Private key generation failed");
    throw new Error("Private key generation failed");
  }

  try {
    await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      nodeId,
      pubKey: publicKeyBase64,
    });
    console.log(`Node ${nodeId} registered successfully!`);
  } catch (error) {
    console.error(`Failed to register node ${nodeId}:`, error);
  }

  onionRouter.get("/getPrivateKey", (req, res) => {
    console.log(privateKeyBase64);
    if (privateKeyBase64) {
      res.json({ result: privateKeyBase64 });
    } else {
      res.status(500).json({ error: "Private key not available" });
    }
  });

  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body as { message: string };

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    try {
      lastReceivedEncryptedMessage = message;
      const [encryptedSymKey, encryptedData] = message.split(/(?<=^[A-Za-z0-9+/=]{392})/);
      const symKeyBase64 = await rsaDecrypt(encryptedSymKey, privateKey);
      const symKey = await importSymKey(symKeyBase64);
      const symKeyString = await exportSymKey(symKey); 
      const decryptedData = await symDecrypt(symKeyString, encryptedData);

      const destination = parseInt(decryptedData.slice(0, 10), 10);
      const nextMessage = decryptedData.slice(10);

      lastReceivedDecryptedMessage = nextMessage;
      lastMessageDestination = destination;

      if (destination >= BASE_USER_PORT) {
        await axios.post(`http://localhost:${destination}/message`, { message: nextMessage });
      } else {
        await axios.post(`http://localhost:${destination}/message`, { message: nextMessage });
      }

      return res.status(200).send("Message forwarded successfully");
    } catch (error) {
      console.error("Failed to forward message:", error);
      return res.status(500).json({ error: "Failed to forward message" });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}