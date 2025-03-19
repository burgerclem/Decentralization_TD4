import bodyParser from "body-parser";
import express from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  let registeredNodes: GetNodeRegistryBody = { nodes: [] };

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    if (nodeId !== undefined && nodeId !== null && pubKey) {
      const newNode: Node = { nodeId, pubKey };
      registeredNodes.nodes.push(newNode);
      res.status(201).json({ message: "Node registered." });
    } else {
      res.status(400).json({ error: "Invalid body." });
    }
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    res.json(registeredNodes);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}