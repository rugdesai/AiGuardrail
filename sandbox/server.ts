import express from "express";
import { runSandbox } from "./run";

const app = express();

app.use(express.json());

app.post("/run-sandbox", async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || language !== "python") {
      return res.status(400).json({
        error: "Invalid code or language",
      });
    }

    const result = await runSandbox(code, language);

    return res.json(result);
  } catch (error) {
    console.error("Sandbox error:", error);

    return res.status(500).json({
      error: "Sandbox execution failed",
    });
  }
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Sandbox API running on http://0.0.0.0:3000");
});