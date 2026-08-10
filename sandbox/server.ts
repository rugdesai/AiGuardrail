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

    // Your Docker + telemetry logic
    const result = await runSandbox(code, language);

    return res.json(result);
  } catch (error) {
    console.error("FATAL SANDBOX ERROR:", error);

    const message =
      error instanceof Error ? error.message : "Unknown sandbox error";

    return res.status(500).json({
      error: message,
    });
  }
});

app.listen(3000, "127.0.0.1", () => {
  console.log("Sandbox API running on http://127.0.0.1:3000");
});