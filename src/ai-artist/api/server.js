const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3100;
app.get("/", function(req, res) { res.json({ status: "ok" }); });
app.get("/health", function(req, res) { res.json({ status: "healthy" }); });
app.post("/generate", async function(req, res) {
  try {
    var prompt = req.body.prompt || "abstract digital art";
    var preset = req.body.preset || "kayanpink";
    var token = process.env.REPLICATE_API_TOKEN;
    if (!token || token.indexOf("YOUR_ACTUAL") !== -1) {
      return res.status(503).json({ error: "No Replicate API token", hint: "Set REPLICATE_API_TOKEN in .env" });
    }
    var Replicate = require("replicate");
    var replicate = new Replicate({ auth: token });
    var t0 = Date.now();
    var prediction = await replicate.predictions.create({
      model: "black-forest-labs/flux-schnell",
      input: { prompt: "in the style of " + preset + ", " + prompt }
    });
    var result = prediction;
    while (result.status !== "succeeded" && result.status !== "failed" && result.status !== "canceled") {
      await new Promise(function(r) { setTimeout(r, 1000); });
      result = await replicate.predictions.get(result.id);
    }
    if (result.status === "failed") {
      return res.status(500).json({ error: "Prediction failed", detail: result.error });
    }
    var output = result.output;
    var imgUrl = Array.isArray(output) ? output[0] : output;
    res.json({ output: imgUrl, timing: { total_ms: Date.now() - t0, predict_time: result.metrics.predict_time }, prompt: prompt, preset: preset });
  } catch (err) { console.error("Generate error:", err.message); res.status(500).json({ error: err.message }); }
});
app.post("/generate/morph", async function(req, res) {
  try {
    var prompt = req.body.prompt || "abstract digital art";
    var preset = req.body.preset || "kayanpink";
    var fps = req.body.fps || 8;
    var frames = req.body.frames || 24;
    var token = process.env.REPLICATE_API_TOKEN;
    if (!token || token.indexOf("YOUR_ACTUAL") !== -1) {
      return res.status(503).json({ error: "No Replicate API token" });
    }
    var Replicate = require("replicate");
    var replicate = new Replicate({ auth: token });
    var prediction = await replicate.predictions.create({
      model: "black-forest-labs/flux-schnell",
      input: { prompt: "in the style of " + preset + ", " + prompt }
    });
    var result = prediction;
    while (result.status !== "succeeded" && result.status !== "failed" && result.status !== "canceled") {
      await new Promise(function(r) { setTimeout(r, 1000); });
      result = await replicate.predictions.get(result.id);
    }
    if (result.status === "failed") {
      return res.status(500).json({ error: "Prediction failed", detail: result.error });
    }
    var imgUrl = Array.isArray(result.output) ? result.output[0] : result.output;
    var dur = frames / fps;
    var dx = Math.random() > 0.5 ? 1 : -1;
    var dy = Math.random() > 0.5 ? 1 : -1;
    res.json({ output_url: imgUrl, frames: [imgUrl], total_frames: 1, fps: fps, duration: dur, ken_burns: { duration: dur + "s", keyframes: ["scale(1) translate(0%,0%)", "scale(1.07) translate(" + (dx*4) + "%," + (dy*3) + "%)", "scale(1.15) translate(" + (dx*8) + "%," + (dy*6) + "%)"] } });
  } catch (err) { console.error("Morph error:", err.message); res.status(500).json({ error: err.message }); }
});
app.get("/platforms", function(req, res) {
  res.json({ tiktok: { min: 8, max: 600, label: "TikTok" }, youtube: { min: 8, max: 18000, label: "YouTube Studio" }, shorts: { min: 8, max: 60, label: "YouTube Shorts" }, reel: { min: 8, max: 90, label: "Instagram Reel" } });
});
app.listen(PORT, function() { console.log("NVME AI Artist on :" + PORT + " | Flux Schnell | Ready"); });