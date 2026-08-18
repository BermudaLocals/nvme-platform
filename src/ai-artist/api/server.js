const express = require("express");
const cors = require("cors");
const wf = require("../pipeline/workflow");
const Asm = require("../pipeline/assembler");
const styles = require("../styles/presets");
const fs = require("fs");
const path = require("path");
const app = express();
app.use(cors());
app.use(express.json());
var CLIP = path.join(__dirname, "../storage/clips");
if (!fs.existsSync(CLIP)) fs.mkdirSync(CLIP, { recursive: true });
app.get("/api/platforms", function(req, res) {
  res.json([
    { id: "tiktok", label: "TikTok", min: 8, max: 600, maxLabel: "10 min" },
    { id: "youtube", label: "YouTube Studio", min: 8, max: 18000, maxLabel: "5 hours" },
    { id: "shorts", label: "Shorts", min: 8, max: 60, maxLabel: "60s" },
    { id: "reel", label: "Reel", min: 8, max: 90, maxLabel: "90s" }
  ]);
});
app.get("/api/styles", function(req, res) {
  res.json(Object.keys(styles).map(function(k) { return { id: k, prefix: styles[k].prefix, suffix: styles[k].suffix, neg: styles[k].neg, cfg: styles[k].cfg, steps: styles[k].steps }; }));
});
app.post("/api/generate", async function(req, res) {
  try {
    var body = req.body;
    var prompt = body.prompt, style = body.style, duration = body.duration, platform = body.platform;
    var p = platform || "tiktok";
    var L = Asm.getLimits(p);
    var dur = Math.max(L.min, Math.min(L.max, duration || 8));
    if (!prompt) return res.status(400).json({ error: "Prompt required" });
    gen.init(process.env.REPLICATE_TOKEN);
    var scenes = await wf.multiScene([{ prompt: prompt, duration: dur, morph: false }], style || "kayanDreamy");
    var r = await wf.render(scenes, p + "_" + Date.now() + ".mp4");
    res.json({ clip: "/api/clips/" + path.basename(r.path), duration: r.duration, formatted: Asm.fmtDur(r.duration), platform: p, style: style, prompt: prompt });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/generate/morph", async function(req, res) {
  try {
    var body = req.body;
    var p1 = body.prompt1, p2 = body.prompt2, style = body.style, duration = body.duration, platform = body.platform;
    var p = platform || "tiktok";
    var L = Asm.getLimits(p);
    var dur = Math.max(L.min, Math.min(L.max, duration || 8));
    gen.init(process.env.REPLICATE_TOKEN);
    var m = await wf.morphClip(p1, p2, style || "kayanMorph", dur);
    var r = await wf.render([{ frames: m.frames, duration: dur }], "morph_" + Date.now() + ".mp4");
    res.json({ clip: "/api/clips/" + path.basename(r.path), duration: dur, formatted: Asm.fmtDur(dur), platform: p, prompt: p1 + " -> " + p2 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.use("/api/clips", express.static(CLIP));
var PORT = process.env.AI_PORT || 3100;
app.listen(PORT, function() { console.log("AI Artist API on :" + PORT + " | TikTok 8s-10m | YouTube 8s-5hr"); });
