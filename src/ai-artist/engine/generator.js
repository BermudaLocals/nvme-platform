const Replicate = require("replicate");
class AIArtist {
  constructor() { this.client = null; }
  init(token) { this.client = new Replicate({ auth: token || process.env.REPLICATE_TOKEN }); }
  async generate(prompt, opts = {}) {
    if (!this.client) throw new Error("Call init(token) first");
    const output = await this.client.run(
      "stability-ai/sdxl:39ed52f2a78e934b3ba6e2a89f5b1c712de7dfea535525255b1aa35c5565e08b",
      { input: {
        prompt, width: opts.width || 1080, height: opts.height || 1920,
        num_inference_steps: opts.steps || 30, guidance_scale: opts.cfg || 7.5,
        negative_prompt: opts.neg || "blurry,low quality,watermark,text,ugly,deformed"
      }}
    );
    return output[0];
  }
}
module.exports = new AIArtist();
