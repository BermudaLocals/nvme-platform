const sharp = require("sharp");
const { createCanvas, loadImage } = require("canvas");
class MorphEngine {
  static async blendFrames(buf1, buf2, totalFrames) {
    const i1 = await loadImage(await sharp(buf1).resize(1080,1920,{fit:"cover"}).png().toBuffer());
    const i2 = await loadImage(await sharp(buf2).resize(1080,1920,{fit:"cover"}).png().toBuffer());
    const canvas = createCanvas(1080,1920), ctx = canvas.getContext("2d");
    const frames = [];
    for (let i = 0; i <= totalFrames; i++) {
      const t = i / totalFrames;
      const ease = t < 0.5 ? 2*t*t : 1 - Math.pow(-2*t+2,2)/2;
      ctx.globalAlpha = 1; ctx.drawImage(i1, 0, 0);
      ctx.globalAlpha = ease; ctx.drawImage(i2, 0, 0);
      frames.push(canvas.toBuffer("image/png"));
    }
    return frames;
  }
  static async kenBurns(imgBuf, durSec, fps = 30) {
    const img = await loadImage(await sharp(imgBuf).resize(1080,1920,{fit:"cover"}).png().toBuffer());
    const canvas = createCanvas(1080,1920), ctx = canvas.getContext("2d");
    const total = Math.round(durSec * fps), frames = [];
    for (let i = 0; i < total; i++) {
      const t = i / total, scale = 1 + 0.08 * t;
      const ox = 1080 * (scale-1) * (0.3 + 0.4 * Math.sin(t * Math.PI));
      const oy = 1920 * (scale-1) * t * 0.5;
      ctx.clearRect(0,0,1080,1920);
      ctx.save(); ctx.translate(-ox, -oy); ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0); ctx.restore();
      frames.push(canvas.toBuffer("image/png"));
    }
    return frames;
  }
}
module.exports = MorphEngine;
