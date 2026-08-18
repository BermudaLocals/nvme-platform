const gen = require("../engine/generator");
const Morph = require("../engine/morph");
const Assembler = require("./assembler");
const styles = require("../styles/presets");
const path = require("path");
class Workflow {
  async singleScene(prompt, styleName, duration) {
    const style = styles[styleName] || styles.kayanDreamy;
    const url = await gen.generate(style.prefix + prompt + style.suffix, style);
    const resp = await fetch(url);
    const buf = Buffer.from(await resp.arrayBuffer());
    const frames = await Morph.kenBurns(buf, duration, 30);
    return { frames: frames, duration: duration, prompt: prompt, style: styleName };
  }
  async morphClip(p1, p2, styleName, duration) {
    const style = styles[styleName] || styles.kayanMorph;
    const u1 = await gen.generate(style.prefix + p1 + style.suffix, style);
    const u2 = await gen.generate(style.prefix + p2 + style.suffix, style);
    const b1 = Buffer.from(await (await fetch(u1)).arrayBuffer());
    const b2 = Buffer.from(await (await fetch(u2)).arrayBuffer());
    const frames = await Morph.blendFrames(b1, b2, duration * 30);
    return { frames: frames, duration: duration, prompt: p1 + " -> " + p2 };
  }
  async multiScene(scenePrompts, styleName) {
    var scenes = [];
    for (var i = 0; i < scenePrompts.length; i++) {
      var sp = scenePrompts[i];
      var dur = Math.max(8, Math.min(600, sp.duration || 8));
      if (i > 0 && sp.morph) {
        var m = await this.morphClip(scenePrompts[i-1].prompt, sp.prompt, "kayanMorph", Math.min(4, dur/2));
        scenes.push({ frames: m.frames, duration: m.frames.length / 30 });
        var left = dur - m.frames.length / 30;
        if (left > 0) {
          var s = await this.singleScene(sp.prompt, styleName, left);
          scenes.push(s);
        }
      } else {
        var s = await this.singleScene(sp.prompt, styleName, dur);
        scenes.push(s);
      }
    }
    return scenes;
  }
  async render(scenes, filename) {
    var out = path.join(__dirname, "../storage/clips", filename);
    var totalDur = scenes.reduce(function(a, s) { return a + s.duration; }, 0);
    if (totalDur > 600) {
      return Assembler.assembleLongForm(scenes, out, "youtube", function(p) {
        console.log("Progress: " + p.pct + "% (seg " + p.seg + ")");
      });
    }
    return Assembler.assembleScene(scenes, out).then(function(r) {
      return { path: out, duration: r.duration };
    });
  }
}
module.exports = new Workflow();
