const ffmpeg = require("fluent-ffmpeg");
const ffmpegPath = require("@ffmpeg-installer/ffmpeg").path;
ffmpeg.setFfmpegPath(ffmpegPath);
const fs = require("fs");
const LIMITS = {
  tiktok:  { min: 8, max: 600,   label: "TikTok 8s-10min" },
  youtube: { min: 8, max: 18000, label: "YouTube 8s-5hr" },
  shorts:  { min: 8, max: 60,    label: "Shorts 8s-60s" },
  reel:    { min: 8, max: 90,    label: "Reel 8s-90s" }
};
class ClipAssembler {
  static getLimits(p) { return LIMITS[p] || LIMITS.tiktok; }
  static validateDuration(sec, p) {
    p = p || "tiktok";
    const L = this.getLimits(p);
    if (sec < L.min) return { valid: false, error: "Min " + L.label + " is " + L.min + "s" };
    if (sec > L.max) return { valid: false, error: "Max " + L.label + " is " + Math.floor(L.max/60) + "m" };
    return { valid: true, duration: sec, platform: p };
  }
  static fmtDur(s) {
    if (s >= 3600) { var h=Math.floor(s/3600),m=Math.floor((s%3600)/60); return m ? h+"h "+m+"m" : h+"h"; }
    if (s >= 60) { var m=Math.floor(s/60),r=s%60; return r ? m+"m "+r+"s" : m+"m"; }
    return s + "s";
  }
  static framesToVideo(frames, output, opts) {
    opts = opts || {};
    return new Promise(function(resolve, reject) {
      var p = opts.platform || "tiktok";
      var L = LIMITS[p] || LIMITS.tiktok;
      var dur = Math.max(L.min, Math.min(L.max, opts.duration || 8));
      var fps = opts.fps || 30, total = Math.round(dur * fps);
      var preset = dur > 600 ? "slow" : dur > 120 ? "medium" : "fast";
      var crf = dur > 3600 ? 23 : dur > 600 ? 20 : 18;
      var cmd = ffmpeg().input("pipe:0").inputFormat("image2pipe").inputFps(fps)
        .videoCodec("libx264")
        .outputOptions(["-pix_fmt yuv420p","-preset "+preset,"-crf "+crf,"-movflags +faststart"])
        .output(output).on("end", function() { resolve({ path: output, duration: dur }); })
        .on("error", reject);
      var fi = 0;
      function write() {
        if (fi >= total) { cmd.stdin.end(); return; }
        cmd.stdin.write(frames[fi % frames.length]); fi++;
        if (fi % 300 === 0) setTimeout(write, 0); else setImmediate(write);
      }
      write();
    });
  }
  static assembleScene(scenes, output, platform) {
    platform = platform || "tiktok";
    var totalDur = scenes.reduce(function(a, s) { return a + s.duration; }, 0);
    var v = this.validateDuration(totalDur, platform);
    if (!v.valid) throw new Error(v.error);
    var all = [];
    for (var i = 0; i < scenes.length; i++) {
      var s = scenes[i], n = Math.round(s.duration * 30);
      for (var j = 0; j < n; j++) all.push(s.frames[j % s.frames.length]);
    }
    return this.framesToVideo(all, output, { duration: totalDur, platform: platform });
  }
  static assembleLongForm(scenes, output, platform, onProgress) {
    platform = platform || "youtube";
    var self = this;
    var totalDur = scenes.reduce(function(a, s) { return a + s.duration; }, 0);
    var v = this.validateDuration(totalDur, platform);
    if (!v.valid) throw new Error(v.error);
    var SEG = 600, segDur = 0, segFrames = [], segments = [];
    return scenes.reduce(function(chain, scene) {
      return chain.then(function() {
        var rem = scene.duration;
        function processChunk() {
          if (rem <= 0) return Promise.resolve();
          var take = Math.min(rem, SEG - segDur), n = Math.round(take * 30);
          for (var i = 0; i < n; i++) segFrames.push(scene.frames[i % scene.frames.length]);
          segDur += take; rem -= take;
          if (segDur >= SEG || rem <= 0) {
            var sp = output.replace(".mp4", "_seg" + segments.length + ".mp4");
            segments.push(sp);
            return self.framesToVideo(segFrames, sp, { duration: segDur, platform: platform }).then(function() {
              if (onProgress) onProgress({ seg: segments.length, pct: Math.round(segments.length * SEG / totalDur * 100) });
              segFrames = []; segDur = 0;
            });
          }
          return Promise.resolve();
        }
        return processChunk();
      });
    }, Promise.resolve()).then(function() {
      if (segments.length === 1) return { path: segments[0], duration: totalDur };
      var listFile = output.replace(".mp4", "_list.txt");
      fs.writeFileSync(listFile, segments.map(function(s) { return "file '" + s + "'"; }).join("\n"));
      return new Promise(function(resolve, reject) {
        ffmpeg().input(listFile).inputOptions(["-f concat","-safe 0"])
          .videoCodec("libx264").outputOptions(["-pix_fmt yuv420p","-preset medium","-crf 20","-movflags +faststart"])
          .output(output).on("end", function() {
            segments.forEach(function(s) { try { fs.unlinkSync(s); } catch(e){} });
            try { fs.unlinkSync(listFile); } catch(e){}
            resolve({ path: output, duration: totalDur });
          }).on("error", reject).run();
      });
    });
  }
}
module.exports = ClipAssembler;
