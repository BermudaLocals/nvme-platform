// Morph engine — Ken Burns simulation via Replicate variations
// No native dependencies (no sharp, no canvas)
// Generates frame variations and returns metadata for client-side assembly

class MorphEngine {
  constructor(options = {}) {
    this.frames = options.frames || 24;
    this.fps = options.fps || 8;
    this.kenBurnsIntensity = options.ken_burns || 0.15;
  }

  /**
   * Generate morph frame prompts by shifting seed/style slightly each frame
   * Returns array of prompt variations for batch generation
   */
  buildFramePrompts(basePrompt, preset, count) {
    const n = count || this.frames;
    const prompts = [];
    const shifts = [
      'slight camera pan left,',
      'slight camera pan right,',
      'slow zoom in,',
      'slow zoom out,',
      'subtle parallax shift,',
      'gentle rotation,',
      'depth of field shift,',
      'light angle change,',
    ];
    for (let i = 0; i < n; i++) {
      const t = i / (n - 1); // 0..1 progress
      const shift = shifts[i % shifts.length];
      // Interpolate intensity: ramp up then down
      const intensity = Math.sin(t * Math.PI) * this.kenBurnsIntensity;
      const pct = Math.round(intensity * 100);
      prompts.push({
        prompt: `${basePrompt}, ${shift} ${pct}% movement`,
        preset,
        frame: i,
        seed_offset: i * 7919 // prime number for good seed spread
      });
    }
    return prompts;
  }

  /**
   * Build client-side morph instructions
   * Returns CSS/JS transform keyframes the frontend can apply to a single image
   */
  buildKenBurnsCSS(duration) {
    const dur = duration || (this.frames / this.fps);
    const int = this.kenBurnsIntensity * 100;
    // Random direction
    const dirX = Math.random() > 0.5 ? 1 : -1;
    const dirY = Math.random() > 0.5 ? 1 : -1;
    const startScale = 1.0;
    const endScale = 1.0 + (Math.random() * int / 100);

    return {
      duration: `${dur}s`,
      keyframes: [
        { transform: `scale(${startScale}) translate(0%, 0%)` },
        { transform: `scale(${(startScale + endScale) / 2}) translate(${dirX * int * 0.3}%, ${dirY * int * 0.2}%)` },
        { transform: `scale(${endScale}) translate(${dirX * int * 0.6}%, ${dirY * int * 0.4}%)` },
      ],
      css: `@keyframes kenburns {
  0% { transform: scale(${startScale}) translate(0%, 0%); }
  50% { transform: scale(${(startScale + endScale) / 2}) translate(${dirX * int * 0.3}%, ${dirY * int * 0.2}%); }
  100% { transform: scale(${endScale}) translate(${dirX * int * 0.6}%, ${dirY * int * 0.4}%); }
}`
    };
  }

  /**
   * Process morph result from Replicate
   * Takes generated frame URLs and returns assembly metadata
   */
  assembleFrameData(frameUrls, options = {}) {
    const frames = Array.isArray(frameUrls) ? frameUrls : [frameUrls];
    const fps = options.fps || this.fps;
    const duration = frames.length / fps;

    return {
      frames: frames.map((url, i) => ({
        index: i,
        url,
        timestamp: +(i / fps).toFixed(3),
        duration: +(1 / fps).toFixed(3)
      })),
      total_frames: frames.length,
      fps,
      duration: +duration.toFixed(3),
      ken_burns: this.buildKenBurnsCSS(duration),
      // Platform-compatible assembly hints
      assembly: {
        tiktok: { max_duration: 600, compatible: duration <= 600 },
        youtube: { max_duration: 18000, compatible: duration <= 18000 },
        shorts: { max_duration: 60, compatible: duration <= 60 },
        reel: { max_duration: 90, compatible: duration <= 90 }
      }
    };
  }

  /**
   * Generate a single blended "morph frame" instruction
   * For client-side: returns two source URLs + blend percentage
   */
  buildBlendInstruction(frameA, frameB, progress) {
    return {
      source_a: frameA,
      source_b: frameB,
      blend: +progress.toFixed(3),
      css_filter: `opacity(${1 - progress})`,
      crossfade: true
    };
  }
}

module.exports = MorphEngine;