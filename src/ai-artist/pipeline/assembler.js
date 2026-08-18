const PLATFORM_LIMITS = {
  tiktok:  { min: 8, max: 600,   label: 'TikTok',       ratio: '9:16' },
  youtube: { min: 8, max: 18000, label: 'YouTube Studio', ratio: '16:9' },
  shorts:  { min: 8, max: 60,    label: 'YouTube Shorts', ratio: '9:16' },
  reel:    { min: 8, max: 90,    label: 'Instagram Reel', ratio: '9:16' },
};

class Assembler {
  constructor(options = {}) {
    this.outputDir = options.outputDir || './output';
    this.platform = options.platform || 'tiktok';
  }

  validate(durationSec, platform) {
    const limits = PLATFORM_LIMITS[platform] || PLATFORM_LIMITS.tiktok;
    return {
      platform: limits.label,
      duration: durationSec,
      min: limits.min,
      max: limits.max,
      compatible: durationSec >= limits.min && durationSec <= limits.max,
      ratio: limits.ratio,
      overflow: durationSec > limits.max ? durationSec - limits.max : 0,
      underflow: durationSec < limits.min ? limits.min - durationSec : 0,
    };
  }

  validateAll(durationSec) {
    const results = {};
    for (const [key] of Object.entries(PLATFORM_LIMITS)) {
      results[key] = this.validate(durationSec, key);
    }
    return results;
  }

  buildSegmentPlan(totalDurationSec, platform) {
    const plat = platform || 'youtube';
    const limits = PLATFORM_LIMITS[plat];
    const segmentMax = Math.min(limits.max, 600);
    const segments = [];
    let cursor = 0;
    let idx = 0;
    while (cursor < totalDurationSec) {
      const len = Math.min(segmentMax, totalDurationSec - cursor);
      segments.push({
        index: idx,
        start: +cursor.toFixed(1),
        duration: +len.toFixed(1),
        end: +(cursor + len).toFixed(1),
        label: 'Part ' + (idx + 1),
      });
      cursor += len;
      idx++;
    }
    return {
      platform: limits.label,
      total_duration: totalDurationSec,
      total_segments: segments.length,
      segment_max: segmentMax,
      segments: segments,
      estimated_render_time_min: segments.length * 2,
    };
  }

  buildManifest(frames, options) {
    const opts = options || {};
    const fps = opts.fps || 8;
    const platform = opts.platform || 'tiktok';
    const duration = frames.length / fps;
    const validation = this.validate(duration, platform);
    return {
      type: 'nvme-morph-manifest',
      version: '1.0',
      platform: platform,
      frames: frames.map(function(f, i) {
        return {
          index: i,
          url: typeof f === 'string' ? f : f.url,
          timestamp: +(i / fps).toFixed(3),
        };
      }),
      fps: fps,
      total_frames: frames.length,
      duration: +duration.toFixed(3),
      validation: validation,
      encoding: {
        codec: 'h264',
        container: 'mp4',
        audio: false,
        client_instructions: {
          method: 'canvas-sequence',
          frame_interval: +(1000 / fps).toFixed(1),
          canvas_width: 1024,
          canvas_height: 1280,
        }
      }
    };
  }

  static getPlatformLimits() {
    var copy = {};
    for (var k in PLATFORM_LIMITS) {
      copy[k] = Object.assign({}, PLATFORM_LIMITS[k]);
    }
    return copy;
  }
}

module.exports = Assembler;