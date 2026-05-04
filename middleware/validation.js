// NVME Input Validation - Joi schemas
const Joi = require("joi");

const schemas = {
  signup: Joi.object({
    email: Joi.string().email().required().max(255),
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(8).max(128).required()
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/)
      .message("Password must be 12+ chars with uppercase, lowercase, and number")
  }),
  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),
  profile: Joi.object({
    displayName: Joi.string().min(1).max(100).allow(""),
    bio: Joi.string().max(500).allow(""),
    country: Joi.string().length(2).uppercase(),
    categories: Joi.array().items(Joi.string().max(30)).max(5),
    avatarUrl: Joi.string().uri().allow("", null)
  }),
  video: Joi.object({
    caption: Joi.string().min(1).max(200).required(),
    hashtags: Joi.array().items(Joi.string().max(50)).max(20),
    privacy: Joi.string().valid("public", "friends", "private").default("public"),
    music: Joi.string().max(100),
    duration: Joi.number().integer().min(1).max(600)
  })
};

function validate(schemaName) {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) return res.status(500).json({ error: "unknown schema" });
    const { error, value } = schema.validate(req.body, { stripUnknown: true, abortEarly: false });
    if (error) {
      return res.status(400).json({
        error: "validation failed",
        details: error.details.map(d => ({ field: d.path.join("."), message: d.message }))
      });
    }
    req.body = value;
    next();
  };
}

module.exports = { validate, schemas };
