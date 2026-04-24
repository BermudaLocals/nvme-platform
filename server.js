{
  "name": "nvme-platform",
  "version": "2.0.0",
  "description": "NVME.live - Bermuda's Premier Creator Platform - Mothership v2.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "twilio": "^4.19.0",
    "axios": "^1.6.2",
    "stripe": "^14.7.0",
    "@paypal/checkout-server-sdk": "^1.0.3",
    "pg": "^8.11.3",
    "uuid": "^9.0.0",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "morgan": "^1.10.0",
    "multer": "^1.4.5-lts.1",
    "pdf-lib": "^1.17.1",
    "node-cron": "^3.0.3"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
