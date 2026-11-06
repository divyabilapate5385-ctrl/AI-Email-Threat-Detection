/**
 * Vercel Serverless Function Handler
 * Routes all API calls to the Aegis Cyber SOC engine and REST API.
 */
const server = require('../src/backend/server');

module.exports = (req, res) => {
  return server.handleRequest(req, res);
};
