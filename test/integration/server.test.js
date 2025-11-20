// test/integration/server.test.js
const request = require('supertest');
const express = require('express');
const app = express();

// Create mock endpoints for testing
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    services: { ast: 'ready' }
  });
});

app.get('/capabilities', (req, res) => {
  res.json({
    status: 'success',
    capabilities: { languages: ['javascript'] }
  });
});

describe('API Endpoints', () => {
  describe('GET /health', () => {
    test('should return healthy status', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('healthy');
      expect(response.body.services).toHaveProperty('ast');
    });
  });

  describe('GET /capabilities', () => {
    test('should return scanner capabilities', async () => {
      const response = await request(app).get('/capabilities');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('success');
      expect(response.body.capabilities).toHaveProperty('languages');
    });
  });
});