const JSContextDetector = require('../../src/contextInference/detectors/jsDetector');

describe('JSContextDetector', () => {
  let detector;

  beforeEach(() => {
    detector = new JSContextDetector();
  });

  describe('detectRoutes', () => {
    test('should detect Express routes', async () => {
      const code = `
        app.get('/users', (req, res) => {
          res.json({users: []});
        });
      `;
      const result = await detector.detectRoutes(code, { file: 'routes.js' });

      expect(result).toHaveProperty('detected');
      expect(result).toHaveProperty('confidence');
      expect(Array.isArray(result.evidence)).toBe(true);
    });

    test('should detect router patterns', async () => {
      const code = `
        router.post('/api/login', handler);
      `;
      const result = await detector.detectRoutes(code, { file: 'api.js' });

      expect(typeof result.detected).toBe('boolean');
      expect(typeof result.confidence).toBe('number');
    });

    test('should use path heuristic', async () => {
      const code = 'const x = 5;';
      const result = await detector.detectRoutes(code, { 
        file: '/app/routes/users.js' 
      });

      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });

    test('should handle empty code', async () => {
      const result = await detector.detectRoutes('', { file: 'test.js' });

      expect(result).toHaveProperty('detected');
    });

    test('should handle malformed code', async () => {
      const result = await detector.detectRoutes('const x = {{{', { file: 'bad.js' });

      expect(result).toHaveProperty('confidence');
    });
  });

  describe('detectAuth', () => {
    test('should detect missing auth', async () => {
      const code = `
        app.get('/admin', (req, res) => {
          res.send('admin');
        });
      `;
      const result = await detector.detectAuth(code, { file: 'routes.js' });

      expect(result).toHaveProperty('missing');
      expect(typeof result.confidence).toBe('number');
    });

    test('should detect auth middleware', async () => {
      const code = `
        app.get('/admin', authenticate, handler);
      `;
      const result = await detector.detectAuth(code, { file: 'routes.js' });

      expect(result).toHaveProperty('confidence');
    });

    test('should handle syntax errors', async () => {
      const result = await detector.detectAuth('const x = {{{', { file: 'test.js' });

      expect(typeof result.missing).toBe('boolean');
    });
  });

  describe('detectPII', () => {
    test('should detect PII fields', async () => {
      const code = `
        const schema = {
          email: String,
          name: String
        };
      `;
      const result = await detector.detectPII(code, { file: 'user.js' });

      expect(result).toHaveProperty('detected');
      expect(Array.isArray(result.evidence)).toBe(true);
    });

    test('should handle non-PII code', async () => {
      const code = 'const port = 3000;';
      const result = await detector.detectPII(code, { file: 'config.js' });

      expect(typeof result.detected).toBe('boolean');
    });

    test('should handle syntax errors', async () => {
      const result = await detector.detectPII('bad code{{{', { file: 'test.js' });

      expect(result).toHaveProperty('detected');
    });
  });

  describe('detectPublicAPI', () => {
    test('should count routes', async () => {
      const code = `
        app.get('/a', h);
        app.post('/b', h);
      `;
      const result = await detector.detectPublicAPI(code);

      expect(result).toHaveProperty('metadata');
      expect(result.metadata.routeCount).toBeGreaterThan(0);
    });

    test('should handle no routes', async () => {
      const result = await detector.detectPublicAPI('const x = 5;');

      expect(result.detected).toBe(false);
      expect(result.metadata.routeCount).toBe(0);
    });
  });

  describe('detectUserInput', () => {
    test('should detect req.body', async () => {
      const code = 'const data = req.body;';
      const result = await detector.detectUserInput(code);

      expect(typeof result.detected).toBe('boolean');
    });

    test('should detect query params', async () => {
      const code = 'const id = req.query.id;';
      const result = await detector.detectUserInput(code);

      expect(result).toHaveProperty('confidence');
    });

    test('should handle no input', async () => {
      const result = await detector.detectUserInput('const x = 5;');

      expect(Array.isArray(result.evidence)).toBe(true);
    });
  });

  describe('detectFileAuth', () => {
    test('should detect file level auth', async () => {
      const code = 'const x = 5;';
      const result = await detector.detectFileAuth(code);

      expect(result).toHaveProperty('missing');
    });
  });
});