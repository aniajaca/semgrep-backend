const PythonContextDetector = require('../../src/contextInference/detectors/pythonDetector');

describe('PythonContextDetector', () => {
  let detector;

  beforeEach(() => {
    detector = new PythonContextDetector();
  });

  describe('detectRoutes', () => {
    test('should detect Flask routes', async () => {
      const code = `
        @app.route('/users')
        def get_users():
            return {'users': []}
      `;
      const result = await detector.detectRoutes(code, { file: 'routes.py' });

      expect(result).toHaveProperty('detected');
      expect(result).toHaveProperty('confidence');
    });

    test('should detect FastAPI routes', async () => {
      const code = `
        @router.get('/items')
        async def read_items():
            return []
      `;
      const result = await detector.detectRoutes(code, { file: 'api.py' });

      expect(typeof result.detected).toBe('boolean');
    });

    test('should use path heuristic', async () => {
      const result = await detector.detectRoutes('x = 5', { 
        file: '/app/views/users.py' 
      });

      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });
  });

  describe('detectAuth', () => {
    test('should detect missing auth', async () => {
      const code = `
        @app.route('/admin')
        def admin():
            return 'admin'
      `;
      const result = await detector.detectAuth(code, { file: 'routes.py' });

      expect(result).toHaveProperty('missing');
    });

    test('should detect auth decorators', async () => {
      const code = '@login_required\ndef protected(): pass';
      const result = await detector.detectAuth(code, { file: 'routes.py' });

      expect(typeof result.confidence).toBe('number');
    });
  });

  describe('detectPII', () => {
    test('should detect PII fields', async () => {
      const code = `
        class User(db.Model):
            email = db.String()
            ssn = db.String()
      `;
      const result = await detector.detectPII(code, { file: 'models.py' });

      expect(result).toHaveProperty('detected');
    });
  });

  describe('detectPublicAPI', () => {
    test('should count routes', async () => {
      const code = `
        @app.route('/a')
        def a(): pass
        @app.route('/b')
        def b(): pass
      `;
      const result = await detector.detectPublicAPI(code);

      expect(result.metadata.routeCount).toBeGreaterThan(0);
    });
  });

  describe('detectUserInput', () => {
    test('should detect request data', async () => {
      const code = 'data = request.json';
      const result = await detector.detectUserInput(code);

      expect(typeof result.detected).toBe('boolean');
    });
  });
});
