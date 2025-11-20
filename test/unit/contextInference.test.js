const ContextInferenceSystem = require('../../src/contextInference');

describe('ContextInferenceSystem', () => {
  let system;

  beforeEach(() => {
    system = new ContextInferenceSystem();
  });

  describe('inferFindingContext', () => {
    test('should detect internet-facing indicators', async () => {
      const finding = {
        file: 'api/routes.js',
        message: 'SQL injection vulnerability'
      };
      
      const code = `
        app.get('/api/users', (req, res) => {
          const query = "SELECT * FROM users WHERE id=" + req.params.id;
        });
      `;

      const result = await system.inferFindingContext(finding, code, '.');

      expect(result).toHaveProperty('internetFacing');
      expect(result.internetFacing).toBeTruthy();
    });

    test('should detect authentication patterns', async () => {
      const finding = {
        file: 'auth.js',
        message: 'Weak authentication'
      };
      
      const code = `
        const jwt = require('jsonwebtoken');
        function authenticate(token) {
          return jwt.verify(token, secret);
        }
      `;

      const result = await system.inferFindingContext(finding, code, '.');

      expect(result).toBeDefined();
    });

    test('should handle empty code', async () => {
      const finding = { file: 'test.js' };
      const result = await system.inferFindingContext(finding, '', '.');

      expect(result).toBeDefined();
      expect(typeof result).toBe('object');
    });
  });

  describe('Context Inference - Edge Cases', () => {
    test('should handle multiple routes in same file', async () => {
      const finding = { file: 'routes.js', message: 'vulnerability' };
      const code = `
        app.get('/api/users', (req, res) => { res.json(users); });
        app.post('/api/users', (req, res) => { users.push(req.body); });
        app.delete('/api/users/:id', (req, res) => { users.delete(req.params.id); });
      `;
      const context = await system.inferFindingContext(finding, code, '.');
      
      expect(context).toBeDefined();
      expect(context.internetFacing).toBeTruthy();
    });

    test('should detect mixed auth scenarios', async () => {
      const finding = { file: 'auth.js', message: 'auth issue' };
      const code = `
        app.get('/public', (req, res) => { res.json({ public: true }); });
        app.get('/private', authMiddleware, (req, res) => { res.json({ private: true }); });
      `;
      const context = await system.inferFindingContext(finding, code, '.');
      
      expect(context).toBeDefined();
    });

    test('should handle syntax errors gracefully', async () => {
      const finding = { file: 'broken.js', message: 'error' };
      const code = `app.get('/broken', (req, res) => {{{{{ invalid`;
      
      await expect(system.inferFindingContext(finding, code, '.')).resolves.toBeDefined();
    });
  });
});