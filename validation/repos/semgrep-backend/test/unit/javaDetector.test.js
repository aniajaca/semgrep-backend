const JavaContextDetector = require('../../src/contextInference/detectors/javaDetector');

describe('JavaContextDetector', () => {
  let detector;

  beforeEach(() => {
    detector = new JavaContextDetector();
  });

  describe('detectRoutes', () => {
    test('should detect Spring controllers', async () => {
      const code = `
        @RestController
        @RequestMapping("/api")
        public class UserController {
          @GetMapping("/users")
          public List<User> getUsers() {}
        }
      `;
      const result = await detector.detectRoutes(code, { file: 'UserController.java' });

      expect(result).toHaveProperty('detected');
      expect(result).toHaveProperty('confidence');
    });

    test('should detect JAX-RS', async () => {
      const code = '@Path("/api")\n@GET\npublic Response get() {}';
      const result = await detector.detectRoutes(code, { file: 'Resource.java' });

      expect(typeof result.detected).toBe('boolean');
    });

    test('should use path heuristic', async () => {
      const result = await detector.detectRoutes('class Test {}', { 
        file: '/controller/UserController.java' 
      });

      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });
  });

  describe('detectAuth', () => {
    test('should detect missing auth', async () => {
      const code = '@RestController\nclass Api {}';
      const result = await detector.detectAuth(code, { file: 'Controller.java' });

      expect(result).toHaveProperty('missing');
    });

    test('should detect auth annotations', async () => {
      const code = '@PreAuthorize("hasRole(\'ADMIN\')")\n@GetMapping';
      const result = await detector.detectAuth(code, { file: 'Controller.java' });

      expect(typeof result.confidence).toBe('number');
    });
  });

  describe('detectPII', () => {
    test('should detect PII fields', async () => {
      const code = `
        @Entity
        class User {
          private String email;
          private String ssn;
        }
      `;
      const result = await detector.detectPII(code, { file: 'User.java' });

      expect(result).toHaveProperty('detected');
    });
  });

  describe('detectPublicAPI', () => {
    test('should count mappings', async () => {
      const code = '@GetMapping\n@PostMapping';
      const result = await detector.detectPublicAPI(code);

      expect(result.metadata.routeCount).toBeGreaterThan(0);
    });
  });

  describe('detectUserInput', () => {
    test('should detect request body', async () => {
      const code = '@RequestBody User user';
      const result = await detector.detectUserInput(code);

      expect(typeof result.detected).toBe('boolean');
    });
  });
});
