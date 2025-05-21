import { Test } from '@nestjs/testing';
import * as pactum from 'pactum';
import { AppModule } from '../src/app.module';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuthDto } from 'src/auth/dto';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import * as argon2 from 'argon2';

describe('App e2e', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let authController: AuthController;
  let authService: AuthService;


  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
      }),
    );

    await app.init();
    await app.listen(3333);

    prisma = app.get(PrismaService);
    await prisma.cleanDb();
    pactum.request.setBaseUrl('http://localhost:3333');

    authController = app.get(AuthController);
    authService = app.get(AuthService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Auth', () => {
    beforeEach(async () => {
      await prisma.cleanDb();
    });

    describe('Signup', () => {
      const dto: AuthDto = {
        email: 'daniel@gmail.com',
        password: '123',
      };

      it('should throw if email empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ password: dto.password })
          .expectStatus(400);
      });

      it('should throw if password empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ email: dto.email })
          .expectStatus(400);
      });

      it('should throw if no body provided', () => {
        return pactum.spec().post('/auth/signup').expectStatus(400);
      });

      it('should signup', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody(dto)
          .expectStatus(201);
      });
    });

    describe('Signin', () => {
      const dto: AuthDto = {
        email: 'daniel@gmail.com',
        password: '123',
      };

      it('should throw if email empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ password: dto.password })
          .expectStatus(400);
      });

      it('should throw if password empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ email: dto.email })
          .expectStatus(400);
      });

      it('should throw if no body provided', () => {
        return pactum.spec().post('/auth/signin').expectStatus(400);
      });

      it('should signin', () => {
        const dto: AuthDto = {
          email: 'daniel@gmail.com',
          password: '123',
        };

        return pactum
          .spec()
          .post('/auth/signin')
          .withBody(dto)
          .expectStatus(200)
          .inspect()
          .stores('userAt', 'access_token');
      });
    });
  });

  // --- Google Auth Tests ---
  describe('Auth Google', () => {
    // Mock user data that GoogleStrategy's validate() would typically provide
    const mockGoogleUserBase = {
      email: 'google.user@example.com',
      firstName: 'Google',
      lastName: 'User',
      picture: 'http://example.com/picture.jpg',
      googleId: 'google123',
      accessToken: 'mockGoogleAccessToken',
    };

    beforeEach(async () => {
      await prisma.cleanDb();
      jest.clearAllMocks(); // Clear mocks before each test
    });

    describe('/auth/google (GET)', () => {
      it('should initiate Google OAuth flow (expect 302 redirect)', () => {
        // This test is tricky because the guard initiates an external redirect.
        // Pactum might follow it or error. We're checking that it doesn't return a 200/201.
        // A 302 Found would be typical for the redirect.
        // If the guard is not set up correctly, it might pass through or error differently.
        return pactum
          .spec()
          .get('/auth/google')
          .expectStatus(302); // Or 401 if configured to throw error if strategy not found immediately
      });
    });

    describe('/auth/google/callback (GET) - Direct Invocation Tests', () => {
      it('should sign up a new user via Google, create user in DB, and return JWT', async () => {
        const mockReq = {
          user: mockGoogleUserBase, // This is what AuthGuard('google') would place on req.user
        };

        const expectedUserFromDb = {
          id: expect.any(Number), // DB will assign an ID
          email: mockGoogleUserBase.email,
          googleId: mockGoogleUserBase.googleId,
          firstName: mockGoogleUserBase.firstName,
          lastName: mockGoogleUserBase.lastName,
          provider: 'google',
          hash: null,
          createdAt: expect.any(Date),
          updatedAt: expect.any(Date),
        };

        const mockedToken = { access_token: 'mocked_jwt_token_for_google_user' };

        // Mock AuthService.validateOAuthLogin
        // This spy is important to ensure that the service method which handles user creation/retrieval
        // based on OAuth profile is correctly implemented.
        // For this test, it simulates creating a new user.
        const validateOAuthLoginSpy = jest
          .spyOn(authService, 'validateOAuthLogin')
          .mockResolvedValueOnce(expectedUserFromDb as any); // as any to satisfy User type

        // Mock AuthService.signToken
        // This spy ensures that after user validation/creation, token signing is attempted.
        const signTokenSpy = jest
          .spyOn(authService, 'signToken')
          .mockResolvedValueOnce(mockedToken);

        // Directly invoke the controller method
        const result = await authController.googleAuthRedirect(mockReq as any); // as any for Express.Request

        // Verify token
        expect(result).toEqual(mockedToken);

        // Verify that validateOAuthLogin was called correctly
        // The controller passes the raw req.user (mockGoogleUserBase) to validateOAuthLogin
        expect(validateOAuthLoginSpy).toHaveBeenCalledWith(
          mockGoogleUserBase, // It receives the raw profile
          'google',
        );
        
        // Verify that signToken was called correctly with the processed user entity's details
        expect(signTokenSpy).toHaveBeenCalledWith(
          expectedUserFromDb.id,
          expectedUserFromDb.email,
        );

        // Verify database state
        const userInDb = await prisma.user.findUnique({
          where: { email: mockGoogleUserBase.email },
        });
        expect(userInDb).toBeDefined();
        expect(userInDb.googleId).toBe(mockGoogleUserBase.googleId);
        expect(userInDb.provider).toBe('google');
        expect(userInDb.hash).toBeNull();
      });

      it('should log in an existing Google user and return JWT', async () => {
        // 1. Create the user in DB first to simulate existing Google user
        const existingDbUser = await prisma.user.create({
          data: {
            email: mockGoogleUserBase.email,
            googleId: mockGoogleUserBase.googleId,
            provider: 'google',
            firstName: mockGoogleUserBase.firstName,
            lastName: mockGoogleUserBase.lastName,
          },
        });
        
        const mockReq = { user: { ...mockGoogleUserBase, id: existingDbUser.id } }; // Simulate guard providing user
        const mockedToken = { access_token: 'mocked_jwt_for_existing_google_user' };

        jest.spyOn(authService, 'validateOAuthLogin').mockResolvedValueOnce(existingDbUser);
        jest.spyOn(authService, 'signToken').mockResolvedValueOnce(mockedToken);

        const result = await authController.googleAuthRedirect(mockReq as any);

        expect(result).toEqual(mockedToken);
        expect(authService.validateOAuthLogin).toHaveBeenCalledWith(
          expect.objectContaining({ googleId: mockGoogleUserBase.googleId, email: mockGoogleUserBase.email }),
          'google'
        );
        expect(authService.signToken).toHaveBeenCalledWith(existingDbUser.id, existingDbUser.email);
        
        const userCount = await prisma.user.count({ where: { email: mockGoogleUserBase.email }});
        expect(userCount).toBe(1); // No new user created
      });

      it('should link Google account to an existing local user and return JWT', async () => {
        // 1. Create a local user
        const localUser = await prisma.user.create({
          data: {
            email: mockGoogleUserBase.email, // Same email
            hash: await argon2.hash('password123'), // Use imported argon2
            provider: 'local',
            firstName: 'Local',
          },
        });

        // mockReq.user should be the raw Google profile, as passed by the guard
        const mockReq = { user: mockGoogleUserBase }; 
        const mockedToken = { access_token: 'mocked_jwt_for_linked_user' };
        
        // Mock validateOAuthLogin to return the user, now linked with Google
        // This is the User entity that validateOAuthLogin would produce.
        const linkedUserEntity = { 
          ...localUser, 
          googleId: mockGoogleUserBase.googleId, 
          provider: 'google', // Provider is now google
          firstName: localUser.firstName, 
          lastName: mockGoogleUserBase.lastName, // Assume lastName is updated from Google profile
          updatedAt: expect.any(Date), // Should be updated
        };
        const validateOAuthLoginSpy = jest.spyOn(authService, 'validateOAuthLogin').mockResolvedValueOnce(linkedUserEntity);
        const signTokenSpy = jest.spyOn(authService, 'signToken').mockResolvedValueOnce(mockedToken);

        const result = await authController.googleAuthRedirect(mockReq as any);

        expect(result).toEqual(mockedToken);
        // authService.validateOAuthLogin receives the raw Google profile
        expect(validateOAuthLoginSpy).toHaveBeenCalledWith(
          mockGoogleUserBase,
          'google'
        );
        // authService.signToken receives id and email from the *linkedUserEntity*
        expect(signTokenSpy).toHaveBeenCalledWith(linkedUserEntity.id, linkedUserEntity.email);

        const dbUser = await prisma.user.findUnique({ where: { email: mockGoogleUserBase.email }});
        expect(dbUser.googleId).toBe(mockGoogleUserBase.googleId);
        expect(dbUser.provider).toBe('google');
        expect(dbUser.hash).toBeDefined(); 
        expect(dbUser.firstName).toBe('Local');
        expect(dbUser.lastName).toBe(mockGoogleUserBase.lastName); // Check if last name was updated
      });
    });
  });
  // --- End Google Auth Tests ---

    describe('Edit user', () => {});
  });

  describe('Bookmarks', () => {
    describe('Create bookmark', () => {});

    describe('Get bookmarks', () => {});

    describe('Get bookmark by id', () => {});

    describe('Edit bookmark', () => {});

    describe('Delete bookmark', () => {});
  });
});
