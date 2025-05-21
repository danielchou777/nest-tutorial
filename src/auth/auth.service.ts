import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client'; // Import User type

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto): Promise<Omit<User, 'hash'>> {
    // Check if user already exists with this email
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      if (existingUser.provider === 'google') {
        throw new ForbiddenException(
          'Email already registered with Google. Please login using Google.',
        );
      }
      // If local user exists, normal "Credentials taken" error will be thrown by P2002
    }

    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
          provider: 'local', // Explicitly set provider for local signup
        },
      });
      const { hash: _, ...result } = user;
      return result;
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw err;
    }
  }

  async signin(dto: AuthDto): Promise<{ access_token: string }> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Credentials incorrect');

    if (user.provider === 'google' && !user.hash) {
      throw new ForbiddenException('Please login using Google.');
    }
    
    if (!user.hash) {
      // This case should ideally not happen if provider is 'local'
      throw new ForbiddenException('Credentials incorrect. No password set for this account.');
    }

    const pwMatches = await argon.verify(user.hash, dto.password);
    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
    return {
      access_token: token,
    };
  }

  async validateOAuthLogin(
    profile: {
      googleId: string;
      email: string;
      firstName?: string;
      lastName?: string;
    },
    providerName: 'google', // Can be extended for other providers
  ): Promise<User> {
    try {
      // Check if user already exists with this googleId
      let user = await this.prisma.user.findUnique({
        where: { googleId: profile.googleId },
      });

      if (user) {
        return user;
      }

      // Check if user already exists with this email
      user = await this.prisma.user.findUnique({
        where: { email: profile.email },
      });

      if (user) {
        // User exists with this email, but not linked to this Google account yet.
        // Link Google account.
        if (user.provider === 'local' || !user.provider) {
          user = await this.prisma.user.update({
            where: { email: profile.email },
            data: {
              googleId: profile.googleId,
              provider: providerName,
              // Potentially update firstName/lastName if empty and provided by Google
              firstName: user.firstName || profile.firstName,
              lastName: user.lastName || profile.lastName,
            },
          });
          return user;
        } else if (user.provider !== providerName) {
          // User exists with this email but is linked to a different OAuth provider
          throw new ForbiddenException(
            `Email already linked with ${user.provider}. Cannot link with ${providerName}.`,
          );
        }
        // If user.provider is already providerName, but googleId didn't match,
        // this is an odd state, potentially a different Google account with same email.
        // For now, we assume googleId is the primary key for OAuth.
        // If googleId matched, it would have been found in the first check.
        // This path (email match, provider match, but googleId mismatch) should be rare.
        // We can throw an error or decide on a specific handling strategy.
        // For simplicity, if it's the same provider, we assume it's the same user.
        // However, the first check for googleId should catch this.
      }

      // No user with this googleId or email, create new user
      const newUser = await this.prisma.user.create({
        data: {
          googleId: profile.googleId,
          email: profile.email,
          firstName: profile.firstName,
          lastName: profile.lastName,
          provider: providerName,
          // hash will be null as this is an OAuth user
        },
      });
      return newUser;
    } catch (err) {
      // Log the error for debugging
      console.error("Error in validateOAuthLogin: ", err);
      if (err instanceof ForbiddenException) throw err;
      throw new Error('Authentication failed. Please try again.');
    }
  }
}
