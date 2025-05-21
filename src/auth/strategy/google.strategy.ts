import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service'; // We'll need this later

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private configService: ConfigService,
    private authService: AuthService, // Will be used for findOrCreateUser logic
  ) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { name, emails, photos, id } = profile;
    const user = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos[0].value,
      googleId: id,
      accessToken, // Optional: store access token if needed for future Google API calls
    };
    
    // Placeholder for findOrCreateUser logic, which will be in AuthService
    // For now, we'll assume the authService will handle this.
    // const validatedUser = await this.authService.validateOAuthLogin(user, 'google');
    // done(null, validatedUser);

    // Temporary: directly pass the processed user data.
    // This will be replaced by a call to a method in AuthService.
    done(null, user); 
  }
}
