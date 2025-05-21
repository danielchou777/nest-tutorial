import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common'; // Added Get, Req, UseGuards
import { AuthGuard } from '@nestjs/passport'; // Added AuthGuard
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signin(@Body() dto: AuthDto) {
    return this.authService.signin(dto);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req) {
    // Initiates the Google OAuth2 login flow
    // Passport automatically redirects to Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req) {
    // Google redirects here after user grants permission
    // req.user contains the user profile from GoogleStrategy.validate()
    // We need to sign a token for this user.
    // This will likely call a method in AuthService, e.g., this.authService.signInOAuthUser(req.user)
    // For now, let's assume authService has a method that takes the user object from Google 
    // and returns a JWT, similar to signToken.
    
    if (!req.user) {
      throw new Error('User not found from Google OAuth');
    }
    
    // Assuming req.user has id and email, which signToken expects.
    // If req.user structure is different (e.g. from our GoogleStrategy's validate method),
    // this might need adjustment or a new service method.
    // The current GoogleStrategy's validate method provides a user object like:
    // { email, firstName, lastName, picture, googleId, accessToken }
    // This needs to be converted/processed by AuthService to a full User entity
    // and then a token signed. This will be handled in the AuthService update step.
    // For now, we'll call signToken if the user object from strategy is compatible.
    // Let's assume AuthService will have a method like processOAuthUser
    // which returns an object compatible with signToken.

    // The raw profile from GoogleStrategy.validate() is in req.user.
    // We need to pass this to AuthService to find or create the user,
    // then sign a token for that user.
    const userEntity = await this.authService.validateOAuthLogin(req.user, 'google');
    
    // Now sign the token using the ID and email from the processed user entity
    return this.authService.signToken(userEntity.id, userEntity.email);
  }
}
