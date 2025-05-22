import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import chalk from 'chalk';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { jwtRefreshSecret } from '../auth.options';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor() {
    if (!jwtRefreshSecret || jwtRefreshSecret === 'secret') {
      console.log(
        chalk.red('Configuration property "jwtRefreshSecret" is not defined or is not secure'),
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtRefreshSecret,
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: any) {
    const refreshToken = req.get('Authorization').replace('Bearer', '').trim();
    return { ...payload, refreshToken };
  }
}
