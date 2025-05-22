import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import chalk from 'chalk';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { jwtAccessSecret } from '../auth.options';

type JwtPayload = {
  auth: {
    uuid: string;
    login: string;
  };
};

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    if (!jwtAccessSecret || jwtAccessSecret === 'secret') {
      console.log(
        chalk.red('Configuration property "jwtAccessSecret" is not defined or is not secure'),
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtAccessSecret,
    });
  }

  async validate(payload: JwtPayload) {
    return {
      auth: payload.auth,
    };
  }
}
