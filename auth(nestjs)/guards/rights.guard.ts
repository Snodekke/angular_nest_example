import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Rights } from '../decorators';

@Injectable()
export class RightsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRights = this.reflector.get(Rights, context.getHandler());

    if (!requiredRights) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const session = request?.session;

    if (!session) {
      return false;
    }

    // У пользователя из сессии должно быть хотя бы одно право из перечисленных в requiredRights
    for (const requiredRight of requiredRights) {
      if (session.rights[requiredRight] === true) {
        return true;
      }
    }

    return false;
  }
}
