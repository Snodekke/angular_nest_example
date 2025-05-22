import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Roles } from '../decorators';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get(Roles, context.getHandler());

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const session = request?.session;

    if (!session) {
      return false;
    }

    // Роль пользователя должна соответстовать хотя бы одной роли из перечисленных в requiredRoles
    for (const requiredRole of requiredRoles) {
      if (session.role === requiredRole) {
        return true;
      }
    }

    return false;
  }
}
