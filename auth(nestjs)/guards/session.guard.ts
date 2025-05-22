import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class SessionGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const session = request?.session;

    // session.touch(); // updates the .maxAge property (if req.session.save was called manually)

    if (!session?.login) {
      throw new UnauthorizedException('Время сессии истекло');
    }

    return true;
  }
}
