import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '@prisma/client';
import { Request } from 'express';
interface AuthenticatedRequest {
  user?: User;
}
export const Authorized = createParamDecorator(
  (data: keyof User | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();

    const user = request.user;

    if (!user) {
      return null;
    }

    return data ? user[data] : user;
  },
);
