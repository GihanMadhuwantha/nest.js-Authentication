import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
  } from '@nestjs/common';
  import { JwtService } from '@nestjs/jwt';
  import { Request } from 'express';
  import { Observable } from 'rxjs';
  
  @Injectable()
  export class RefreshTokenGuard implements CanActivate {
    constructor(private jwtService: JwtService) {}
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const request = context.switchToHttp().getRequest();
      const token = this.extractTokenFromHeader(request);
  
      if (!token) throw new UnauthorizedException();
      try {
        const payload = await this.jwtService.verifyAsync(token, {
          secret: process.env.JWT_REFRESH_TOKEN_KEY,
        });
        request['user'] = payload;
      } catch (error) {
        throw new UnauthorizedException();
      }
      return true;
    }
  
    private extractTokenFromHeader(request: Request) {
      const authHeader = request.headers.authorization;
      if (!authHeader) {
        return undefined; 
      }
      const [type, token] = request.headers.authorization.split(' ') ?? [];
      return type === 'Refresh' ? token : undefined;
    }
  }
  