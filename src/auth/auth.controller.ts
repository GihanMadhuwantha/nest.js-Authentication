import { Body, Controller, Post, Request, UseGuards} from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/user.dto';
import { UserService } from 'src/user/user.service';
import { LoginDto } from './dto/auth.dto';
import { AuthService } from './auth.service';
import { RefreshTokenGuard } from './guards/refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private userService: UserService,private authService:AuthService) {}

  @Post('register')
    async registerUser(@Body() createUserDto:CreateUserDto){
      return await this.userService.create(createUserDto)
    }

  @Post('login')
  async login(@Body() loginDto:LoginDto){
    return await this.authService.login(loginDto)
  }
  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  async refreshToken(@Request() req){
    return await this.authService.refreshToken(req.user)
  }
}
