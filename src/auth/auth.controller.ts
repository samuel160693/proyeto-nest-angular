import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    console.log(createUserDto);
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login( @Body() loginDto: LoginDto ){
    return this.authService.login( loginDto );
  }

  @Post('/register')
  register( @Body() registerUserDto: RegisterUserDto ){
    return this.authService.register( registerUserDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request ) {
    // const user = req['user'];

    // return user;


    return this.authService.findAll();
  }

  @UseGuards( AuthGuard )
  @Get('check-token')
  
  checkToken(@Request() req: Request ) : LoginResponse{
     const user = req['user'] as User;

     return{
       user, 
       token: this.authService.getJwtToken({ id:user._id })
     }
   
  }
}
