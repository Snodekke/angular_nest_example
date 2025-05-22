import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DoctorModule } from '../doctor';
import { DoctorClinicModule } from '../doctor-clinic';
import { AuthController } from './auth.controller';
import { Auth } from './auth.entity';
import { accessSignOptions, jwtAccessSecret } from './auth.options';
import { AuthService } from './auth.service';
import { AccessTokenStrategy } from './strategies/access-token.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';

@Module({
  imports: [
    DoctorModule,
    DoctorClinicModule,
    TypeOrmModule.forFeature([Auth]),
    JwtModule.register({
      secret: jwtAccessSecret,
      signOptions: accessSignOptions,
    }),
  ],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
