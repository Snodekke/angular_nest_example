import { IDoctor } from '@ek/interfaces';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Logger,
  Patch,
  Post,
  Req,
  Res,
  Session,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { RequestContext } from '../context';
import { DoctorClinicService } from '../doctor-clinic';
import { ChangePasswordDto, SaveAuthDto, SigninAuthDto } from './auth.dto';
import { AuthService } from './auth.service';
import { Roles } from './decorators';
import { JwtAuthGuard, RefreshTokenGuard, SessionGuard } from './guards';

@ApiTags('Аутентификация и авторизация')
@Controller('core/auth')
export class AuthController {
  constructor(
    private service: AuthService,
    private doctorClinicService: DoctorClinicService,
  ) {}

  @Post('signin')
  @ApiOperation({ summary: 'Аутентификация' })
  @HttpCode(HttpStatus.OK)
  async login(@Req() req, @Body() dto: SigninAuthDto) {
    const authTokens = await this.service.signin(dto.login, dto.password);

    req.session.login = dto.login;
    req.session.save((err) => {
      if (err) {
        Logger.error(err);
      }
    });

    return authTokens;
  }

  @Post('refreshToken')
  @ApiOperation({ summary: 'Обновление JWT-токена' })
  @ApiBearerAuth()
  @UseGuards(RefreshTokenGuard, SessionGuard)
  @HttpCode(HttpStatus.CREATED)
  refreshToken(@Req() request) {
    const login = request['user']?.auth?.login;
    const refreshToken = request['user']?.refreshToken;

    if (!login || !refreshToken) {
      throw new UnauthorizedException('Ошибка при обновлении токена');
    }

    return this.service.refreshToken(login, refreshToken);
  }

  @Get('authDoctor')
  @ApiOperation({
    summary: 'Получение данных о сессионном враче и его клиниках для авторизации',
  })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, SessionGuard)
  async getAuthDoctor(): Promise<IDoctor> {
    let authDoctor: IDoctor;

    try {
      authDoctor = await this.service.getAuthDoctor();
    } catch (err) {
      throw new UnauthorizedException('Для пользователя не заведён сотрудник');
    }

    if (authDoctor?.state === 0) {
      throw new UnauthorizedException('Сотрудник заблокирован');
    }

    if (!authDoctor?.doctorClinics?.length) {
      throw new UnauthorizedException('Сотрудник не прикреплён к учреждению');
    }

    return authDoctor;
  }

  @Post('setSession')
  @ApiOperation({ summary: 'Установка сессии для выбранной клиники' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, SessionGuard)
  async setSession(@Req() req, @Res() res: Response): Promise<void> {
    const context = RequestContext.currentUser();
    const uuidDoctorClinic = req?.body?.uuidDoctorClinic;

    if (!uuidDoctorClinic) {
      throw new UnauthorizedException('Unauthorized');
    }

    if (!context.auth?.uuid) {
      throw new UnauthorizedException('Unauthorized');
    }

    const doctorClinic = await this.doctorClinicService.findOne(uuidDoctorClinic, {
      relations: ['role'],
    });

    if (context.auth?.uuid !== doctorClinic.uuidDoctor) {
      throw new UnauthorizedException('Unauthorized');
    }

    req.session.uuidDoctor = doctorClinic?.uuidDoctor;
    req.session.uuidDoctorClinic = doctorClinic?.uuid;
    req.session.uuidPosition = doctorClinic?.uuidPosition;
    req.session.uuidClinic = doctorClinic?.uuidClinic;
    req.session.uuidDivision = doctorClinic?.uuidDivision;
    req.session.uuidRole = doctorClinic?.uuidRole;
    req.session.uuidArea = doctorClinic?.uuidArea;
    req.session.rights = doctorClinic?.role?.rights;
    req.session.role = doctorClinic?.role?.type;

    res.status(HttpStatus.OK).send();
    // req.session.save((err) => {
    //   if (err) {
    //     Logger.error(err);
    //   }

    //   res.status(HttpStatus.OK).send();
    // });
  }

  @Post('logout')
  @ApiOperation({ summary: 'Выход из сессии' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, SessionGuard)
  async logout(@Req() req, @Res() res: Response): Promise<void> {
    const context = RequestContext.currentUser();

    if (!context.auth?.uuid) {
      throw new UnauthorizedException('Unauthorized');
    }

    req.session.destroy();
    res.status(HttpStatus.OK).send();
  }

  @HttpCode(HttpStatus.OK)
  @Patch('')
  @ApiOperation({ summary: 'Создание / Редактирование учетной записи пользователя' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, SessionGuard)
  @Roles(['system.admin', 'mo.admin'])
  async save(@Body() dto: SaveAuthDto, @Session() session) {
    if (session.role !== 'system.admin' && dto.login === 'admin') {
      throw new UnauthorizedException('Unauthorized');
    }

    return this.service.save(dto);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('changePassword')
  @ApiOperation({ summary: 'Изменение пароля' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, SessionGuard)
  @Roles(['system.admin', 'mo.admin'])
  async changePassword(@Body() dto: ChangePasswordDto, @Session() session) {
    if (session.role !== 'system.admin' && dto.login === 'admin') {
      throw new UnauthorizedException('Unauthorized');
    }

    return this.service.changePassword(dto.login, dto.password);
  }
}
