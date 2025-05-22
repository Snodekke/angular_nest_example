import { IAccessTokenPayload, IAuth, IAuthTokens } from '@ek/interfaces';
import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RequestContext } from '../context/request-context';
import { DoctorService } from '../doctor';
import { SaveAuthDto } from './auth.dto';
import { Auth } from './auth.entity';
import {
  accessSignOptions,
  jwtAccessSecret,
  jwtRefreshSecret,
  refreshSignOptions,
} from './auth.options';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const md5 = require('md5');

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth)
    private readonly authRepository: Repository<Auth>,
    @Inject(JwtService)
    private readonly jwtService: JwtService,
    @Inject(DoctorService)
    private readonly doctorService: DoctorService,
  ) {}

  /**
   * Аутентификация
   */
  public async signin(login: string, password: string): Promise<IAuthTokens> {
    let authInfo: IAuth;

    if (!login) {
      throw new BadRequestException('Неверный логин и/или пароль.');
    }

    let proxyLogin: string;

    // Проверка на добавочный прокси-логин. Например, в admin[test], test - это добавочный логин
    if (login.search(/\[(.*?)\]/) > 0) {
      proxyLogin = login.match(/\[(.*?)\]/)[1];
      login = login.match(/^(.+?)\[/)[1];
    }

    try {
      authInfo = await this.getAuthInfo(login);
    } catch (e) {
      console.log(e);
      throw new BadRequestException('Неверный логин и/или пароль.');
    }

    const isPasswordValid = await this.validatePassword(password, authInfo.password);

    if (!isPasswordValid) {
      throw new BadRequestException('Неверный логин и/или пароль.');
    }

    if (login === 'admin' && proxyLogin) {
      try {
        authInfo = await this.getAuthInfo(proxyLogin);
      } catch (e) {
        console.log(e);
        throw new BadRequestException('Неверный добавочный логин.');
      }
    }

    const payload = this.setPayload(authInfo);
    return await this.getTokens(payload);
  }

  /**
   * Обновление JWT-токена
   */
  async refreshToken(login: string, refreshToken: string): Promise<IAuthTokens> {
    const authInfo = await this.getAuthInfo(login);
    const payload = this.setPayload(authInfo);
    return {
      accessToken: await this.signAccessToken(payload),
      refreshToken,
    };
  }

  /**
   * Возвращает полезную нагрузку JWT-токена
   */
  setPayload(authInfo: IAuth): IAccessTokenPayload {
    const payload: IAccessTokenPayload = {
      auth: {
        uuid: authInfo.uuid,
        login: authInfo.login,
      },
    };

    return payload;
  }

  /**
   * Возвращает подписанные JWT-токены
   */
  async getTokens(payload: IAccessTokenPayload): Promise<IAuthTokens> {
    return {
      accessToken: await this.signAccessToken(payload),
      refreshToken: await this.signRefreshToken(payload),
    };
  }

  /**
   * Шифрование пароля
   */
  public async encryptPassword(password: string): Promise<string> {
    return md5(password);
  }

  /**
   * Валидация пароля
   */
  public async validatePassword(password: string, encryptedPassword: string): Promise<boolean> {
    return md5(password) === encryptedPassword;
  }

  /**
   * Подписание токена доступа
   */
  async signAccessToken(payload: IAccessTokenPayload): Promise<string> {
    return this.jwtService.signAsync(payload, {
      secret: jwtAccessSecret,
      ...accessSignOptions,
    });
  }

  /**
   * Подписание токена обновления
   */
  async signRefreshToken(payload: IAccessTokenPayload): Promise<string> {
    return this.jwtService.signAsync(payload, {
      secret: jwtRefreshSecret,
      ...refreshSignOptions,
    });
  }

  /**
   * Получение данных о сессионном враче и его клиниках для авторизации
   */
  getAuthDoctor() {
    const context = RequestContext.currentUser();
    return this.doctorService.findByAuth(context.auth.uuid);
  }

  /**
   * Получение данных авторизации
   */
  getAuthInfo(login: string): Promise<Auth> {
    return this.authRepository
      .createQueryBuilder('a')
      .select(['a.uuid', 'a.login', 'a.password', 'a.type', 'a.createdAt', 'a.updatedAt'])
      .where('a.login = :login', { login })
      .getOneOrFail();
  }

  /**
   * Создание / Редактирование
   */
  async save(dto: SaveAuthDto): Promise<Auth> {
    if (!dto.uuid) {
      throw new NotFoundException('Пользователь не найден');
    }

    const item = await this.authRepository.findOne({
      where: {
        uuid: dto.uuid,
      },
    });

    const isUserExists = await this.existsByUsername(dto.login, dto.uuid);

    if (isUserExists) {
      throw new BadRequestException('Пользователь с таким логином уже зарегистрирован в системе.');
    }

    if (dto.password) {
      dto.password = await this.encryptPassword(dto.password);
    }

    if (item) {
      this.authRepository.merge(item, dto);
      return this.authRepository.save(item);
    } else {
      return this.authRepository.save(dto);
    }
  }

  /**
   * Проверка на занятость логина
   */
  async existsByUsername(login: string, uuid: string): Promise<boolean> {
    const where = {
      login,
    };

    const item = await this.authRepository.findOne({
      where,
    });

    // Логин у того же пользователя что пытается его изменить
    if (item && uuid && item.uuid === uuid) {
      return false;
    }

    return !!item;
  }

  /**
   * Изменение пароля
   */
  async changePassword(username: string, password: string) {
    const userAuthInfo = await this.getAuthInfo(username);
    const encryptedPassword = await this.encryptPassword(password);

    const data = await this.authRepository.save({
      uuid: userAuthInfo.uuid,
      password: encryptedPassword,
    });

    delete data['password'];

    return data;
  }
}
