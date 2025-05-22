import { IsDate, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class SigninAuthDto {
  @IsString()
  login: string;

  @IsString()
  password: string;
}

export class SaveAuthDto {
  @IsString()
  uuid: string;

  @IsString()
  login: string;

  @IsString()
  password: string;

  @IsNumber()
  type: number;

  @IsDate()
  createdAt: Date;

  @IsDate()
  updatedAt: Date;
}

export class ChangePasswordDto {
  @IsString()
  login: string;

  @IsNotEmpty()
  password: string;
}
