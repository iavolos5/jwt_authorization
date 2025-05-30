import {
  IsString,
  IsNotEmpty,
  IsEmail,
  MinLength,
  MaxLength,
} from 'class-validator';

export class LoginRequest {
  @IsString({ message: 'email должен быть строкой' })
  @IsNotEmpty({ message: 'Заполните поле email' })
  @IsEmail({}, { message: 'Формат email не правильный' })
  email: string;

  @IsString({ message: 'password должен быть строкой' })
  @IsNotEmpty({ message: 'Заполните поле password' })
  @MinLength(6, { message: 'password от 6 символов' })
  @MaxLength(128, { message: 'password до 128 символов' })
  password: string;
}
