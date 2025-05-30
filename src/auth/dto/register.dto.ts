import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class RegisterRequest {
  @IsString({ message: 'Имя должно быть строкой' })
  @IsNotEmpty({ message: 'Заполните поле Имя' })
  @MaxLength(50, { message: 'Имя не может быть больше 50 символов' })
  name: string;

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
