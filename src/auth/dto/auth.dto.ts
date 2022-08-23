import { IsNotEmpty, IsString } from 'class-validator';

export class AuthDTO {
    @IsNotEmpty()
    @IsString()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;
}