import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private config: ConfigService
        ) {}

    async signupLocal(dto: AuthDTO): Promise<Tokens> {
        const hash = await argon.hash(dto.password);

        const newUser = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash
            }
        });

        const tokens = await this.getTokens(newUser.id, newUser.email);
        await this.updateRtHash(newUser.id, tokens.refresh_token);

        return tokens;
    }

    async signinLocal(dto: AuthDTO): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        });

        if(!user)
            throw new ForbiddenException('Access denied');
        
        const passwordMatches = await argon.verify(user.hash, dto.password);

        if(!passwordMatches)
            throw new ForbiddenException('Access denied');
        
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async logout(userId: number) {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashedRt: {
                    not: null
                }
            },
            data: {
                hashedRt: null
            }
        });
    }

    async refreshTokens(userId: number, rt: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId
            }
        });

        if(!user || !user.hashedRt)
            throw new ForbiddenException('Access denied');

        const rtMatches = await argon.verify(user.hashedRt, rt);
        
        if(!rtMatches)
            throw new ForbiddenException('Access denied');
        
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }
    
    async getTokens(userId: number, email: string): Promise<Tokens> {
        const [at, rt] = await Promise.all([
            this.jwtService.signAsync({
                sub: userId,
                email
            }, {
                secret: this.config.get('AT_SECRET'),
                expiresIn: '15m'
            }),
            this.jwtService.signAsync({
                sub: userId,
                email
            }, {
                secret: this.config.get('RT_SECRET'),
                expiresIn: '1w'
            })
        ]);

        return {
            access_token: at,
            refresh_token: rt
        }
    }

    async updateRtHash(userId: number, rt: string) {
        const hash = await argon.hash(rt);

        await this.prisma.user.update({
            where: {
                id: userId
            },
            data: {
                hashedRt: hash
            }
        })
    }

}
