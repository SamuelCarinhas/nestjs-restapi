import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";

type JwtPayload = {
    sub: string;
    email: string;
};

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {

    constructor(config: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get('AT_SECRET')
        });
    }

    validate(payload: JwtPayload) {
        return payload;
    }

}