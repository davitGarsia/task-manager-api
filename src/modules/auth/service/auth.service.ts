import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SignupDto } from '../dtos/signup.dto';
import { RefreshTokenDto } from '../dtos/refresh-token';
import { LoginPayloadDto } from '../dtos/LoginPayloadDto';
import { Token } from '../token.entity';
import { TokenPayloadDto } from '../dtos/TokenPayloadDto';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { v4 as uuid } from 'uuid';
import * as jwt from 'jsonwebtoken';
import { User } from '../../user/entities/user.entity';
import { UserDto } from '../../user/dto/User.dto';
import { UtilsService } from '../../../providers/utils.service';
import { Role } from '../../role/entities/role.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(Token) private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
  ) {}

  async signup(signupDto: SignupDto): Promise<LoginPayloadDto> {
    try {
      const roles = await this.userRepository.manager.find(Role, {
        where: { name: 'Super Admin' },
      });

      const user = new User();
      user.email = signupDto.email;
      user.firstName = signupDto.firstName;
      user.lastName = signupDto.lastName;
      user.password = signupDto.password;
      user.roles = roles;
      const created = await this.userRepository.save(user);
      delete created.password;
      return {
        user: new UserDto(created),
        token: await this.createToken(user),
      };
    } catch (error) {
      if (error.code === '23505') {
        throw new BadRequestException('Email already exists');
      }
      throw new BadRequestException('Something went wrong');
    }
  }

  async validateUser(email: string, password: string): Promise<any> {
    const foundUser = await this.userRepository.findOne({
      select: ['id', 'email', 'firstName', 'lastName', 'password'],
      where: { email },
      relations: ['roles', 'userPermissions', 'projects'],
    });
    if (foundUser) {
      const isPasswordValid = await UtilsService.validateHash(
        password,
        foundUser && foundUser.password,
      );
      delete foundUser.password;
      if (!foundUser || !isPasswordValid) {
        throw new NotFoundException('User not found');
      }
      return foundUser;
    }
    return null;
  }

  async login(user: User): Promise<LoginPayloadDto> {
    return {
      user: new UserDto(user),
      token: await this.createToken(user),
    };
  }

  async findByIDForPayload(id: number): Promise<User> {
    return await this.userRepository.findOne({
      where: { id },
      relations: ['roles', 'roles.permissions', 'userPermissions', 'projects'],
    });
  }

  async refreshToken(dto: RefreshTokenDto): Promise<LoginPayloadDto> {
    const checkToken = await this.checkToken(dto);
    const userEntity = await this.findByIDForPayload(checkToken.sub);
    const token = await this.createToken(userEntity);
    return new LoginPayloadDto(userEntity, token);
  }

  async checkToken({ refreshToken }: RefreshTokenDto): Promise<any> {
    const decodeToken: any = jwt.decode(refreshToken);
    const lastTokenSecret = await this.tokenRepository.findOne({
      where: {
        userId: decodeToken.sub,
        isRevoked: false,
      },
    });
    if (!lastTokenSecret) {
      throw new NotFoundException('Token not found');
    }
    try {
      const decoded: any = await jwt.verify(
        refreshToken,
        lastTokenSecret.token,
      );
      await this.tokenRepository.save({ ...lastTokenSecret, isRevoked: true });
      return decoded;
    } catch (err) {
      // err
      throw new NotFoundException('Token not found');
    }
  }

  async createToken(dto: User | UserDto): Promise<TokenPayloadDto> {
    const expiresIn = 84600;
    const user = await this.userRepository.findOne({
      where: { id: dto.id },
      relations: ['roles'],
    });
    const roles = user.roles.map((role) => role.name);
    const payload = {
      ...user,
      roles: roles,
      sub: user.id,
    };
    const lastToken = await this.tokenRepository.findOne({
      where: { userId: user.id, isRevoked: false },
    });
    let refreshTokenSecretKey = uuid();
    if (lastToken) {
      refreshTokenSecretKey = lastToken.token;
    } else {
      const token = new Token();
      token.token = refreshTokenSecretKey;
      token.userId = user.id;
      token.isRevoked = false;
      token.type = 'refresh_token';
      await this.tokenRepository.save(token);
    }
    const refreshToken = jwt.sign({ sub: user.id }, refreshTokenSecretKey, {
      expiresIn: '14d',
    });
    return new TokenPayloadDto({
      expiresIn,
      accessToken: await this.jwtService.signAsync(payload),
      refreshToken,
    });
  }

  async verifyPayload(payload: JwtPayload): Promise<User> {
    let user: User;
    try {
      user = await this.findByIDForPayload(payload.sub);
    } catch (error) {
      throw new UnauthorizedException(
        `There isn't any user with id: ${payload.sub}`,
      );
    }
    delete user.password;

    return user;
  }

  async checkEmail(email: string): Promise<{ exists: boolean }> {
    const userFound = await this.userRepository.findOne({ where: { email } });
    return {
      exists: !!userFound,
    };
  }
}
