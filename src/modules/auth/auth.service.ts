import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { LoginDto } from './dto/login.dto';
import { JwtPayload, Tokens } from './interfaces/jwt-payload.interface';
import { User, UserRole } from '../users/entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import { LoginResponseDto, TokensResponseDto } from './dto/auth-response.dto';

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 15;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  private readonly accessSecret: string;
  private readonly refreshSecret: string;
  private readonly accessExpiresIn: string;
  private readonly refreshExpiresIn: string;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.accessSecret = this.configService.getOrThrow<string>('JWT_ACCESS_SECRET');
    this.refreshSecret = this.configService.getOrThrow<string>('JWT_REFRESH_SECRET');

    this.accessExpiresIn = this.configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m');
    this.refreshExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN', '7d');
  }


  async register(registerDto: RegisterDto): Promise<LoginResponseDto> {
    const { email, password, firstName, lastName, roles } = registerDto;

    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new ConflictException('An account with this email already exists');
    }

    const user = this.userRepository.create({
      firstName,
      lastName,
      email,
      password,
      roles: roles ?? [UserRole.USER],
    });

    const savedUser = await this.userRepository.save(user);
    this.logger.log(`New user registered: ${savedUser.email}`);

    const tokens = await this.generateTokens(savedUser.id, savedUser.email, savedUser.roles);
    await this.storeRefreshToken(savedUser.id, tokens.refreshToken);

    return { user: savedUser.toSafeObject() as any, tokens };
  }


  async login(loginDto: LoginDto): Promise<LoginResponseDto> {
    const { email, password } = loginDto;

    const user = await this.userRepository
      .createQueryBuilder('user')
      .addSelect('user.password')
      .where('user.email = :email', { email })
      .getOne();

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new ForbiddenException('Account has been deactivated. Please contact support.');
    }

    if (user.isLocked) {
      const minutesLeft = Math.ceil(
        (user.lockedUntil!.getTime() - Date.now()) / 60000,
      );
      throw new ForbiddenException(
        `Account is temporarily locked. Try again in ${minutesLeft} minute(s).`,
      );
    }

    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      await this.handleFailedLogin(user);
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.userRepository.update(user.id, {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: new Date(),
    });

    this.logger.log(`User logged in: ${user.email}`);

    const tokens = await this.generateTokens(user.id, user.email, user.roles);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return { user: user.toSafeObject() as any, tokens };
  }


  async logout(userId: string): Promise<void> {
    const result = await this.userRepository.update(
      { id: userId },
      { hashedRefreshToken: null },
    );

    if (result.affected === 0) {
      this.logger.warn(`Logout called for user ${userId} with no active session`);
    } else {
      this.logger.log(`User ${userId} logged out`);
    }
  }


  async refreshTokens(
    userId: string,
    email: string,
    roles: string[],
    incomingRefreshToken: string,
  ): Promise<TokensResponseDto> {
    const user = await this.userRepository
      .createQueryBuilder('user')
      .addSelect('user.hashedRefreshToken')
      .where('user.id = :id AND user.isActive = :isActive', {
        id: userId,
        isActive: true,
      })
      .getOne();

    if (!user || !user.hashedRefreshToken) {
      throw new ForbiddenException('Access denied. Please log in again.');
    }

    const tokenMatches = await bcrypt.compare(
      incomingRefreshToken,
      user.hashedRefreshToken,
    );

    if (!tokenMatches) {
      await this.userRepository.update(userId, { hashedRefreshToken: null });
      this.logger.warn(`Possible refresh token reuse detected for user: ${userId}`);
      throw new ForbiddenException(
        'Refresh token has already been used. Please log in again.',
      );
    }

    this.logger.log(`Tokens refreshed for user: ${userId}`);

    const tokens = await this.generateTokens(userId, email, roles);
    await this.storeRefreshToken(userId, tokens.refreshToken);

    return tokens;
  }


  async getProfile(userId: string): Promise<Partial<User>> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user.toSafeObject();
  }


  private async generateTokens(
    userId: string,
    email: string,
    roles: string[],
  ): Promise<Tokens> {
    const payload: JwtPayload = { sub: userId, email, roles };

    const accessOptions: any = {
      secret: this.accessSecret,
      expiresIn: this.accessExpiresIn,
    };

    const refreshOptions: any = {
      secret: this.refreshSecret,
      expiresIn: this.refreshExpiresIn,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, accessOptions),
      this.jwtService.signAsync(payload, refreshOptions),
    ]);

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(userId: string, refreshToken: string): Promise<void> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.userRepository.update(userId, { hashedRefreshToken });
  }

  private async handleFailedLogin(user: User): Promise<void> {
    const newFailedAttempts = user.failedLoginAttempts + 1;

    if (newFailedAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockedUntil = new Date(Date.now() + LOCK_DURATION_MINUTES * 60 * 1000);
      await this.userRepository.update(user.id, {
        failedLoginAttempts: newFailedAttempts,
        lockedUntil,
      });
      this.logger.warn(`Account locked for ${LOCK_DURATION_MINUTES} minutes: ${user.email}`);
    } else {
      await this.userRepository.update(user.id, {
        failedLoginAttempts: newFailedAttempts,
      });
    }
  }
}