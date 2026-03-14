import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    BeforeInsert,
    BeforeUpdate,
    Index,
} from 'typeorm';
import * as bcrypt from 'bcrypt';

export enum UserRole {
    SUPER_ADMIN = 'super-admin',
    ADMIN = 'admin',
    USER = 'user',
    MODERATOR = 'moderator',
}

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ name: 'first_name', type: 'varchar', length: 50 })
    firstName: string;

    @Column({ name: 'last_name', type: 'varchar', length: 50 })
    lastName: string;

    @Index({ unique: true })
    @Column({ type: 'varchar', unique: true, length: 255 })
    email: string;

    // select: false — never returned in normal queries; use addSelect() explicitly
    @Column({ type: 'varchar', length: 255, select: false })
    password: string;

    @Column({ type: 'simple-array', default: UserRole.USER })
    roles: string[];

    @Column({ name: 'is_active', type: 'boolean', default: true })
    isActive: boolean;

    @Column({ name: 'last_login_at', type: 'timestamptz', nullable: true, default: null })
    lastLoginAt: Date | null;

    @Column({ name: 'failed_login_attempts', type: 'int', default: 0 })
    failedLoginAttempts: number;

    @Column({ name: 'locked_until', type: 'timestamptz', nullable: true, default: null })
    lockedUntil: Date | null;

    @Column({ type: 'varchar', nullable: true, select: false })
    hashedRefreshToken: string | null;
    
    @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
    updatedAt: Date;

    @BeforeInsert()
    @BeforeUpdate()
    async hashPassword(): Promise<void> {
        if (this.password && !this.password.startsWith('$2b$')) {
            this.password = await bcrypt.hash(this.password, 12);
        }
    }


    async validatePassword(plainPassword: string): Promise<boolean> {
        return bcrypt.compare(plainPassword, this.password);
    }

    get fullName(): string {
        return `${this.firstName} ${this.lastName}`;
    }

    get isLocked(): boolean {
        if (!this.lockedUntil) return false;
        return new Date() < this.lockedUntil;
    }

    toSafeObject(): Partial<User> {
        const { password, hashedRefreshToken, ...safe } = this as any;
        return safe;
    }
}