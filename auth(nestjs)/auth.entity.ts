import { IAuth } from '@ek/interfaces';
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity({ schema: 'public', name: 'auth' })
export class Auth implements IAuth {
  @PrimaryGeneratedColumn('uuid', { comment: 'Идентификатор' })
  uuid: string;

  @Column({ type: 'varchar', length: 100 })
  login: string;

  @Column({ type: 'varchar', length: 100 })
  password: string;

  @Column({ type: 'int4' })
  type: number;

  @CreateDateColumn({ comment: 'Дата создания' })
  createdAt: Date;

  @UpdateDateColumn({ comment: 'Дата обновления' })
  updatedAt: Date;
}
