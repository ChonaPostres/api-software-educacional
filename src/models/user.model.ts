import {hasOne, model, property} from '@loopback/repository';
import { TimestampEntity } from '../lib/timestamp-entity';
import {UserCredentials} from '../models';

@model()
export class User extends TimestampEntity {
  @property({
    type: 'string',
    id: true
  })
  id: string;

  @property({
    type: 'string',
    required: true,
  })
  name: string;

  @property({
    type: 'string',
    required: true,
  })
  lastName: string;

  @property({
    type: 'string',
    required: true,
  })
  nickname: string;

  @property({
    type: 'string',
    required: true,
  })
  email: string;

  @property({
    type: 'string',
    required: true,
  })
  role: string;

  @property({
    type: 'number',
    required: true,
    default: 1
  })
  status: number;

  @property({
    type: 'number',
    required: true,
    default: 0
  })
  failedAttempts: number;

  @property({
    type: 'number',
    required: true,
    default: 0
  })
  score: number;

  @hasOne(() => UserCredentials)
  userCredentials: UserCredentials;


  constructor(data?: Partial<User>) {
    super(data);
  }
}

export interface UserRelations {
  // describe navigational properties here
}

export type UserWithRelations = User & UserRelations;
