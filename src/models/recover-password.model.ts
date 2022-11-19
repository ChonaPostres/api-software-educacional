import {model, property} from '@loopback/repository';
import {TimestampEntity} from '../lib/timestamp-entity';

@model()
export class RecoverPassword extends TimestampEntity {
  @property({
    type: 'boolean',
  })
  active: boolean;

  @property({
    type: 'string',
  })
  hash: string;

  @property({
    type: 'string',
    id: true,
  })
  id: string;

  @property({
    type: 'string',
    required: true,
  })
  user: string;

  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<RecoverPassword>) {
    super(data);
  }
}

export interface RecoverPasswordRelations {
  // describe navigational properties here
}

export type RecoverPasswordWithRelations = RecoverPassword & RecoverPasswordRelations;
