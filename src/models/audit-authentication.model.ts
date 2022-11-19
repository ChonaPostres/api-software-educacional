import {model, property} from '@loopback/repository';
import {TimestampEntity} from '../lib/timestamp-entity';

@model()
export class AuditAuthentication extends TimestampEntity {

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

  @property({
    type: 'number',
    required: true,
  })
  success: number;

  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<AuditAuthentication>) {
    super(data);
  }
}

export interface AuditAuthenticationRelations {
  // describe navigational properties here
}

export type AuditAuthenticationWithRelations = AuditAuthentication & AuditAuthenticationRelations;
