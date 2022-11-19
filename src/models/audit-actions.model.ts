import {model, property} from '@loopback/repository';
import {TimestampEntity} from '../lib/timestamp-entity';

@model()
export class AuditActions extends TimestampEntity {
  @property({
    type: 'string',
    required: true,
  })
  action: string;

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

  constructor(data?: Partial<AuditActions>) {
    super(data);
  }
}

export interface AuditActionsRelations {
  // describe navigational properties here
}

export type AuditActionsWithRelations = AuditActions & AuditActionsRelations;
