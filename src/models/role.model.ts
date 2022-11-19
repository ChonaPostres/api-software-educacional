import {model, property} from '@loopback/repository';
import {SlugEntityTitle} from '../lib/slug-entity-title';

@model()
export class Role extends SlugEntityTitle {
  @property({
    type: 'string',
    id: true,
  })
  id: string;

  @property({
    type: 'string',
  })
  description?: string;

  @property({
    type: 'string',
  })
  createdBy?: string;

  @property({
    type: 'number',
    required: true,
  })
  status?: number;

  @property.array(String)
  privilege: string[];

  constructor(data?: Partial<Role>) {
    super(data);
  }
}

