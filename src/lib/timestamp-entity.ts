/*
 * File: timestamp-entity.ts
 * Project: nuevodercomaq-api
 * File Created: Wednesday, 3rd April 2019 10:23:05 am
 * Author: Jurgen Heysen (jurgen@inventures.cl)
 * -----
 * Last Modified: Wednesday, 3rd April 2019 11:13:44 am
 * Modified By: Jurgen Heysen (jurgen@inventures.cl)
 * -----
 * Copyright 2019 - 2019 Incrementa Ventures SpA. ALL RIGHTS RESERVED
 * Terms and conditions defined in license.txt
 * -----
 * Inventures - www.inventures.cl
 */

import {Entity, property} from '@loopback/repository';

/*
 * Custom entity that adds createdAt and updatedAt properties to models
 */

export class TimestampEntity extends Entity {
  @property({
    type: 'date',
    default: () => new Date(),
  })
  createdAt?: Date;

  @property({
    type: 'date',
    default: () => new Date(),
  })
  updatedAt?: Date;
}
