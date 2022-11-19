/*
 * File: timestamp-repository.ts
 * Project: nuevodercomaq-api
 * File Created: Wednesday, 3rd April 2019 10:36:16 am
 * Author: Jurgen Heysen (jurgen@inventures.cl)
 * -----
 * Last Modified: Wednesday, 3rd April 2019 10:50:22 am
 * Modified By: Jurgen Heysen (jurgen@inventures.cl)
 * -----
 * Copyright 2019 - 2019 Incrementa Ventures SpA. ALL RIGHTS RESERVED
 * Terms and conditions defined in license.txt
 * -----
 * Inventures - www.inventures.cl
 */

import {DefaultCrudRepository, DataObject, Options} from '@loopback/repository';
import {TimestampEntity} from './timestamp-entity';

export class TimestampRepository<
  T extends TimestampEntity,
  ID
> extends DefaultCrudRepository<T, ID> {
  /**
   * Create a new Entity in DataStore
   * @param entity Data from request to create Entity
   * @param options Options for Default CRUD repo
   * @returns Created entity
   */
  async create(entity: DataObject<T>, options?: Options): Promise<T> {
    const now = new Date();
    entity.createdAt = now;
    entity.updatedAt = now;
    return super.create(entity, options);
  }

  /**
   * Update an existing entity
   * @param entity Entity to update
   * @param options Options to Default CRUD Repo
   * @returns void
   */
  async update(entity: T, options?: Options): Promise<void> {
    entity.updatedAt = new Date();
    return super.update(entity, options);
  }

  /**
   * Update an entity in the datastore given its ID
   * @param id ID of entity to update in DataStore
   * @param data Data from request for updating object
   * @param options Options to default CRUD repo
   * @returns void
   */
  async updateById(
    id: ID,
    data: DataObject<T>,
    options?: Options,
  ): Promise<void> {
    data.updatedAt = new Date();
    return super.updateById(id, data, options);
  }
}
