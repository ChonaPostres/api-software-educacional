/**
 * File: slug-repository.ts
 * Project: nuevo-dercomaq-api
 * File Created: Thursday, 28th February 2019 11:44:07 am
 * Author: Felipe Rojos Almuna (felipe@inventures.cl)
 * -----
 * Last Modified: Friday, 17th May 2019 1:09:28 pm
 * Modified By: Felipe Rojos Almuna (felipe@inventures.cl)
 * -----
 * Copyright 2019 - 2019 Incrementa Ventures SpA. ALL RIGHTS RESERVED
 * Terms and conditions defined in license.txt
 * -----
 * Inventures - www.inventures.cl
 */
 import {DataObject, Filter, Options} from '@loopback/repository';
 import {GenerateSlug} from './slug';
 import {TimestampRepository} from './timestamp-repository';
 import {SlugEntityTitle} from './slug-entity-title';
 /**
  * Custom repository that create slug before creation and before update an entity.
  */
 export class SlugRepositoryTitle<
   T extends SlugEntityTitle,
   ID
 > extends TimestampRepository<T, ID> {
   async create(entity: DataObject<T>, options?: Options): Promise<T> {
     const slug = await this.finalSlug(entity);
     entity.slug = slug;
     return super.create(entity, options);
   }
   /**
    * Override function. Recalculate slug
    * @param entity New data
    * @param options Other options
    * @returns Void
    */
   update(entity: T, options?: Options): Promise<void> {
     return this.finalSlug(entity).then(slug => {
       entity.slug = slug;
       return super.update(entity, options);
     });
   }
   /**
    * Override Function. Update slag for a specific entity
    * @param id Entity Identifier
    * @param data Data to update
    * @param options Other Option
    * @returns Void
    */
   async updateById(
     id: ID,
     data: DataObject<T>,
     options?: Options,
   ): Promise<void> {
     const slug = await this.finalSlug(data, 0, id);
     data.slug = slug;
     return super.updateById(id, data, options);
   }
   /**
    * Create a filter and search with the given slug
    * @param slug Slug to search
    * @returns A promise that returns an array of entities found
    */
   // async searchSlug(slug: string) {
   //   const filter = {
   //     where: {
   //       slug: slug,
   //     },
   //   } as Filter<T>;
   //   return super.find(filter);
   // }
 
   /**
    * Create a filter and search with the given slug
    * @param slug Slug to search
    * @param id The entity id
    * @returns A promise that returns an array of entities found
    */
   async searchSlug(slug: string, id?: ID) {
     const filter = {
       where: {
         slug: slug,
         id: {
           nin: [id],
         },
       },
     } as Filter<T>;
     return super.find(filter);
   }
   /**
    * Recursive Promise that returns a unique slug
    * @param entity Entity data. It throw an error if does not exist almost a name or a
    * @param i
    * @param id
    * @returns A unique slug
    */
   async finalSlug(entity: DataObject<T>, i = 0, id?: ID): Promise<string> {
     const titleType = typeof entity.title === 'string';
     if (!titleType) {
       if (!id) {
         throw new Error('Please give a title');
       } else {
         const instance = await super.findById(id);
         return instance.slug;
       }
     }
     let title: string = '';
     if (typeof entity.title === 'string') title = entity.title;
     //if (typeof entity.brand === 'string') brand = entity.brand;
     if (id) {
       const instance = await super.findById(id);
       if (!titleType) title = instance.title;
     }
     const slugArr = title.split(' ');
     let slug;
     i > 0 ? (slug = GenerateSlug(slugArr, i)) : (slug = GenerateSlug(slugArr));
     const result = await this.searchSlug(slug, id);
     if (result.length > 0) return this.finalSlug(entity, i + 1, id);
     return slug;
   }
 }
 