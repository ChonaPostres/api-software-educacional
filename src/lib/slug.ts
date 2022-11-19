/**
 * File: slug.ts
 * Project: nuevo-dercomaq-api
 * File Created: Thursday, 28th February 2019 11:37:47 am
 * Author: Felipe Rojos Almuna (felipe@inventures.cl)
 * -----
 * Last Modified: Thursday, 28th February 2019 3:10:27 pm
 * Modified By: Felipe Rojos Almuna (felipe@inventures.cl)
 * -----
 * Copyright 2019 - 2019 Incrementa Ventures SpA. ALL RIGHTS RESERVED
 * Terms and conditions defined in license.txt
 * -----
 * Inventures - www.inventures.cl
 */
 const getSlug = require('speakingurl');
 /**
  * Create a slug from an array of human-readable strings with a number if the created slug was already in use.
  * @param strings Human readable strings for better slug
  * @param id Optional integer for repeated slug
  * @returns Slug string
  */
 export function GenerateSlug(strings: string[], id?: number): string {
   if (id) {
     return getSlug(strings.join(' ') + ' ' + id.toString());
   }
   return getSlug(strings.join(' '));
 }
 