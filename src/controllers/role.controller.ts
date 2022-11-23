import {authenticate} from '@loopback/authentication';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where
} from '@loopback/repository';
import {
  del, get,
  getModelSchemaRef, param, post,




  put,
  HttpErrors,
  requestBody
} from '@loopback/rest';
import {Role} from '../models';
import {RoleRepository, UserRepository} from '../repositories';
import {SecurityBindings, securityId, UserProfile} from '@loopback/security';
import {inject} from '@loopback/core';


export class RoleController {
  constructor(
    @repository(RoleRepository)
    public roleRepository: RoleRepository,
    @repository(UserRepository)
    public userRepository: UserRepository
  ) { }

  @post('/roles', {
    responses: {
      '200': {
        description: 'Role model instance',
        content: {'application/json': {schema: getModelSchemaRef(Role)}},
      },
    },
  })
  @authenticate('jwt')
  async create(@inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Role, {
            title: 'NewRole',
            exclude: ['id'],
          }),
        },
      },
    })
    role: Omit<Role, 'id'>,
  ): Promise<Role> {
    const rut = currentUserProfile[securityId];
    role.createdBy = rut;
    return this.roleRepository.create(role);
  }

  @get('/roles/count', {
    responses: {
      '200': {
        description: 'Role model count',
        content: {'application/json': {schema: CountSchema}},
      },
    },
  })
  @authenticate('jwt')
  async count(
    @param.where(Role) where?: Where<Role>,
  ): Promise<Count> {
    return this.roleRepository.count(where);
  }

  @get('/roles', {
    responses: {
      '200': {
        description: 'Array of Role model instances',
        content: {
          'application/json': {
            schema: {
              type: 'array',
              items: getModelSchemaRef(Role, {includeRelations: true}),
            },
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async find(
    @param.filter(Role) filter?: Filter<Role>,
  ): Promise<Role[]> {
    return this.roleRepository.find(filter);
  }

  @put('/roles/{slug}', {
    responses: {
      '204': {
        description: 'Role PUT success',
      },
    },
  })
  @authenticate('jwt')
  async replaceById(
    @param.path.string('slug') slug: string,
    @requestBody() role: Role,
  ): Promise<void> {
    const roleTemp = await this.findSlugOrId(slug);
    roleTemp.description = role.description;
    roleTemp.title = role.title;
    roleTemp.status = role.status;
    roleTemp.privilege = role.privilege;
  await this.roleRepository.updateById(roleTemp.id, roleTemp);
    const roleNew = await this.roleRepository.findById(roleTemp.id);
    let users = await this.userRepository.find({ where : { role : slug}});
    for (let user of users){
      user.role = roleNew.slug;
      await this.userRepository.update(user);
    }
  }

  private async findSlugOrId(id: string): Promise<Role> {
    const role = await this.roleRepository.searchSlug(id);
    if (role.length > 0) return role[0];
    return await this.roleRepository.findById(id);
  }
}
