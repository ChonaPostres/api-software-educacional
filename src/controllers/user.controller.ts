import {
  authenticate, TokenService,
  UserService
} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {
  Filter,
  repository,
  CountSchema,
  Count,
  Where
} from '@loopback/repository';
import {
  get,
  getModelSchemaRef,
  del,


  HttpErrors, param,
  post,
  put,
  requestBody
} from '@loopback/rest';
import {SecurityBindings, securityId, UserProfile} from '@loopback/security';
import {promisify} from 'util';
import { PasswordHasherBindings, TokenServiceBindings,

  UserServiceBindings
} from '../keys';
import {Role, User, UserCredentials} from '../models';
import {AuditActionsRepository, AuditAuthenticationRepository, Credentials, RecoverPasswordRepository, UserRepository, RoleRepository, RegisterCredentials, UserCredentialsRepository} from '../repositories';
import {PasswordHasher} from '../services/hash.password.bcryptjs';
import {registerAuditAction, registerAuditAuth} from '../services/validator';
import {
  CredentialsRequestBody, RegisterRequestBody
} from './specs/user-controller.specs';

const jwt = require('jsonwebtoken');

export type IsLoggedIn = {
  valid: Boolean;
  profile: User;
};


export class UserController {
  constructor(
    @repository(RecoverPasswordRepository) public recoverPasswordRepository: RecoverPasswordRepository,
    @repository(UserRepository) public userRepository: UserRepository,
    @repository(AuditAuthenticationRepository) public auditAuthenticationRepository: AuditAuthenticationRepository,
    @repository(AuditActionsRepository) public auditActionsRepository: AuditActionsRepository,
    @repository(RoleRepository) public roleRepository: RoleRepository,
    @repository(UserCredentialsRepository) public userCredentialsRepository: UserCredentialsRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHasher: PasswordHasher,
    @inject(TokenServiceBindings.TOKEN_SERVICE) public jwtService: TokenService,
    @inject(TokenServiceBindings.TOKEN_EXPIRES_IN) private jwtExpiresIn: string,
    @inject(TokenServiceBindings.TOKEN_SECRET) private jwtSecret: string,
    @inject(UserServiceBindings.USER_SERVICE) public userService: UserService<User, Credentials>
  ) { }

  @post('/users', {
    responses: {
      '200': {
        description: 'User model instance',
        content: {'application/json': {schema: getModelSchemaRef(User)}},
      },
    },
  })
  @authenticate('jwt')
  async create(@inject(SecurityBindings.USER)
  currentUserProfile: UserProfile,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(User, {
            title: 'NewUser',

          }),
        },
      },
    })
    user: User,
  ): Promise<User> {
    const email = currentUserProfile[securityId];
    user.status = 0;
    user.failedAttempts = 0;
    const created =  await this.userRepository.create(user);
    return created;
  }

  @get('/users', {
    responses: {
      '200': {
        description: 'Array of User model instances',
        content: {
          'application/json': {
            schema: {
              type: 'array',
              items: getModelSchemaRef(User, {includeRelations: false}),
            },
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async find(
    @param.filter(User) filter?: Filter<User>,
  ): Promise<User[]> {
    return this.userRepository.find(filter);
  }

  @get('/users/{email}', {
    responses: {
      '200': {
        description: 'User model instance',
        content: {
          'application/json': {
            schema: getModelSchemaRef(User, {includeRelations: true}),
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async findById(
    @param.path.string('email') email: string) : Promise<User> {
    const users = await this.userRepository.find({ where : { email : email}});
    return users[0];
  }

  @put('/users/{email}', {
    responses: {
      '204': {
        description: 'User PUT success',
      },
    },
  })
  @authenticate('jwt')
  async replaceById(
    @param.path.string('email') email: string,
    @requestBody() user: User,
  ): Promise<void> {
    const users = await this.userRepository.find({ where : { email : email}});
    users[0].name = user.name;
    users[0].lastName = user.lastName;
    users[0].email = user.email;
    users[0].role = user.role;
    users[0].status = user.status;
    await this.userRepository.updateById(users[0].id, users[0]);
  }

  @get('/users/current', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async current(@inject(SecurityBindings.USER) currentUserProfile: UserProfile): Promise<Object> {
    const email = currentUserProfile[securityId];
    var user = await this.userRepository.findOne({where: {email: email}});
    if (user){
      const role = await this.findRoleSlugOrId(user.role);

      return {
        email: user.email,
        name: user.name + " " + user.lastName,
        role: {
          slug: role.slug,
          name: role.title
        },
        privilege: role.privilege      
      };
    }
    throw new HttpErrors.Unauthorized("Usuario no registrado, favor contacte al administrador");    
  }

  @post('/users/authentication', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async authentication(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<Object> {

    var user = await this.userRepository.findOne({where: {email: credentials.email}});
    if (user){
      const role = await this.findRoleSlugOrId(user.role);
      const verifyUser = await this.userService.verifyCredentials(credentials);
      const userProfile = this.userService.convertToUserProfile(verifyUser);
      const token = await this.jwtService.generateToken(userProfile);
      await this.auditAuthenticationRepository.create(registerAuditAuth(verifyUser.id, 1));
      return {
        nickname: user.nickname,
        name: user.name + " " + user.lastName,
        email: user.email,
        role: {
          slug: role.slug,
          name: role.title
        },
        token: token
      };
    }
    throw new HttpErrors.Unauthorized("Usuario no registrado, favor contacte al administrador");    
  }
  @post('/users/regist', {
    responses: {
      '200': {
        description: 'NewUser',
      },
    },
  })
  //@authenticate('jwt')
  async regist(
    //user: User,
    @requestBody(RegisterRequestBody) credentials: RegisterCredentials,
  ): Promise<any> {
    try {
      const users = await this.userRepository.find( { where : { email : credentials.email }});
      if (users.length == 0) {
        const previousCredentials = await this.userCredentialsRepository.find({where: {userId: credentials.email}});
        if (previousCredentials.length > 0) {
          await this.userCredentialsRepository.deleteById(previousCredentials[0].id);
        }
        // encrypt the password
        const password = await this.passwordHasher.hashPassword(
          credentials.password,
        );
        // Crear user
        var user = new User;
        var userCredentials = new UserCredentials;
        user.email = credentials.email;
        user.nickname = credentials.nickname;
        user.name = credentials.name;
        user.lastName = credentials.lastName;
        user.role = credentials.role;
        user.failedAttempts = 0;
        user.status = 1;
        var newUser = await this.userRepository.create(user);
        // Crear credenciales de user
        userCredentials.userId = newUser.email;
        userCredentials.password = password;
        var newUserCredentials = await this.userCredentialsRepository.create(userCredentials);
        // Registro de creacion de usuario y credenciales
        await this.auditActionsRepository.create(registerAuditAction(newUser.id, "Creacion de Usuario y credenciales"));
        return true;
      } else {
        throw new HttpErrors.Conflict('errors.unathorized');
      }
    } catch (ex) {
      console.log(ex);
      throw new HttpErrors.Conflict('sign-in.dntexist');
    }
    
  }

  @get('/users/logged-in', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': Boolean,
            },
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async isLoggedIn(@inject(SecurityBindings.USER)
  currentUserProfile: UserProfile,
  ): Promise<Boolean> {

    try {
      const email = currentUserProfile[securityId];
      var user = await this.userRepository.findOne({where: {email: email}});
      if (user) {
        return true;
      } 
      throw new HttpErrors.Unauthorized();
    } catch (ex) {
      console.log(ex);
      throw new HttpErrors.Unauthorized();
    }

  }

  @get('/users/count', {
    responses: {
      '200': {
        description: 'Region model count',
        content: {'application/json': {schema: CountSchema}},
      },
    },
  })
  @authenticate('jwt')
  async count(
    @param.filter(User) filter?: Filter<User>,
  ): Promise<Number> {
    const users = await this.userRepository.find(filter);
    return users.length;
  }

  @del('/users/{email}', {
    responses: {
      '204': {
        description: 'User DELETE success',
      },
    },
  })
  @authenticate('jwt')
  async deleteById(@param.path.string('email') email: string): Promise<void> {
    const users = await this.userRepository.find({ where : { email : email}});
    await this.userRepository.deleteById(users[0].id);
  }

  private async findRoleSlugOrId(id: string): Promise<Role> {
    const role = await this.roleRepository.searchSlug(id);
    if (role.length > 0) return role[0];
    return await this.roleRepository.findById(id);
  }
}