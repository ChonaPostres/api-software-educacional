import {
  SchemaObject
} from '@loopback/rest';

export const UserProfileSchema = {
  type: 'object',
  required: ['id'],
  properties: {
    id: {type: 'string'},
    email: {type: 'string'},
    name: {type: 'string'},
  },
};

// TODO(jannyHou): This is a workaround to manually
// describe the request body of 'Users/login'.
// We should either create a Credential model, or
// infer the spec from User model

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: {
      type: 'string'
    },
    password: {
      type: 'string'
    },
  },
};
const RegisterSchema: SchemaObject = {
  type: 'object',
  required: ['nickname', 'email', 'name', 'lastName', 'role', 'password'],
  properties: {
    nickname: {
      type: 'string'
    },
    email: {
      type: 'string'
    },
    name: {
      type: 'string'
    },
    lastName: {
      type: 'string'
    },
    role: {
      type: 'string'
    },
    password: {
      type: 'string'
    },
  },
}

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': {schema: CredentialsSchema},
  },
};

export const RegisterRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': {schema: RegisterSchema},
  },
};
