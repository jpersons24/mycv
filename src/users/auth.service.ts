import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';
import { UsersService } from './users.service';

// scrypt is an async function
const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async signup(email: string, password: string) {
    // see if email is in use
    const users = await this.usersService.find(email);
    if (users.length) {
      throw new BadRequestException('Email already in use, please choose another.')
    }

    // hash the users password
    // generate a salt
    const salt = randomBytes(8).toString('hex');
    // hash salt and password together
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    // joing hashed result and salt together
    const result = salt + '.' + hash.toString('hex');

    // create a new user and save it
    const user = await this.usersService.create(email, result);
    // return user
    return user;
  }

  async signin(email: string, plainTextPassword: string) {
    // find user by id
    const [user] = await this.usersService.find(email);
    // if user is not found throw an error
    if(!user) {
      throw new NotFoundException('User not found, please try again.');
    }

    // extract salt and hash from USER password
    const [salt, storedHash] = user.password.split('.');
    // create new hash using plain text password
    const hash = (await scrypt(plainTextPassword, salt, 32)) as Buffer;

    // compare hashes
    if(storedHash !== hash.toString('hex')) {
      throw new BadRequestException('Incorrect password!')
    }

    return user
  }
}