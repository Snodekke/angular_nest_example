import { Reflector } from '@nestjs/core';

export const Rights = Reflector.createDecorator<string[]>();
