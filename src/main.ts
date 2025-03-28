import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FormatResponseInterceptor } from './format-response.interceptor';
import { InvokeRecordInterceptor } from './invoke-record.interceptor';
import { UnloginFilter } from './unlogin.filter';
import { CustomExceptionFilter } from './custom-exception.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.useGlobalPipes(new ValidationPipe()); //全局启用 ValidationPipe  来对请求体做校验。
  app.useGlobalInterceptors(new FormatResponseInterceptor()); //全局启用 FormatResponseInterceptor 来对响应体做格式化。
  app.useGlobalInterceptors(new InvokeRecordInterceptor()); //全局启用 InvokeRecordInterceptor 来记录请求信息。
  app.useGlobalFilters(new UnloginFilter()); //全局启用 UnloginFilter 来处理未登录异常。
  app.useGlobalFilters(new CustomExceptionFilter()); //全局启用 CustomExceptionFilter 来处理自定义异常。
  app.useStaticAssets('uploads', {
    prefix: '/uploads',
  }); // 配置静态文件目录

  const config = new DocumentBuilder()
    .setTitle('会议室预订系统')
    .setDescription('api 接口文档')
    .setVersion('1.0')
    .addBearerAuth({
      type: 'http',
      description: '基于 jwt 的认证',
    })
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  const configService = app.get(ConfigService);
  await app.listen(configService.get('nest_server_port') ?? 3000);
}
bootstrap();
