import { createParamDecorator, ExecutionContext, SetMetadata } from "@nestjs/common";

export const  RequireLogin = () => SetMetadata('require-login', true);

export const  RequirePermission = (...permissions: string[]) => SetMetadata('require-permission', permissions);

export const UserInfo = createParamDecorator((data:string,ctx:ExecutionContext)=>{
  const request = ctx.switchToHttp().getRequest<Request>()
  //@ts-ignore
  if(!request.user){
    return null
  }
  //@ts-ignore
  return data?request.user[data]:request.user
})