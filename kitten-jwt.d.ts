

declare module 'kitten-jwt'{

    export type  params = {
        // client cache size used by getToken
        clientCacheSize : number,
        // how many time before expiration do we renew the token in millisecond
        clientRenewTokenBeforeExp : number,
        // default expiration of token in seconds
        clientTokenExpiration : number,
        // server cache size used by verifyHTTPHeaderFn
        serverCacheSize : number,
        // Invalidate bad token cache after XX milliseconds when the error is coming from getPublicKey
        serverGetPublicKeyErrorCacheExpiration : number
    };
    export function set (options:Partial<params> ):void;
    export function verify(jwt:string, publicKey:string, callback:(err:function, parsedPayload:any)=>void, now?:number):void
    export function verifyHTTPHeaderFn (serverId:number|string, getPublicKeyFn:string):RequestHandler 
    export function generate(
        clientId:number|string, 
        serverId:number|string, 
        expiresIn:number, 
        privKey:string, 
        data:any):string
       
    export function getToken (
        clientId:number|string, 
        serverId:number|string, 
        privKey:string|unknown, 
        data:any
        ):string
    export function resetCache():void
    export function generateECDHKeys(
        outputDir:string, 
        outputKeyName:string, 
        callback:   (err:any, stderr:any, stdout:any)=>void
        ):void 
    
        
    export function parseCookie(cookie:string):string|null
  }

