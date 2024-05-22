declare namespace NodeJS{
    export interface ProcessEnv{
        DATABASE_URL:string;
        JWT_SECRETKEY:string;
        JWT_REFRESH_TOKEN:string;
    }
}