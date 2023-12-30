import winston from 'winston';

let LOGGER: winston.Logger;

// formats log message
export const formatLogMessage = (payload: any, prefix?: string) => {
  let message = `[${prefix}] ` || ''; 
  if (payload instanceof Error) {
    message += `${payload.name}: ${payload.message}\n${payload.stack}`;
  } else {
    message += JSON.stringify(payload, undefined, 2); 
  }
  return message;
};

// creates or retrieves logger
export const getLogger = (): winston.Logger => {
  if (!LOGGER) {
    LOGGER = winston.createLogger({
      transports: [new winston.transports.Console()],
      exitOnError: false
    }); 
  }
  return LOGGER;
};

export const env = {
  DB_SERVICE: process.env.DB_SERVICE as string,
  DB_NAME: process.env.DB_NAME as string,
  DB_URL: process.env.DB_URL as string,
  DB_STATUS_CREDENTIAL_TABLE: process.env.DB_STATUS_CREDENTIAL_TABLE as string
};
