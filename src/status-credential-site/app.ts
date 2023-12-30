import cors from 'cors';
import express, { Express } from 'express';
import HttpStatus from 'http-status-codes';
import { getDatabaseClient } from './database';
import { formatLogMessage, getLogger } from './util';

// builds app
export const buildApp = async (): Promise<Express> => {
  // get logger
  const logger = getLogger();

  // build database client
  const databaseClient = getDatabaseClient();

  // configure express app
  const app = express();

  app.use(express.json());

  app.use(cors());

  app.use(express.urlencoded({ extended: false }));

  // Get status credential
  app.get('/:statusCredentialId', async (req, res) => {
    const statusCredentialId = req.params.statusCredentialId;
    let errorMessage;
    try {
      const statusCredential = await databaseClient.getStatusCredential(statusCredentialId);
      if (!statusCredential) {
        errorMessage = `Unable to find status credential with ID "${statusCredentialId}".`;
        logger.error(formatLogMessage({
          error: errorMessage
        }, `GET /${statusCredentialId}`));
        return res.status(HttpStatus.NOT_FOUND).send(errorMessage);
      }
      return res.status(HttpStatus.OK).json(statusCredential);
    } catch (error: any) {
      errorMessage = `Encountered internal server error while fetching status credential with ID "${statusCredentialId}".`;
      logger.error(formatLogMessage(error, `GET /${statusCredentialId}`));
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(errorMessage);
    }
  });

  return app;
};
