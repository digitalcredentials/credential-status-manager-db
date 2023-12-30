import { buildApp } from './app';
import { getLogger } from './util';

const port = process.env.PORT;

// runs app
const runApp = async () => {
  // create logger
  const logger = getLogger();

  // build app
  const app = await buildApp();

  // start app
  const server = app.listen(port, () => {
    const address = server.address();
    const location = typeof address === 'string' ? address : `http://${address?.address}:${address?.port}`;
    logger.info(`status-credential-site is running at ${location}`);
  });
};

runApp();
