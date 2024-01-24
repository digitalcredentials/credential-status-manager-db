import archiver from 'archiver';
import AWS from 'aws-sdk';
import fs from 'fs';
import { BadRequestError, InternalServerError } from './errors.js';
import { BaseStatusCredentialSiteDeployer, BaseStatusCredentialSiteDeployerOptions } from './status-credential-site-deployer-base.js';

const elasticbeanstalk = new AWS.ElasticBeanstalk();
const s3 = new AWS.S3();

// AWS regions
export enum AwsRegion {
  UsEast1 = 'us-east-1',
  UsEast2 = 'us-east-2',
  UsWest1 = 'us-west-1',
  UsWest2 = 'us-west-2',
  AfSouth1 = 'af-south-1',
  ApEast1 = 'ap-east-1',
  ApSouth1 = 'ap-south-1',
  ApSouth2 = 'ap-south-2',
  ApNortheast1 = 'ap-northeast-1',
  ApNortheast2 = 'ap-northeast-2',
  ApNortheast3 = 'ap-northeast-3',
  ApSoutheast1 = 'ap-southeast-1',
  ApSoutheast2 = 'ap-southeast-2',
  ApSoutheast3 = 'ap-southeast-3',
  ApSoutheast4 = 'ap-southeast-4',
  CaCentral1 = 'ca-central-1',
  CaWest1 = 'ca-west-1',
  EuNorth1 = 'eu-north-1',
  EuCentral1 = 'eu-central-1',
  EuCentral2 = 'eu-central-2',
  EuWest1 = 'eu-west-1',
  EuWest2 = 'eu-west-2',
  EuWest3 = 'eu-west-3',
  EuSouth1 = 'eu-south-1',
  EuSouth2 = 'eu-south-2',
  IlCentral1 = 'il-central-1',
  MeCentral1 = 'me-central-1',
  MeSouth1 = 'me-south-1',
  SaEast1 = 'sa-east-1',
  UsGovEast1 = 'us-gov-east-1',
  UsGovWest1 = 'us-gov-west-1'
}

type AwsStatusCredentialSiteDeployerOptions = {
  awsRegion: AwsRegion;
  awsElasticBeanstalkAppName: string;
  awsElasticBeanstalkEnvName: string;
  awsS3BucketName: string;
} & BaseStatusCredentialSiteDeployerOptions;

// Minimal set of options required for configuring BaseCredentialStatusManager
export const AWS_MANAGER_REQUIRED_OPTIONS: Array<keyof AwsStatusCredentialSiteDeployerOptions> = [
  'awsRegion',
  'awsElasticBeanstalkAppName',
  'awsElasticBeanstalkEnvName',
  'awsS3BucketName'
];

// Implementation of BaseStatusCredentialSiteDeployer for AWS
export class AwsStatusCredentialSiteDeployer extends BaseStatusCredentialSiteDeployer {
  private readonly baseOptions: BaseStatusCredentialSiteDeployerOptions;
  private readonly awsRegion: string;
  private readonly awsElasticBeanstalkAppName: string;
  private readonly awsElasticBeanstalkEnvName: string;
  private readonly awsS3BucketName: string;

  constructor(options: AwsStatusCredentialSiteDeployerOptions) {
    const {
      awsRegion,
      awsElasticBeanstalkAppName,
      awsElasticBeanstalkEnvName,
      awsS3BucketName,
      ...baseOptions
    } = options;
    super(baseOptions);
    this.baseOptions = baseOptions;
    this.awsRegion = awsRegion;
    this.awsElasticBeanstalkAppName = awsElasticBeanstalkAppName;
    this.awsElasticBeanstalkEnvName = awsElasticBeanstalkEnvName;
    this.awsS3BucketName = awsS3BucketName;
    this.validateConfiguration(options);
  }

  // ensures valid configuration of AWS site deployer
  validateConfiguration(options: AwsStatusCredentialSiteDeployerOptions): void {
    const missingOptions = [] as
      Array<keyof AwsStatusCredentialSiteDeployerOptions>;

    const isProperlyConfigured = AWS_MANAGER_REQUIRED_OPTIONS.every(
      (option: keyof AwsStatusCredentialSiteDeployerOptions) => {
        if (!options[option]) {
          missingOptions.push(option as any);
        }
        return !!options[option];
      }
    );

    if (!isProperlyConfigured) {
      throw new BadRequestError({
        message:
          'You have neglected to set the following required options for deploying a ' +
          `"${this.databaseService}" credential status manager to AWS: ` +
          `${missingOptions.map(o => `"${o}"`).join(', ')}.`
      });
    }
  }

  // runs deployment script for site hosting service and returns site URL
  async run(): Promise<string> {
    const baseOptionsStructured = Object.entries(this.baseOptions)
      .map(([k, v]) => {
        return {
          Namespace: 'aws:elasticbeanstalk:application:environment',
          OptionName: k,
          Value: v
        };
      });

    AWS.config.update({ region: this.awsRegion });

    const date = Date.now();
    const appVersion = `v${date}`;
    const appFileName = `app${date}.zip`;
    const output = fs.createWriteStream(appFileName);
    const archive = archiver('zip', { zlib: { level: 9 } });

    const basicAppParams = {
      ApplicationName: this.awsElasticBeanstalkAppName,
      EnvironmentName: this.awsElasticBeanstalkEnvName
    };

    let siteUrlPromise = new Promise<string>(() => {});

    output.on('close', async () => {
      const createBucketParams = {
        Bucket: this.awsS3BucketName,
        ACL: 'private'
      };

      await s3.createBucket(createBucketParams).promise();

      const createAppVersionParams = {
        ApplicationName: this.awsElasticBeanstalkAppName,
        AutoCreateApplication: true,
        SourceBundle: {
          S3Bucket: this.awsS3BucketName,
          S3Key: `app-versions/${appFileName}`
        },
        VersionLabel: appVersion,
        OptionSettings: baseOptionsStructured
      };

      await elasticbeanstalk.createApplicationVersion(createAppVersionParams).promise();

      const createEnvParams = {
        ...basicAppParams,
        SolutionStackName: 'Node.js'
      };

      await elasticbeanstalk.createEnvironment(createEnvParams).promise();

      const updateEnvParams = {
        ...basicAppParams,
        VersionLabel: createAppVersionParams.VersionLabel
      };

      await elasticbeanstalk.updateEnvironment(updateEnvParams).promise();

      siteUrlPromise = new Promise((resolve, reject) => {
        elasticbeanstalk.describeEnvironments(basicAppParams, (err, envs) => {
          if (envs.Environments &&
            envs.Environments.length > 0 &&
            typeof envs.Environments[0].EndpointURL === 'string'
          ) {
            const siteUrl = envs.Environments[0].EndpointURL;
            resolve(siteUrl);
          } else {
            throw new InternalServerError({ message: err.message });
          }
        });
      });
    });

    archive.pipe(output);
    archive.directory('./status-credential-site', false);
    archive.finalize();

    return siteUrlPromise;
  }
}
