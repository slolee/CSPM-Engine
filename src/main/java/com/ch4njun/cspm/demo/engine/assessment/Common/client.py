import boto3

class Client:
    def __init__(self):
        self.iam_client = None
        self.ec2_client = None
        self.autoscaling_client = None
        self.elb_client = None
        self.elbv2_client = None
        self.cloudtrail_client = None
        self.cloudfront_client = None
        self.cloudwatch_client = None
        self.logs_client = None
        self.s3_client = None
        self.rds_client = None
        self.sts_client = None
        self.organizations_client = None
        self.kms_client = None
        self.lambda_client = None
        self.secretsmanager_client = None
        self.backup_client = None

        self.AWS_CURRENT_ID = None

    def init_client(self, access_key, secret_key, region_name):
        self.iam_client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.ec2_client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.autoscaling_client = boto3.client('autoscaling', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.elb_client = boto3.client('elb', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.elbv2_client = boto3.client('elbv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.cloudfront_client = boto3.client('cloudfront', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.cloudwatch_client = boto3.client('cloudwatch', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.logs_client = boto3.client('logs', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.rds_client = boto3.client('rds', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                         region_name=region_name)
        self.sts_client = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.organizations_client = boto3.client('organizations', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        self.kms_client = boto3.client('kms', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.lambda_client = boto3.client('lambda', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.secretsmanager_client = boto3.client('secretsmanager', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)
        self.backup_client = boto3.client('backup', aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                  region_name=region_name)

        self.AWS_CURRENT_ID = self.sts_client.get_caller_identity()

client = Client()

