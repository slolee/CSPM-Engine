import sys
from iam import *
from vpc import *
from cloudtrail import *
from cloudwatch import *
from ec2 import *
from rds import *
from s3 import *
from ebs import *
from cloudfront import *
from kms import *
from myLambda import *

if __name__ == '__main__':
    arguments = sys.argv

    print('[*] Assessment Start')
    client.init_client(arguments[2], arguments[3], arguments[4])
    execute_insert_history_sql((arguments[1], "running"))
    commit()

    rows = execute_select_history_sql(arguments[1])
    low_data.init_diagnosis_id(rows[0][0])

    if 'IAM' in arguments[5]:
        print('[*] IAM Assessment Start')
        iam = IAM()
        iam.audit_all()
        print('[*] IAM Assessment End')
    if 'VPC' in arguments[5]:
        print('[*] VPC Assessment Start')
        vpc = VPC()
        vpc.audit_all()
        print('[*] VPC Assessment End')
    if 'CloudTrail' in arguments[5]:
        print('[*] CloudTrail Assessment Start')
        cloudtrail = CloudTrail()
        cloudtrail.audit_all()
        print('[*] CloudTrail Assessment End')
    if 'CloudWatch' in arguments[5]:
        print('[*] CloudWatch Assessment Start')
        cloudwatch = CloudWatch()
        cloudwatch.audit_all()
        print('[*] CloudWatch Assessment End')
    if 'EC2' in arguments[5]:
        print('[*] EC2 Assessment Start')
        ec2 = EC2()
        ec2.audit_all()
        print('[*] EC2 Assessment End')
    if 'RDS' in arguments[5]:
        print('[*] RDS Assessment Start')
        rds = RDS()
        rds.audit_all()
        print('[*] RDS Assessment End')
    if 'S3' in arguments[5]:
        print('[*] S3 Assessment Start')
        s3 = S3()
        s3.audit_all()
        print('[*] S3 Assessment End')
    if 'EBS' in arguments[5]:
        print('[*] EBS Assessment Start')
        ebs = EBS()
        ebs.audit_all()
        print('[*] EBS Assessment End')
    if 'CloudFront' in arguments[5]:
        print('[*] CloudFront Assessment Start')
        cloudfront = CloudFront()
        cloudfront.audit_all()
        print('[*] CloudFront Assessment End')
    if 'KMS' in arguments[5]:
        print('[*] KMS Assessment Start')
        kms = KMS()
        kms.audit_all()
        print('[*] KMS Assessment End')
    if 'Lambda' in arguments[5]:
        print('[*] Lambda Assessment Start')
        myLambda = Lambda()
        myLambda.audit_all()
        print('[*] Lambda Assessment End')

    commit()
    print('[*] Assessment End')