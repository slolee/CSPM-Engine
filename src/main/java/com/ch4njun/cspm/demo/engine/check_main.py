import sys
from Common.data import low_data
from Common.db_profile import *
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
import boto3
from Common.client import *

# IAM : 100
# VPC : 200
# CloudTrail : 300
# EC2 : 400
# RDS : 500
# S3 : 600
# EBS : 700

if __name__ == '__main__':
    arguments = sys.argv
    del arguments[0]

    low_data.set_diagnosis_id(arguments[0])
    del arguments[0]

    if 'IAM' in arguments:
        print('====== IAM 진단 시작 ======')
        iam = IAM()
        iam.audit_all()
        print('====== IAM 진단 종료 ======')
    if 'VPC' in arguments:
        print('====== VPC 진단 시작 ======')
        vpc = VPC()
        vpc.audit_all()
        print('====== VPC 진단 종료 ======')
    if 'CloudTrail' in arguments:
        print('====== CloudTrail 진단 시작 ======')
        cloudtrail = CloudTrail()
        cloudtrail.audit_all()
        print('====== CloudTrail 진단 종료 ======')
    if 'CloudWatch' in arguments:
        print('====== CloudWatch 진단 시작 ======')
        cloudwatch = CloudWatch()
        cloudwatch.audit_all()
        print('====== CloudWatch 진단 종료 ======')
    if 'EC2' in arguments:
        print('====== EC2 진단 시작 ======')
        ec2 = EC2()
        ec2.audit_all()
        print('====== EC2 진단 종료 ======')
    if 'RDS' in arguments:
        print('====== RDS 진단 시작 ======')
        rds = RDS()
        rds.audit_all()
        print('====== RDS 진단 종료 ======')
    if 'S3' in arguments:
        print('====== S3 진단 시작 ======')
        s3 = S3()
        s3.audit_all()
        print('====== S3 진단 종료 ======')
    if 'EBS' in arguments:
        print('====== EBS 진단 시작 ======')
        ebs = EBS()
        ebs.audit_all()
        print('====== EBS 진단 종료 ======')
    if 'CloudFront' in arguments:
        print('====== CloudFront 진단 시작 ======')
        cloudfront = CloudFront()
        cloudfront.audit_all()
        print('====== CloudFront 진단 종료 ======')
    if 'KMS' in arguments:
        print('====== KMS 진단 시작 ======')
        kms = KMS()
        kms.audit_all()
        print('====== KMS 진단 종료 ======')
    if 'Lambda' in arguments:
        print('====== Lambda 진단 시작 ======')
        myLambda = Lambda()
        myLambda.audit_all()
        print('====== Lambda 진단 종료 ======')