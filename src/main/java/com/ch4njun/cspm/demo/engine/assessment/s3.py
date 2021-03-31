from Common.data import low_data
from Common.client import *
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class S3:
    def __init__(self):
        low_data.load_s3_low_data()

    def audit_all(self):
        self.s3_001()
        self.s3_002()
        self.s3_003()
        self.s3_004()
        self.s3_005()
        self.s3_006()
        self.s3_007()
        self.s3_008()
        self.s3_009()
        self.s3_010()
        self.s3_011()
        self.s3_012()

    def s3_001(self):
        print('[S3_001] S3 버킷에 대해 버킷 정책이 공개적으로 접근가능하지 않도록 설정하였는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            bucket_policy = json.loads(low_data.buckets_policy[bucket['Name']])
            append_data(data, 'aws s3api get-bucket-policy --bucket ' + bucket['Name'], {'Policy': bucket_policy})
            if [statement for statement in bucket_policy['Statement'] if statement['Effect'] == 'Allow' and statement['Principal'] in ['*', {'AWS': '*'}]]:
                append_summary(data, bucket['Name'] + ' 의 버킷 정책이 공개적으로 접근가능하도록 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '001', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_002(self):
        print('[S3_002] S3 버킷에 대해 인증된 사용자 그룹의 권한이 과도하게 부여되어 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-acl --bucket ' + bucket['Name'] + ' --query \"{Grants:Grants}\"', {'Grants': low_data.buckets_acl[bucket['Name']]})
            for grant in low_data.buckets_acl[bucket['Name']]:
                if grant['Grantee']['Type'] == 'Group' and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    if grant['Permission'] == 'FULL_CONTROL':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한이 \'FULL_CONTROL\'로 부여되어 있습니다.')
                    if grant['Permission'] == 'READ':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'READ\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'READ_ACP':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'READ_ACP\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'WRITE':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'WRITE\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'WRITE_ACP':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'WRITE_ACP\' 부여되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '002', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_003(self):
        print('[S3_003] S3 버킷에 대해 퍼블릭 사용자의 권한이 과도하게 부여되어 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-acl --bucket ' + bucket['Name'] + ' --query \"{Grants:Grants}\"', {'Grants': low_data.buckets_acl[bucket['Name']]})
            for grant in low_data.buckets_acl[bucket['Name']]:
                if grant['Grantee']['Type'] == 'Group' and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    if grant['Permission'] == 'FULL_CONTROL':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한이 \'FULL_CONTROL\'로 부여되어 있습니다.')
                    if grant['Permission'] == 'READ':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'READ\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'READ_ACP':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'READ_ACP\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'WRITE':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'WRITE\'가 부여되어 있습니다.')
                    if grant['Permission'] == 'WRITE_ACP':
                        append_summary(data, bucket['Name'] + ' 에 대해 인증된 사용자 그룹의 권한 \'WRITE_ACP\' 부여되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '003', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_004(self):
        print('[S3_004] S3 버킷에 대해 MFA Delete를 사용하고 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-versioning --bucket ' + bucket['Name'] + ' --query \"{MFADelete:MFADelete}\"',
                        {'MFADelete': low_data.buckets_versioning[bucket['Name']]['MFADelete'] if 'MFADelete' in low_data.buckets_versioning[bucket['Name']] else 'null'})
            if 'MFADelete' not in low_data.buckets_versioning[bucket['Name']]:
                append_summary(data, bucket['Name'] + ' 에 대한 MFA Delete가 사용되고있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '004', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_005(self):
        print('[S3_005] S3 버킷의 수명 주기 관리를 설정하였는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-lifecycle-configuration --bucket ' + bucket['Name'],
                        {'Rules': low_data.buckets_lifecycle_configuration[bucket['Name']]} if low_data.buckets_lifecycle_configuration[bucket['Name']]
                        else {'Error': 'An error occurred (NoSuchLifecycleConfiguration) when calling the GetBucketLifecycleConfiguration operation'})
            if not low_data.buckets_lifecycle_configuration[bucket['Name']]:
                append_summary(data, bucket['Name'] + ' 의 수명 주기 관리가 설정되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '005', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_006(self):
        print('[S3_006] S3 버킷의 객체에 대해 객체 잠금 관리를 설정하였는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-object-lock-configuration --bucket ' + bucket['Name'],
                        {'ObjectLockConfiguration': low_data.buckets_object_lock_configuration[bucket['Name']]} if low_data.buckets_object_lock_configuration[bucket['Name']]
                        else {'Error': 'An error occurred (ObjectLockConfigurationNotFoundError) when calling the GetObjectLockConfiguration operation'})
            if not low_data.buckets_object_lock_configuration[bucket['Name']]:
                append_summary(data, bucket['Name'] + ' 의 객체 잠금 관리가 설정되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '006', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_007(self):
        print('[S3_007] S3 버킷을 정적 웹사이트로 구성할 때 정적 웹 사이트 호스팅을 활성화 하였는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            try:
                get_bucket_website = client.s3_client.get_bucket_website(Bucket=bucket['Name'])
                append_data(data, 'aws s3api get-bucket-website --bucket' + bucket['Name'],
                            {'IndexDocument': get_bucket_website['IndexDocument']})
            except ClientError as e:
                append_data(data, 'aws s3api get-bucket-website --bucket ' + bucket['Name'],
                            {'Error': 'An error occurred (NoSuchWebsiteConfiguration) when calling the GetBucketWebsite operation'})
                append_summary(data, bucket['Name'] + ' 의 정적 웹 사이트 호스팅이 비활성화되어 있습니다.\n해당 버킷이 정적 웹사이트로 구성되어있는지 확인하시오.')
                check = '?'

            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '007', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_008(self):
        print('[S3_008] S3 버킷에 대해 버전 관리를 사용하고 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-versioning --bucket ' + bucket['Name'] + ' --query \"{Status:Status}\"',
                        {'Status': low_data.buckets_versioning[bucket['Name']]['Status'] if 'Status' in low_data.buckets_versioning[bucket['Name']] else 'null'})
            if 'Status' not in low_data.buckets_versioning[bucket['Name']] or low_data.buckets_versioning[bucket['Name']]['Status'] != 'Enabled':
                append_summary(data, bucket['Name'] + ' 이 버전 관리를 사용하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '008', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_009(self): # 서버 액세스 로깅이 A에서 B를 Target으로 삼고있다면, B에 대한 액세스 로깅이 A에 쌓이는건가 아니면 A에 대한 액세스 로깅이 B에 쌓이는건가.
                        # 이에 따라 코딩 수정 필요 지금은 후자로 짜여있음.
        print('[S3_009] S3 버킷에 대한 서버 엑세스 로깅를 수집하고 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-logging --bucket ' + bucket['Name'], {'LoggingEnabled': low_data.buckets_logging[bucket['Name']]})
            if not low_data.buckets_logging[bucket['Name']]:
                append_summary(data, bucket['Name'] + '에 대한 서버 액세스 로깅을 수집하고 있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '009', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_010(self):
        print('[S3_010] S3 버킷에 대해 기본 암호화를 사용하고 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-encryption --bucket ' + bucket['Name'],
                        {'ServerSideEncryptionConfiguration': {'Rules': low_data.buckets_encryption[bucket['Name']]}} if low_data.buckets_encryption[bucket['Name']] else
                        {'Error': 'An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption operation'})
            if not low_data.buckets_encryption[bucket['Name']]:
                append_summary(data, bucket['Name'] + ' 에 대한 기본 암호화가 사용되지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '010', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_011(self):
        print('[S3_011] S3 버킷에 KMS에 저장된 CMK(고객 마스터 키)를 사용한 서버 측 암호화로 데이터를 보호 하고 있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws s3api get-bucket-encryption --bucket ' + bucket['Name'],
                        {'ServerSideEncryptionConfiguration': {'Rules': low_data.buckets_encryption[bucket['Name']]}} if low_data.buckets_encryption[bucket['Name']] else
                        {'Error': 'An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption operation'})
            if not low_data.buckets_encryption[bucket['Name']]:
                append_summary(data, bucket['Name'] + ' 에 대한 기본 암호화가 사용되지 않습니다.')
            else:
                if not [bucket_encryption for bucket_encryption in low_data.buckets_encryption[bucket['Name']]
                        if bucket_encryption['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms']:
                    append_summary(data, bucket['Name'] + ' 의 기본 암호화에서 KMS 고객 관리형 키(CMK)로 암호화하지 않습니다.')
                elif [bucket_encryption for bucket_encryption in low_data.buckets_encryption[bucket['Name']]
                        if bucket_encryption['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'].endswith('alias/aws/s3')]:
                    append_summary(data, bucket['Name'] + ' 의 기본 암호화에서 KMS 고객 관리형 키(CMK)로 암호화되지만 AWS에서 제공하는 키를 사용합니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '011', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()

    def s3_012(self):
        print('[S3_012] 서버 기본 암호화가 활성화 되어있는지 확인하시오.')
        for bucket in low_data.buckets:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            bucket_policy = json.loads(low_data.buckets_policy[bucket['Name']])
            append_data(data, 'aws s3api get-bucket-policy --bucket ' + bucket['Name'], {'Policy': bucket_policy})
            if not [statement for statement in bucket_policy['Statement'] if 'Condition' in statement and 'Null' in statement['Condition']
                    and statement['Condition']['Null'] == {'s3:x-amz-server-side-encryption': 'true'}]:
                append_summary(data, bucket['Name'] + ' 의 서버 기본 암호화가 설정되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, bucket['Name'], data, sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'S3', '012', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], check, str(data)))
        print()


