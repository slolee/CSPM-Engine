from Common.data import low_data
from Common.client import *
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class EBS:
    def __init__(self):
        low_data.load_ebs_low_data()

    def audit_all(self):
        self.ebs_001()
        self.ebs_002()
        self.ebs_003()
        self.ebs_004()
        self.ebs_005()
        self.ebs_006()
        self.ebs_007()

    def ebs_001(self):
        print('[EBS_001] EBS 볼륨 스냅샷이 퍼블릭으로 설정되어 있는지 확인하시오.')
        for snapshot in low_data.snapshots:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            describe_snapshot_attribute = client.ec2_client.describe_snapshot_attribute(SnapshotId=snapshot['SnapshotId'], Attribute='createVolumePermission')
            snapshot_create_volume_permission = describe_snapshot_attribute['CreateVolumePermissions']

            append_data(data, 'aws ec2 describe-snapshot-attribute --snapshot-id ' + snapshot['SnapshotId'] + ' --attribute createVolumePermission',
                        {'CreateVolumePermissions': describe_snapshot_attribute['CreateVolumePermissions'], 'SnapshotId': describe_snapshot_attribute['SnapshotId']})
            if {'Group': 'all'} in snapshot_create_volume_permission:
                append_summary(data, snapshot['SnapshotId'] + ' 스냅샷이 퍼블릭으로 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, snapshot['SnapshotId'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'EBS', '001', snapshot['SnapshotId'], snapshot['SnapshotId'], check, str(data)))
        print()

    def ebs_002(self):
        print('[EBS_002] 연결되지 않은 EBS 볼륨이 존재하는지 확인하시오.')
        for volume in low_data.volumes:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws ec2 describe-volumes --filter Name=volume-id,Values=' + volume['VolumeId'] + ' --query \"Volumes[*].{VolumeId:VolumeId, State:State}\"',
                        {'VolumeId': volume['VolumeId'], 'State': volume['State']})
            if volume['State'] != 'in-use':
                append_summary(data, volume['VolumeId'] + ' 볼륨이 연결되지 않은 ' + volume['State'] + ' 상태입니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, volume['VolumeId'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'EBS', '002', volume['VolumeId'], volume['VolumeId'], check, str(data)))
        print()

    def ebs_003(self):
        print('[EBS_003] EBS 볼륨이 최대 7일마다 스냅샷을 생성하도록 설정되어 있는지 확인하시오.')
        print()

    def ebs_004(self):
        print('[EBS_004] EBS 볼륨의 암호화 설정이 활성화되어 있는지 확인하시오.')
        for volume in low_data.volumes:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws ec2 describe-volumes --filter Name=volume-id,Values=' + volume['VolumeId'] + ' --query \"Volumes[*].{VolumeId:VolumeId, Encrypted:Encrypted}\"',
                        {'VolumeId': volume['VolumeId'], 'Encrypted': volume['Encrypted']})
            if not volume['Encrypted']:
                append_summary(data, volume['VolumeId'] + ' 볼륨의 암호화 설정이 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, volume['VolumeId'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'EBS', '004', volume['VolumeId'], volume['VolumeId'], check, str(data)))
        print()

    def ebs_005(self):
        print('[EBS_005] EBS 볼륨이 KMS 고객 관리형 키(CMK)로 암호화되었는지 확인하시오.')
        for volume in low_data.volumes:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws ec2 describe-volumes --filter Name=volume-id,Values=' + volume['VolumeId'] + ' --query \"Volumes[*].{VolumeId:VolumeId, KmsKeyId:KmsKeyId}\"',
                        {'VolumeId': volume['VolumeId'], 'KmsKeyId': (volume['KmsKeyId'] if 'KmsKeyId' in volume else 'null')})
            if 'KmsKeyId' not in volume:
                append_summary(data, volume['VolumeId'] + ' 볼륨이 KMS 고객 관리형 키(CMK)로 암호화되지 않습니다.')
            else:
                aliases = [alias for alias in low_data.aliases if alias['TargetKeyId'] == volume['KmsKeyId']]
                if [alias for alias in aliases if alias['AliasName'] == 'alias/aws/ebs']:
                    append_summary(data, volume['VolumeId'] + ' 볼륨이 KMS 고객 관리형 키(CMK)로 암호화되지만 AWS에서 제공하는 KMS 고객 관리형 키를 사용합니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, volume['VolumeId'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'EBS', '005', volume['VolumeId'], volume['VolumeId'], check, str(data)))
        print()

    def ebs_006(self):
        print('[EBS_006] EBS 스냅샷이 암호화되었는지 확인하시오.')
        for snapshot in low_data.snapshots:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws ec2 describe-snapshots --owner-ids ' + client.AWS_CURRENT_ID['Account'] + ' --filter Name=snapshot-id,Values=' + snapshot['SnapshotId'] +\
                        ' --query \"Snapshots[*].{SnapshotId:SnapshotId, Description:Description, Encrypted:Encrypted}\"',
                        {'SnapshotId': snapshot['SnapshotId'], 'Description': snapshot['Description'], 'Encrypted': snapshot['Encrypted']})
            if not snapshot['Encrypted']:
                append_summary(data, snapshot['SnapshotId'] + ' 스냅샷이 암호화되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, snapshot['SnapshotId'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'EBS', '006', snapshot['SnapshotId'], snapshot['SnapshotId'], check, str(data)))
        print()

    def ebs_007(self):
        print('[EBS_007] EBS 볼륨 설정에서 "새 EBS 볼륨을 항상 암호화"가 활성화되어 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        if low_data.ebs_encryption_by_default == 'Error':
            append_data(data, 'aws ec2 get-ebs-encryption-by-default',
                        {'Error': 'An error occurred (UnauthorizedOperation) when calling the GetEbsEncryptionByDefault operation'})
            append_summary(data, '해당 항목을 확인하려면 \"GetEbsEncryptionByDefault\" 권한을 부여해야 합니다.')
            check = '?'
        else:
            append_data(data, 'aws ec2 get-ebs-encryption-by-default', {'EbsEncryptionByDefault': low_data.ebs_encryption_by_default})
            if not low_data.ebs_encryption_by_default:
                append_summary(data, 'EBS 볼륨 설정에 "새 EBS 볼륨을 항상 암호화"가 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
        print(check, data, "EBS", sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'EBS', '007', 'EBS', 'EBS', check, str(data)))
        print()


