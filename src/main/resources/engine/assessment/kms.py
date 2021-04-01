from common.client import *
from common.db import *
from common.utils import *
import json

class KMS:
    def __init__(self):
        low_data.load_kms_low_data()

    def audit_all(self):
        self.kms_001()
        self.kms_002()
        self.kms_003()
        self.kms_004()
        self.kms_005()
        self.kms_006()
        self.kms_007()

    def kms_001(self):
        try:
            print('[KMS_001] Amazon KMS 마스터 키가 모든 사람에게 노출되지 않는지 확인하시오.')
            for key in low_data.customer_keys_id:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                kms_policy = json.loads(low_data.key_policies[key])
                append_data(data, 'aws kms get-key-policy --key-id ' + key + ' --policy-name default', {'Policy': kms_policy})
                filtered_statements = [statement for statement in kms_policy['Statement'] if 'AWS' in statement['Principal'] and statement['Principal']['AWS'] == '*']
                for statement in filtered_statements:
                    if 'Condition' in statement:
                        if 'StringEquals' not in statement['Condition'] or 'kms:CallerAccount' not in statement['Condition']['StringEquals']:
                            append_summary(data, key + ' Amazon KMS 마스터 키가 모든 사람에게 노출되도록 구성되어 있습니다.')
                    else:
                        append_summary(data, key + ' Amazon KMS 마스터 키가 모든 사람에게 노출되도록 구성되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '001', key, low_data.keys[key]['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_002(self):
        try:
            print('[KMS_002] Amazon KMS 마스터 키가 알 수없는 교차 계정 액세스를 허용하지 않는지 확인하시오.')
            for key in low_data.customer_keys_id:
                check = '?'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                kms_policy = json.loads(low_data.key_policies[key])
                append_data(data, 'aws kms get-key-policy --key-id ' + key + ' --policy-name default', {'Policy': kms_policy})
                principals = [statement['Principal'] for statement in kms_policy['Statement']]
                append_summary(data, key + ' Amazon KMS 마스터 키의 정책에 허용된 계정목록은 ' + str(principals) + ' 입니다.\n해당 목록이 신뢰할 수 있는 계정인지 확인하시오.')

                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '002', key, low_data.keys[key]['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_003(self):
        try:
            print('[KMS_003] Amazon KMS 마스터 키가 삭제 예약되거나 비활성화되어 있는지 확인하시오.')
            for key in low_data.customer_keys_id:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                key_detail = low_data.keys[key]
                append_data(data, 'aws kms describe-key --key-id ' + key + ' --query \"KeyMetadata.{AWSAccountId:AWSAccountId, KeyId:KeyId, Arn:Arn, KeyState:KeyState}\"',
                            {'AWSAccountId': key_detail['AWSAccountId'], 'KeyId': key_detail['KeyId'], 'Arn': key_detail['Arn'], 'KeyState': key_detail['KeyState']})
                if key_detail['KeyState'] == 'Disabled':
                    append_summary(data, key + ' Amazon KMS 마스터 키가 비활성화되어 있습니다.')
                elif key_detail['KeyState'] == 'PendingDeletion':
                    append_summary(data, key + ' Amazon KMS 마스터 키가 삭제 예약되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '003', key, low_data.keys[key]['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_004(self):
        try:
            print('[KMS_004] Amazon KMS 마스터 키의 키 순환 기능이 활성화되어 있는지 확인하시오.')
            for key in low_data.customer_keys_id:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                get_key_rotation_status = client.kms_client.get_key_rotation_status(KeyId=key)
                append_data(data, 'aws kms get-key-rotation-status --key-id ' + key, {'KeyRotationEnabled': get_key_rotation_status['KeyRotationEnabled']})
                if not get_key_rotation_status['KeyRotationEnabled']:
                    append_summary(data, key + ' Amazon KMS 마스터 키의 키 순환 기능이 비활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '004', key, low_data.keys[key]['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_005(self):
        try:
            print('[KMS_005] 웹 tier에 대해 AWS 계정에 생성된 Amazon KMS 고객 마스터 키(CMK)가 있는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            for key in low_data.customer_keys_id:
                list_resource_tags = client.kms_client.list_resource_tags(KeyId=key)
                append_data(data, 'aws kms list-resource-tags --key-id ' + key + ' --query \"{Tags:Tags}\"',
                            {'KeyId': key, 'Tags': list_resource_tags['Tags']})

            if len(data['raw_data']) > 0:
                append_summary(data, 'Amazon KMS 고객 마스터 키(CMK) 중에서 웹 tier에 대해서 생성된 것이 존재하는지 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '005', 'KMS', 'KMS', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_006(self):
        try:
            print('[KMS_006] 앱 tier에 대해 AWS 계정에 생성된 Amazon KMS 고객 마스터 키(CMK)가 있는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            for key in low_data.customer_keys_id:
                list_resource_tags = client.kms_client.list_resource_tags(KeyId=key)
                append_data(data, 'aws kms list-resource-tags --key-id ' + key + ' --query \"{Tags:Tags}\"',
                            {'KeyId': key, 'Tags': list_resource_tags['Tags']})

            if len(data['raw_data']) > 0:
                append_summary(data, 'Amazon KMS 고객 마스터 키(CMK) 중에서 앱 tier에 대해서 생성된 것이 존재하는지 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '006', 'KMS', 'KMS', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)

    def kms_007(self):
        try:
            print('[KMS_007] 데이터 tier에 대해 AWS 계정에 생성된 Amazon KMS 고객 마스터 키(CMK)가 있는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            for key in low_data.customer_keys_id:
                list_resource_tags = client.kms_client.list_resource_tags(KeyId=key)
                append_data(data, 'aws kms list-resource-tags --key-id ' + key + ' --query \"{Tags:Tags}\"',
                            {'KeyId': key, 'Tags': list_resource_tags['Tags']})

            if len(data['raw_data']) > 0:
                append_summary(data, 'Amazon KMS 고객 마스터 키(CMK) 중에서 데이터 tier에 대해서 생성된 것이 존재하는지 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'KMS', '007', 'KMS', 'KMS', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error :', e)
