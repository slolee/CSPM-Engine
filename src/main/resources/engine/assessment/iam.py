import sys, os
import datetime, maya
from pytz import timezone
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from common.client import *
from common.utils import *
from common.db import *

class IAM:
    def __init__(self):
        low_data.load_iam_low_data()

    def audit_all(self):
        self.iam_001()
        self.iam_002()
        self.iam_003()
        self.iam_004()
        self.iam_005()
        self.iam_006()
        self.iam_007()
        self.iam_008()
        self.iam_009()
        self.iam_010()
        self.iam_011()
        self.iam_012()
        self.iam_013()
        self.iam_014()
        # self.iam_015() - 구현 불가능
        self.iam_016()
        self.iam_017()
        self.iam_018()
        self.iam_019()
        self.iam_020()
        self.iam_021()
        self.iam_022()
        self.iam_023()
        self.iam_024()
        self.iam_025()
        self.iam_026()
        self.iam_027()
        self.iam_028()
        self.iam_029()
        self.iam_030()
        self.iam_031()
        self.iam_032()
        # self.iam_033()
        self.iam_034()
        self.iam_035()

    def iam_001(self):
        try:
            print('[IAM_001] AWS 계정 Root 사용자가 30일 이내에 사용된적 있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws iam generate-credential-report', {})

            root_credential = [credential for credential in low_data.credential_report if credential['user'] == '<root_account>'][0]
            append_data(data, 'aws iam get-credential-report', {'user': root_credential['user'], 'password_last_used': root_credential['password_last_used'], 'access_key_1_active': root_credential['access_key_1_active'],
                        'access_key_1_last_used_date': root_credential['access_key_1_last_used_date'], 'access_key_2_active': root_credential['access_key_2_active'], 'access_key_2_last_used_date': root_credential['access_key_2_last_used_date']})
            if from_now(maya.parse(root_credential['password_last_used']).datetime()) < 30:
                append_summary(data, 'AWS 계정 Root 사용자가 AWS Management 콘솔의 패스워드를 사용해 30일 이내에 사용된적 있습니다.')
                append_summary(data, '최근 사용 시간: ' + root_credential['password_last_used'])

            if root_credential['access_key_1_active'] == 'true':
                if root_credential['access_key_1_last_used_date'] != 'N/A':
                    if from_now(maya.parse(root_credential['access_key_1_last_used_date']).datetime()) < 30:
                        append_summary(data, 'AWS 계정 Root 사용자가 액세스 키 1번을 사용 30일 이내에 사용된적 있습니다.')
                        append_summary(data, '최근 사용 시간: ' + root_credential['access_key_1_last_used_date'])

            if root_credential['access_key_2_active'] == 'true':
                if root_credential['access_key_2_last_used_date'] != 'N/A':
                    if from_now(maya.parse(root_credential['access_key_2_last_used_date']).datetime()) < 30:
                        append_summary(data, 'AWS 계정 Root 사용자가 액세스 키 2번을 사용 30일 이내에 사용된적 있습니다.')
                        append_summary(data, '최근 사용 시간: ' + root_credential['access_key_2_last_used_date'])

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '001', root_credential['user'], root_credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_002(self):
        try:
            print('[IAM_002] AWS 계정 Root 사용자의 활성화된 액세스 키가 존재하는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws iam generate-credential-report', {})

            root_credential = [credential for credential in low_data.credential_report if credential['user'] == '<root_account>'][0]
            append_data(data, 'aws iam get-credential-report', {'user': root_credential['user'], 'access_key_1_active': root_credential['access_key_1_active'], 'access_key_2_active': root_credential['access_key_2_active']})
            if root_credential['access_key_1_active'] == 'true':
                append_summary(data, 'AWS 계정 Root 사용자의 액세스 키 1번이 활성화되어 있습니다.')
            if root_credential['access_key_2_active'] == 'true':
                append_summary(data, 'AWS 계정 Root 사용자의 액세스 키 2번이 활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '002', root_credential['user'], root_credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_003(self):
        try:
            print('[IAM_003] AWS 계정 Root 사용자의 액세스 키가 30일 이내에 재발급되었는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws iam generate-credential-report', {})

            root_credential = [credential for credential in low_data.credential_report if credential['user'] == '<root_account>'][0]
            append_data(data, 'aws iam get-credential-report', {'user': root_credential['user'], 'access_key_1_active': root_credential['access_key_1_active'], 'access_key_1_last_rotated': root_credential['access_key_1_last_rotated'],
                                                                'access_key_2_active': root_credential['access_key_2_active'], 'access_key_2_last_rotated': root_credential['access_key_2_last_rotated']})
            if root_credential['access_key_1_active'] == 'true':
                if from_now(maya.parse(root_credential['access_key_1_last_rotated']).datetime()) >= 30:
                    append_summary(data, 'AWS 계정 Root 사용자의 액세스 키 1번이 30일 이내에 재발급되지 않았습니다.')
            if root_credential['access_key_2_active'] == 'true':
                if from_now(maya.parse(root_credential['access_key_2_last_rotated']).datetime()) >= 30:
                    append_summary(data, 'AWS 계정 Root 사용자의 액세스 키 2번이 30일 이내에 재발급되지 않았습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '003', root_credential['user'], root_credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_004(self):
        try:
            print('[IAM_004] AWS 계정 Root 사용자의 X.509 서명이 활성화되어 있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws iam generate-credential-report', {})

            root_credential = [credential for credential in low_data.credential_report if credential['user'] == '<root_account>'][0]
            append_data(data, 'aws iam get-credential-report', {'user': root_credential['user'], 'cert_1_active': root_credential['cert_1_active'], 'cert_2_active': root_credential['cert_2_active']})
            if root_credential['cert_1_active'] == 'true':
                append_summary(data, 'AWS 계정 Root 사용자의 X.509 서명 1번이 활성화되어 있습니다.')
            if root_credential['cert_2_active'] == 'true':
                append_summary(data, 'AWS 계정 Root 사용자의 X.509 서명 2번이 활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '004', root_credential['user'], root_credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_005(self):
        try:
            print('[IAM_005] AWS 계정 Root 사용자의 MFA가 활성화되어 있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws iam generate-credential-report', {})

            root_credential = [credential for credential in low_data.credential_report if credential['user'] == '<root_account>'][0]
            append_data(data, 'aws iam get-account-summary --query \"SummaryMap.{AccountMFAEnabled:AccountMFAEnabled}\"', {'AccountMFAEnabled': low_data.account_summary['AccountMFAEnabled']})
            append_data(data, 'aws iam get-credential-report', {'user': root_credential['user'], 'mfa_active': root_credential['mfa_active']})
            if low_data.account_summary['AccountMFAEnabled'] == 0 and root_credential['mfa_active'] == 'false':
                append_summary(data, 'AWS 계정 Root 사용자의 MFA가 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '005', root_credential['user'], root_credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_006(self):
        try:
            print('[IAM_006] AWS 계정 Root 사용자가 하드웨어 MFA가 활성화되어 있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws iam get-account-summary --query \"SummaryMap.{AccountMFAEnabled:AccountMFAEnabled}\"', {'AccountMFAEnabled': low_data.account_summary['AccountMFAEnabled']})
            append_data(data, 'aws iam list-virtual-mfa-devices', {'VirtualMFADevices': low_data.virtual_mfa_devices})
            if low_data.account_summary['AccountMFAEnabled'] == 0:
                append_summary(data, 'AWS 계정 Root 사용자의 MFA가 비활성화되어 있습니다.')
            else:
                if [virtual_mfa_device for virtual_mfa_device in low_data.virtual_mfa_devices if virtual_mfa_device['SerialNumber'].endsWith('root-account-mfa-device')]:
                    append_summary(data, 'AWS 계정 Root 사용자의 하드웨어 MFA가 아니라 Virtual MFA가 활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '006', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_007(self):
        try:
            print('[IAM_007] AdministratorAccess 관리형 정책을 가진 관리자용 IAM 사용자가 존재하는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            administrator_access = [policy for policy in low_data.policies_only_attached if policy['PolicyName'] == 'AdministratorAccess']
            list_entities_for_policy = client.iam_client.list_entities_for_policy(PolicyArn=administrator_access[0]['Arn'])
            append_data(data, 'aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
                        {'PolicyUsers': list_entities_for_policy['PolicyUsers'], 'PolicyGroups': list_entities_for_policy['PolicyGroups'], 'PolicyRoles': list_entities_for_policy['PolicyRoles']})

            summary = ''
            if administrator_access:
                if list_entities_for_policy['PolicyGroups']:
                    summary += 'Group : ' + str([entity['GroupName'] for entity in list_entities_for_policy['PolicyGroups']]) + '\n'
                if list_entities_for_policy['PolicyUsers']:
                    summary += 'Users : ' + str([entity['UserName'] for entity in list_entities_for_policy['PolicyUsers']]) + '\n'
                if list_entities_for_policy['PolicyRoles']:
                    summary += 'Roles : ' + str([entity['RoleName'] for entity in list_entities_for_policy['PolicyRoles']]) + '\n'

            if summary:
                append_summary(data, 'AdministratorAccess 관리형 정책이 부여된 IAM 개체는 다음과 같습니다.')
                append_summary(data, summary)
                append_summary(data, '올바른 사용자에게 부여된 권한인지 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '007', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_008(self):
        try:
            print('[IAM_008] AWS 계정 설정에 대체 연락처 세부 정보가 설정되어있는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_summary(data, 'AWS 계정 설정에 대체 연락처 세부 정보가 설정되어있는지 AWS Management Console을 통해 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '008', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_009(self):
        try:
            print('[IAM_009] AWS 계정 설정에 보안 챌린지 질문 구성이 설정되어있는지 확인하시오.')
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_summary(data, 'AWS 계정 설정에 보안 챌린지 질문 구성이 설정되어있는지 AWS Management Console을 통해 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '009', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_010(self):
        try:
            print('[IAM_010] IAM 암호 정책이 사용중인지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws iam get-account-password-policy', {'PasswordPolicy': low_data.account_password_policy})
            if not low_data.account_password_policy:
                append_summary(data, '해당 AWS 계정에 IAM 암호 정책이 사용되지 않고 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '010', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_011(self):
        try:
            print('[IAM_011] 강력한 IAM 암호 정책을 설정했는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.account_password_policy:
                append_data(data, 'aws iam get-account-password-policy --query \"PasswordPolicy.{RequireUppercaseCharacters:RequireUppercaseCharacters, RequireLowercaseCharacters:RequireLowercaseCharacters, RequireNumbers:RequireNumbers, RequireSymbols:RequireSymbols}\"',
                            {'RequireUppercaseCharacters': low_data.account_password_policy['RequireUppercaseCharacters'], 'RequireLowercaseCharacters': low_data.account_password_policy['RequireLowercaseCharacters'],
                             'RequireNumbers': low_data.account_password_policy['RequireNumbers'], 'RequireSymbols': low_data.account_password_policy['RequireSymbols']})
                if not low_data.account_password_policy['RequireUppercaseCharacters']:
                    append_summary(data, '\"1개 이상의 라틴 알파벨 대문자(A-Z) 필수\" IAM 암호 정책이 설정되어있지 않습니다.')
                if not low_data.account_password_policy['RequireLowercaseCharacters']:
                    append_summary(data, '\"1개 이상의 라틴 알파벨 소문자(a-z) 필수\" IAM 암호 정책이 설정되어있지 않습니다.')
                if not low_data.account_password_policy['RequireNumbers']:
                    append_summary(data, '\"1개 이상의 숫자 필수\" IAM 암호 정책이 설정되어있지 않습니다.')
                if not low_data.account_password_policy['RequireSymbols']:
                    append_summary(data, '\"영숫자를 제외한 문자 1개 이상 필수(!@#$%^&*()_+-=[]{}|)\" IAM 암호 정책이 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '011', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_012(self):
        try:
            print('[IAM_012] IAM 암호 정책이 14자 이상의 암호를 요구하도록 설정되어있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.account_password_policy:
                append_data(data, 'aws iam get-account-password-policy --query \"PasswordPolicy.{MinimumPasswordLength:MinimumPasswordLength}\"',
                            {'MinimumPasswordLength': low_data.account_password_policy['MinimumPasswordLength']})
                if low_data.account_password_policy['MinimumPasswordLength'] < 14:
                    append_summary(data, 'IAM 암호 정책이 14자 이상의 암호를 요구하도록 설정되어있지 않습니다.')
                    append_summary(data, '현재 최소 암호 길이 : ' + str(low_data.account_password_policy['MinimumPasswordLength']))

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '012', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_013(self):
        try:
            print('[IAM_013] IAM 암호 정책이 암호 재사용을 방지하도록 설정되어있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.account_password_policy:
                append_data(data, 'aws iam get-account-password-policy --query \"PasswordPolicy.{PasswordReusePrevention:PasswordReusePrevention}\"',
                            {'PasswordReusePrevention': (low_data.account_password_policy['PasswordReusePrevention'] if 'PasswordReusePrevention' in low_data.account_password_policy else 'null')})
                if 'PasswordReusePrevention' not in low_data.account_password_policy:
                    append_summary(data, 'IAM 암호 정책이 암호 재사용을 방지하도록 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '013', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_014(self):
        try:
            print('[IAM_014] IAM 암호 정책이 암호를 90일 이내에 만료하도록 설정했는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.account_password_policy:
                append_data(data, 'aws iam get-account-password-policy --query \"PasswordPolicy.{MaxPasswordAge:MaxPasswordAge}\"',
                            {'MaxPasswordAge': (low_data.account_password_policy['MaxPasswordAge'] if 'MaxPasswordAge' in low_data.account_password_policy else 'null')})
                if 'MaxPasswordAge' not in low_data.account_password_policy:
                    append_summary(data, 'IAM 암호 정책이 암호를 만료하도록 설정되어있지 않습니다.')
                elif low_data.account_password_policy['MaxPasswordAge'] > 90:
                    append_summary(data, 'IAM 암호 정책이 90일 이내에 만료하도록 설정되어있지 않습니다.')
                    append_summary(data, '현재 암호 만료일 : ' + str(low_data.account_password_policy['MaxPasswordAge']) + '일')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '014', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_016(self):
        try:
            print('[IAM_016] 암호가 만료되거나 만료일이 7일 이내인 IAM 사용자가 존재하는지 확인하시오.')
            for credential in low_data.credential_report:
                if credential['user'] == '<root_account>':
                    continue
                if credential['password_last_changed'] == 'N/A' or credential['password_next_rotation'] == 'N/A':
                    continue

                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'password_next_rotation': credential['password_next_rotation']})

                if (maya.parse(credential['password_next_rotation']).datetime() - datetime.datetime.now(timezone('Asia/Seoul'))).days < 0:
                    append_summary(data, credential['user'] + ' 의 암호가 만료된지 ' + str((maya.parse(credential['password_next_rotation']).datetime() - datetime.datetime.now(timezone('Asia/Seoul'))).days * -1) + '일 경과했습니다.')
                elif (maya.parse(credential['password_next_rotation']).datetime() - datetime.datetime.now(timezone('Asia/Seoul'))).days < 7:
                    append_summary(data, credential['user'] + ' 의 암호의 만료일이 7일 이내입니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '016', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_017(self):
        try:
            print('[IAM_017] 사용하지 않는(90일 이내) IAM 자격증명이 존재하는지 확인하시오.')
            for credential in low_data.credential_report:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'password_enabled': credential['password_enabled'], 'password_last_used': credential['password_last_used'], 'password_last_changed': credential['password_last_changed'],
                                                                    'access_key_1_active': credential['access_key_1_active'], 'access_key_1_last_used_date': credential['access_key_1_last_used_date'], 'access_key_1_last_rotated': credential['access_key_1_last_rotated'],
                                                                    'access_key_2_active': credential['access_key_2_active'], 'access_key_2_last_used_date': credential['access_key_2_last_used_date'], 'access_key_2_last_rotated': credential['access_key_2_last_rotated']})

                if credential['password_enabled'] == 'true':
                    if credential['password_last_used'] == 'no_information':
                        if from_now(maya.parse(credential['password_last_changed']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 암호가 사용되지 않습니다.')
                    else:
                        if from_now(maya.parse(credential['password_last_used']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 암호가 사용된지가 ' + str(from_now(maya.parse(credential['password_last_used']).datetime())) + '일 경과했습니다.')
                if credential['access_key_1_active'] == 'true':
                    if credential['access_key_1_last_used_date'] == 'N/A':
                        if from_now(maya.parse(credential['access_key_1_last_rotated']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 액세스 키 1번이 사용되지 않습니다.')
                    else:
                        if from_now(maya.parse(credential['access_key_1_last_used_date']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 액세스 키 1번이 사용된지' + str(from_now(maya.parse(credential['access_key_1_last_used_date']).datetime())) + '일 경과했습니다.')
                if credential['access_key_2_active'] == 'true':
                    if credential['access_key_2_last_used_date'] == 'N/A':
                        if from_now(maya.parse(credential['access_key_2_last_rotated']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 액세스 키 2번이 사용되지 않습니다.')
                    else:
                        if from_now(maya.parse(credential['access_key_2_last_used_date']).datetime()) > 90:
                            append_summary(data, credential['user'] + ' 의 액세스 키 2번이 사용된지' + str(from_now(maya.parse(credential['access_key_2_last_used_date']).datetime())) + '일 경과했습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '017', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_018(self):
        try:
            print('[IAM_018] IAM 사용자 생성과정에서 액세스 키가 생성되는지 확인하시오.')
            for credential in low_data.credential_report:
                if credential['user'] == '<root_account>':
                    continue
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'user_creation_time': credential['user_creation_time'], 'access_key_1_last_rotated': credential['access_key_1_last_rotated'],
                                                                    'access_key_2_last_rotated': credential['access_key_2_last_rotated']})
                if credential['access_key_1_last_rotated'] != 'N/A':
                    if (maya.parse(credential['access_key_1_last_rotated']) - maya.parse(credential['user_creation_time'])).seconds <= 1:
                        append_summary(data, credential['user'] + ' 의 액세스 키 1번이 IAM 사용자 생성과정에서 생성되었습니다.')
                if credential['access_key_2_last_rotated'] != 'N/A':
                    if (maya.parse(credential['access_key_2_last_rotated']) - maya.parse(credential['user_creation_time'])).seconds <= 1:
                        append_summary(data, credential['user'] + ' 의 액세스 키 2번이 IAM 사용자 생성과정에서 생성되었습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '018', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_019(self):
        try:
            print('[IAM_019] IAM 사용자의 액세스 키가 30일 이내에 재발급되었는지 확인하시오.')
            for credential in low_data.credential_report:
                if credential['user'] == '<root_account>':
                    continue
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'access_key_1_active': credential['access_key_1_active'], 'access_key_1_last_rotated': credential['access_key_1_last_rotated'],
                                                                    'access_key_2_active': credential['access_key_2_active'], 'access_key_2_last_rotated': credential['access_key_2_last_rotated']})

                if credential['access_key_1_active'] == 'true' and from_now(maya.parse(credential['access_key_1_last_rotated']).datetime()) >= 30:
                    append_summary(data, credential['user'] + ' 의 액세스 키 1번이 30일 이내에 재발급되지 않았습니다.')
                if credential['access_key_2_active'] == 'true' and from_now(maya.parse(credential['access_key_2_last_rotated']).datetime()) >= 30:
                    append_summary(data, credential['user'] + ' 의 액세스 키 2번이 30일 이내에 재발급되지 않았습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '019', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_020(self):
        try:
            print('[IAM_020] 2개의 액세스 키가 활성화된 IAM 사용자가 존재하는지 확인하시오.')
            for credential in low_data.credential_report:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'access_key_1_active': credential['access_key_1_active'], 'access_key_2_active': credential['access_key_2_active']})

                if credential['access_key_1_active'] == 'true' and credential['access_key_2_active'] == 'true':
                    append_summary(data, credential['user'] + ' 의 2개의 액세스 키가 활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '020', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_021(self):
        try:
            print('[IAM_021] 2개의 SSH Public Key가 활성화된 IAM 사용자가 존재하는지 확인하시오.')

            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-ssh-public-keys --user-name ' + user['UserName'], {'SSHPublicKeys': low_data.ssh_public_keys[user['UserName']]})

                active_count = 0
                if len([ssh_public_key for ssh_public_key in low_data.ssh_public_keys[user['UserName']] if ssh_public_key['Status'] == 'Active']) > 1:
                    append_summary(data, user['UserName'] + ' 이 SSH Public Key가 ' + str(active_count) + '개 활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '021', user['UserName'], user['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_022(self):
        try:
            print('[IAM_022] SSH Public Key가 90일 이내에 재발급되었는지 확인하시오.')
            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-ssh-public-keys --user-name ' + user['UserName'], {'SSHPublicKeys': low_data.ssh_public_keys[user['UserName']]})

                for ssh_public_key in low_data.ssh_public_keys[user['UserName']]:
                    if from_now(ssh_public_key['UploadDate']) >= 90:
                        append_summary(data, user['UserName'] + ' 의 SSH Public Key(' + ssh_public_key['SSHPublicKeyId'] + ' )가 재발급된지 ' + str(from_now(ssh_public_key['UploadDate'])) + '일 경과했습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '022', user['UserName'], user['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_023(self):
        try:
            print('[IAM_023] 모든 IAM 사용자의 MFA가 활성화되어 있는지 확인하시오.')
            for credential in low_data.credential_report:
                if credential['user'] == '<root_account>':
                    continue
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam generate-credential-report', {})
                append_data(data, 'aws iam get-credential-report', {'user': credential['user'], 'mfa_active': credential['mfa_active']})

                if credential['mfa_active'] == 'false':
                    append_summary(data, credential['user'] + ' 의 MFA가 비활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '023', credential['user'], credential['arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_024(self):
        try:
            print('[IAM_024] IAM 사용자에 연결된 IAM 정책이 존재하는지 확인하시오.')
            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-attached-user-policies --user-name ' + user['UserName'], {'AttachedPolicies': low_data.attached_user_policies[user['UserName']]})

                if low_data.attached_user_policies[user['UserName']]:
                    append_summary(data, user['UserName'] + ' 에 연결된 IAM 정책이 ' + str(len(low_data.attached_user_policies[user['UserName']])) + '개 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '024', user['UserName'], user['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_025(self):
        try:
            print('[IAM_025] 사용하지 않는 IAM 사용자가 존재하는지 확인하시오.')
            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws iam list_users --filter Name=user-name,Values=' + user['UserName'], {'UserName': user['UserName'], 'PasswordLastUsed': (str(user['PasswordLastUsed']) if 'PasswordLastUsed' in user else 'null')})
                if 'PasswordLastUsed' not in user or from_now(user['PasswordLastUsed']) >= 90:
                    active_access_keys = list(filter(lambda access_key: access_key['Status'] == 'Active', low_data.access_keys[user['UserName']]))
                    append_data(data, 'aws iam list-access-keys --user-name=' + user['UserName'] + ' --query \"{AccessKeyMetadata:AccessKeyMetadata[*].{UserName:UserName, Status:Status, AccessKeyId:AccessKeyId}}\"',
                                {'AccessKeyMetadata': [{'UserName': active_access_key['UserName'], 'Status': active_access_key['Status'], 'AccessKeyId': active_access_key['AccessKeyId']} for active_access_key in active_access_keys]})

                    active_count = 0
                    for active_access_key in active_access_keys:
                        access_key_last_used = client.iam_client.get_access_key_last_used(AccessKeyId=active_access_key['AccessKeyId'])
                        append_data(data, 'aws iam get-access-key-last-used --access-key-id=' + active_access_key['AccessKeyId'], {'UserName': access_key_last_used['UserName'],
                                    'AccessKeyLastUsed': {'Region': access_key_last_used['AccessKeyLastUsed']['Region'], 'ServiceName': access_key_last_used['AccessKeyLastUsed']['ServiceName'],
                                                          'LastUsedDate': str(access_key_last_used['AccessKeyLastUsed']['LastUsedDate'])}})
                        if 'LastUsedDate' in access_key_last_used['AccessKeyLastUsed'] and \
                                from_now(access_key_last_used['AccessKeyLastUsed']['LastUsedDate']) < 90:
                            active_count += 1
                    if active_count == 0:
                        append_summary(data, user['UserName'] + ' 은 사용되지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '025', user['UserName'], user['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_026(self):
        try:
            print('[IAM_026] 인라인 정책이 있는 IAM 사용자 혹은 그룹이 존재하는지 확인하시오.')

            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-user-policies --user-name ' + user['UserName'], {'AttachedPolicies': low_data.user_policies[user['UserName']]})

                if low_data.user_policies[user['UserName']]:
                    append_summary(data, 'IAM 사용자 ' + user['UserName'] + ' 에 인라인 정책이 ' + str(len(low_data.user_policies[user['UserName']])) + '개 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '026', user['UserName'], user['Arn'], check, str(data)))

            for group in low_data.groups:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-group-policies --group-name ' + group['GroupName'], {'AttachedPolicies': low_data.group_policies[group['GroupName']]})

                if low_data.group_policies[group['GroupName']]:
                    append_summary(data, 'IAM 그룹 ' + group['GroupName'] + ' 에 인라인 정책이 ' + str(len(low_data.group_policies[group['GroupName']])) + '개 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '026', group['GroupName'], group['Arn'], check, str(data)))

            for role in low_data.roles:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-role-policies --role-name ' + role['RoleName'], {'AttachedPolicies': low_data.role_policies[role['RoleName']]})

                if low_data.role_policies[role['RoleName']]:
                    append_summary(data, 'IAM 역할 ' + role['RoleName'] + ' 에 인라인 정책이 ' + str(len(low_data.role_policies[role['RoleName']])) + '개 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '026', role['RoleName'], role['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_027(self):
        try:
            print('[IAM_027] 사용하지 않는 IAM 그룹이 존재하는지 확인하시오.')
            for group in low_data.groups:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                get_group = client.iam_client.get_paginator('get_group').paginate(GroupName=group['GroupName'])
                users_in_group = [group_user for group_info in get_group for group_user in group_info['Users']]
                append_data(data, 'aws iam get-group --group-name ' + group['GroupName'] + ' --query \"{Users:Users[*].{UserName:UserName, UserId:UserId}}\"',
                            {'Users': [{'UserName': user_in_group['UserName'], 'UserId': user_in_group['UserId']} for user_in_group in users_in_group]})
                if not users_in_group:
                    append_summary(data, group['GroupName'] + ' 은 사용되지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '027', group['GroupName'], group['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_028(self):
        try:
            print('[IAM_028] IAM 정책을 수정/삭제할 수 있는 비인가된 IAM 사용자가 존재하는지 확인하시오.')
            policies = ['iam:CreatePolicy', 'iam:CreatePolicyVersion', 'iam:DeleteGroupPolicy', 'iam:DeletePolicy', 'iam:DeleteRolePolicy', 'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy',
                        'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy', 'iam:PutUserPolicy', 'iam:UpdateAssumeRolePolicy']

            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            # 구현 방법에 대해 이야기
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_029(self):
        try:
            print('[IAM_029] AWSCloudTrail_FullAccess 정책이 한 개 이상의 IAM Entity에 부여되어있는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            aws_cloudtrail_full_access = list(filter(lambda policy: policy['PolicyName'] == 'AWSCloudTrail_FullAccess', low_data.policies_only_attached))
            summary = ''
            if aws_cloudtrail_full_access:
                list_entities_for_policy = client.iam_client.list_entities_for_policy(PolicyArn=aws_cloudtrail_full_access[0]['Arn'])
                append_data(data, 'aws iam list-entries-for-policy --policy-arn ' + aws_cloudtrail_full_access[0]['Arn'],
                            {'PolicyGroups': list_entities_for_policy['PolicyGroups'], 'PolicyUsers': list_entities_for_policy['PolicyUsers'], 'PolicyRoles': list_entities_for_policy['PolicyRoles']})
                if list_entities_for_policy['PolicyGroups']:
                    summary += 'Group : ' + str([entity['GroupName'] for entity in list_entities_for_policy['PolicyGroups']]) + '\n'
                if list_entities_for_policy['PolicyUsers']:
                    summary += 'Users : ' + str([entity['UserName'] for entity in list_entities_for_policy['PolicyUsers']]) + '\n'
                if list_entities_for_policy['PolicyRoles']:
                    summary += 'Roles : ' + str([entity['RoleName'] for entity in list_entities_for_policy['PolicyRoles']]) + '\n'

            if summary:
                append_summary(data, 'AWSCloudTrail_FullAccess 관리형 정책이 부여된 IAM 개체는 다음과 같습니다.')
                append_summary(data, summary)
                append_summary(data, '올바르게 부여된 권한인지 확인하시오.')
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '029', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_030(self):
        try:
            print('[IAM_030] 모든 Action(*)를 허용하는 IAM 정책이 존재하는지 확인하시오.')
            for policy in low_data.policies_local:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws iam list-policies --scope Local --query \"Policies[*].{PolicyName:PolicyName, PolicyId:PolicyId, DefaultVersionId:DefaultVersionId, Arn:Arn}\"',
                            {'PolicyName': policy['PolicyName'], 'PolicyId': policy['PolicyId'], 'DefaultVersionId': policy['DefaultVersionId'], 'Arn':policy['Arn']})
                get_policy_version = client.iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
                append_data(data, 'aws iam get-policy-version --policy-arn ' + policy['Arn'] + ' --version-id ' + policy['DefaultVersionId'] + ' --query \"PolicyVersion.{VersionId:VersionId, Document:Document}\"',
                            {'VersionId': get_policy_version['PolicyVersion']['VersionId'], 'Document': get_policy_version['PolicyVersion']['Document']})

                if type(get_policy_version['PolicyVersion']['Document']['Statement']) == list:
                    if [statement for statement in get_policy_version['PolicyVersion']['Document']['Statement'] if statement['Effect'] == 'Allow' and '*' in statement['Action']]:
                        append_summary(data, policy['PolicyName'] + ' 정책에서 모든 Action(*)을 허용합니다.')
                elif type(get_policy_version['PolicyVersion']['Document']['Statement']) == dict:
                    if get_policy_version['PolicyVersion']['Document']['Statement']['Effect'] == 'Allow' and '*' in get_policy_version['PolicyVersion']['Document']['Statement']['Action']:
                        append_summary(data, policy['PolicyName'] + ' 정책에서 모든 Action(*)을 허용합니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '030', policy['PolicyName'], policy['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_031(self):
        try:
            print('[IAM_031] Effect:"Allow"와 "NotAction"을 함께 사용하는 IAM 정책이 존재하는지 확인하시오.')
            for policy in low_data.policies_local:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws iam list-policies --scope Local --query \"Policies[*].{PolicyName:PolicyName, PolicyId:PolicyId, DefaultVersionId:DefaultVersionId, Arn:Arn}\"',
                            {'PolicyName': policy['PolicyName'], 'PolicyId': policy['PolicyId'], 'DefaultVersionId': policy['DefaultVersionId'], 'Arn': policy['Arn']})

                get_policy_version = client.iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
                append_data(data, 'aws iam get-policy-version --policy-arn ' + policy['Arn'] + ' --version-id ' + policy['DefaultVersionId'] + ' --query \"PolicyVersion.{VersionId:VersionId, Document:Document}\"',
                            {'VersionId': get_policy_version['PolicyVersion']['VersionId'], 'Document': get_policy_version['PolicyVersion']['Document']})

                document = get_policy_version['PolicyVersion']['Document']
                if type(document['Statement']) == list:
                    if [statement for statement in document['Statement'] if statement['Effect'] == 'Allow' and 'NotAction' in statement]:
                        append_summary(data, policy['PolicyName'] + ' 정책에 \"Effect\":\"Allow\"와 \"NotAction\"을 함께 사용합니다.')
                elif type(document['Statement']) == dict:
                    if document['Statement']['Effect'] == 'Allow' and 'NotAction' in document['Statement']:
                        append_summary(data, policy['PolicyName'] + ' 정책에 \"Effect\":\"Allow\"와 \"NotAction\"을 함께 사용합니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '031', policy['PolicyName'], policy['Arn'], check, str(data)))

            for user in low_data.users:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-user-policies --user-name ' + user['UserName'], {'PolicyNames': low_data.user_policies[user['UserName']]})
                for user_policy in low_data.user_policies[user['UserName']]:
                    statements = client.iam_client.get_user_policy(UserName=user['UserName'], PolicyName=user_policy)
                    append_data(data, 'aws iam get-user-policy --user-name ' + user['UserName'] + ' --policy-name ' + user_policy,
                                {'UserName': statements['UserName'], 'PolicyName': statements['PolicyName'], 'PolicyDocument': statements['PolicyDocument']})
                    if [statement for statement in statements['PolicyDocument']['Statement'] if statement['Effect'] == 'Allow' and 'NotAction' in statement]:
                        append_summary(data, user['UserName'] + ' 사용자의 ' + user_policy + ' 인라인정책에 \"Effect\":\"Allow\"와 \"NotAction\"을 함께 사용합니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '031', user['UserName'], user['Arn'], check, str(data)))

            for group in low_data.groups:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-group-policies --group-name ' + group['GroupName'], {'PolicyNames': low_data.group_policies[group['GroupName']]})
                for group_policy in low_data.group_policies[group['GroupName']]:
                    statements = client.iam_client.get_group_policy(GroupName=group['GroupName'], PolicyName=group_policy)
                    append_data(data, 'aws iam get-group-policy --group-name ' + group['GroupName'] + ' --policy-name ' + group_policy,
                                {'GroupName': statements['GroupName'], 'PolicyName': statements['PolicyName'], 'PolicyDocument': statements['PolicyDocument']})
                    if [statement for statement in statements['PolicyDocument']['Statement'] if statement['Effect'] == 'Allow' and 'NotAction' in statement]:
                        append_summary(data, group['GroupName'] + ' 그룹의 ' + group_policy + ' 인라인정책에 \"Effect\":\"Allow\"와 \"NotAction\"을 함께 사용합니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '031', group['GroupName'], group['Arn'], check, str(data)))

            for role in low_data.roles:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws iam list-role-policies --role-name ' + role['RoleName'], {'PolicyNames': low_data.role_policies[role['RoleName']]})
                for role_policy in low_data.role_policies[role['RoleName']]:
                    statements = client.iam_client.get_role_policy(RoleName=role['RoleName'], PolicyName=role_policy)
                    append_data(data, 'aws iam get-role-policy --role-name ' + role['RoleName'] + ' --policy-name ' + role_policy,
                                {'RoleName': statements['RoleName'], 'PolicyName': statements['PolicyName'], 'PolicyDocument': statements['PolicyDocument']})
                    if [statement for statement in statements['PolicyDocument']['Statement'] if statement['Effect'] == 'Allow' and 'NotAction' in statement]:
                        append_summary(data, role['RoleName'] + ' 역할의 ' + role_policy + ' 인라인정책에 \"Effect\":\"Allow\"와 \"NotAction\"을 함께 사용합니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '031', role['RoleName'], role['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_032(self):
        try:
            print('[IAM_032] AWSSupportAccess 정책을 가지는 IAM 역할이 존재하는지 확인하시오.')
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            aws_support_access = [policy for policy in low_data.policies_only_attached if policy['PolicyName'] == 'AWSSupportAccess']
            if aws_support_access:
                list_entities_for_policy = client.iam_client.list_entities_for_policy(PolicyArn=aws_support_access[0]['Arn'])
                append_data(data, 'aws iam list-entries-for-policy --policy-arn ' + aws_support_access[0]['Arn'] + ' --query \"{PolicyRoles:PolicyRoles}\"',
                            {'PolicyRoles': list_entities_for_policy['PolicyRoles']})
                if not list_entities_for_policy['PolicyRoles']:
                    append_summary(data, 'AWSSupportAccess 관리형 정책이 부여된 IAM 역할이 존재하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '032', 'IAM', 'IAM', check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_033(self):
        try:
            print('[IAM_033] 보안그룹, NACL, 흐름로그를 생성하고 관리할 수 있는 권한이 과도하게 부여되어있지 않은지 확인하시오.')
            policies = ['ec2:CreateSecurityGroup', 'ec2:DeleteSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:AuthorizeSecurityGroupEgress',
                        'ec2:RevokeSecurityGroupIngress', 'ec2:RevokeSecurityGroupEgress', 'ec2:CreateFlowLogs', 'ec2:DeleteFlowlogs',
                        'ec2:CreateNetworkAcl', 'ec2:DeleteNetworkAcl', 'ec2:CreateNetworkAclEntry', 'ec2:DeleteNetworkAclEntry']

            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            # 28번과 같은 고민..
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_034(self): # 체크필요
        try:
            print('[IAM_034] 만료되거나 만료일이 7일 이내인 SSL/TLS 인증서가 존재하는지 확인하시오.')
            for server_certificate in low_data.server_certificates:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws iam get-server-certificate --server-certificate-name ' + server_certificate['ServerCertificateMetadata']['ServerCertificateName'] + ' --query \"ServerCertificate.ServerCertificateMetadata\"',
                            server_certificate['ServerCertificateMetadata'])
                if (server_certificate['ServerCertificateMetadata']['Expiration'] - datetime.datetime.now(timezone('Asia/Seoul'))).days < 0:
                    append_summary(data, server_certificate['ServerCertificateMetadata']['ServerCertificateName'] + ' 인증서가 만료된지 ' + \
                                   str((server_certificate['ServerCertificateMetadata']['Expiration'] - datetime.datetime.now(timezone('Asia/Seoul'))).days * -1) + '일 경과했습니다.')
                elif (server_certificate['ServerCertificateMetadata']['Expiration'] - datetime.datetime.now(timezone('Asia/Seoul'))).days < 7:
                    append_summary(data, server_certificate['ServerCertificateMetadata']['ServerCertificateName'] + ' 인증서 만료일의 7일 이내입니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '034', server_certificate['ServerCertificateMetadata']['ServerCertificateName'], server_certificate['ServerCertificateMetadata']['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def iam_035(self):
        try:
            print('[IAM_035] 2014년 4월 1일 이전에 업로드된 SSL/TLS 인증서가 없는지 확인하시오.')
            for server_certificate in low_data.server_certificates:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws iam get-server-certificate --server-certificate-name ' + server_certificate['ServerCertificateMetadata']['ServerCertificateName'] + ' --query \"ServerCertificate.ServerCertificateMetadata\"',
                            server_certificate['ServerCertificateMetadata'])
                if (server_certificate['ServerCertificateMetadata']['UploadDate'] - datetime.datetime(2014, 4, 1)).days < 0:
                    append_summary(data, server_certificate['ServerCertificateMetadata']['ServerCertificateName'] + ' 인증서가 2014년 4월 1일 이전에 업로드 됐습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'IAM', '035', server_certificate['ServerCertificateMetadata']['ServerCertificateName'], server_certificate['ServerCertificateMetadata']['Arn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)
