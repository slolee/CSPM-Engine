from Common.data import low_data, AWS_CURRENT_ID
from Common.client import *
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class Lambda:
    def __init__(self):
        low_data.load_lambda_low_data()

    def audit_all(self):
        self.lambda_001()
        self.lambda_002()
        self.lambda_003()
        self.lambda_004()
        self.lambda_005()
        self.lambda_006()
        self.lambda_007()
        self.lambda_008()

    def lambda_001(self):
        print('[Lambda_001] 둘 이상의 Lambda 함수가 동일한 IAM 역할을 사용하지 않는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, Role:Role}}\"',
                        {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'Role': function['Role']} for function in low_data.functions]})

            this_function = function
            duplicate_functions = [function for function in low_data.functions if function['Role'] == this_function['Role'] and function['FunctionName'] != this_function['FunctionName']]
            if len(duplicate_functions) > 0:
                append_summary(data, function['FunctionName'] + ' 함수와 동일한 IAM 역할을 사용하는 함수 ' + str(duplicate_functions) + ' 가 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '001', function['FunctionName'], check, str(data)))
        print()

    def lambda_002(self):
        print('[Lambda_002] 사용가능한 Lambda 함수에 관리자 권한이 있는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, Role:Role}}\"',
                        {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'Role': function['Role']} for function in low_data.functions]})

            role_name = function['Role'].split('/')[-1]
            list_attached_role_policies = iam_client.get_paginator('list_attached_role_policies').paginate(RoleName=role_name)
            attached_role_policies = [attached_role_policy for attached_role_policies in list_attached_role_policies for attached_role_policy in attached_role_policies['AttachedPolicies']]
            append_data(data, 'aws iam list-attached-role-policies --role-name ' + role_name, {'AttachedPolicies': attached_role_policies})

            for attached_role_policy in attached_role_policies:
                list_policy_versions = iam_client.get_paginator('list_policy_versions').paginate(PolicyArn=attached_role_policy['PolicyArn'])
                default_policy_versions = [policy_version for policy_versions in list_policy_versions for policy_version in policy_versions['Versions'] if policy_version['IsDefaultVersion']]
                append_data(data, 'aws iam list-policy-versions --policy-arn ' + attached_role_policy['PolicyArn'] + ' --query \"{Versions:Versions.{VersionId:VersionId, IsDefaultVersion:IsDefaultVersion}}\"',
                            {'Versions': {'VersionId': default_policy_versions[0]['VersionId'], 'IsDefaultVersion': default_policy_versions[0]['IsDefaultVersion']}})

                get_policy_version = iam_client.get_policy_version(PolicyArn=attached_role_policy['PolicyArn'], VersionId=default_policy_versions[0]['VersionId'])
                append_data(data, 'aws iam get-policy-version --policy-arn ' + attached_role_policy['PolicyArn'] + ' --version-id ' + default_policy_versions[0]['VersionId'] +
                            ' --query \"{PolicyVersion:PolicyVersion.{Document:Document, VersionId:VersionId}}\"',
                            {'PolicyVersion': {'Document': get_policy_version['PolicyVersion']['Document'], 'VersionId': get_policy_version['PolicyVersion']['VersionId']}})

                document = get_policy_version['PolicyVersion']['Document']
                if type(document['Statement']) == list:
                    if [statement for statement in document['Statement'] if statement['Effect'] == 'Allow' and '*' in statement['Action']]:
                        append_summary(data, function['FunctionName'] + ' 함수에 관리자 권한이 있습니다.')
                elif type(document['Statement']) == dict:
                    if document['Statement']['Effect'] == 'Allow' and '*' in document['Statement']['Action']:
                        append_summary(data, function['FunctionName'] + ' 함수에 관리자 권한이 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '002', function['FunctionName'], check, str(data)))
        print()

    def lambda_003(self):
        print('[Lambda_003] Lambda 함수가 권한 정책을 통해 알 수없는 교차 계정 액세스를 허용하지 않는지 확인하시오.')
        for function in low_data.functions:
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.function_policies[function['FunctionName']]:
                function_policy = json.loads(low_data.function_policies[function['FunctionName']])
                statements = function_policy['Statement']

                raw_data = []
                if type(statements) == list:
                    raw_data = [{'Sid': statement['Sid'], 'Condition': {'ArnLike': {'AWS:SourceArn': statement['Condition']['ArnLike']['AWS:SourceArn']}} if 'Condition' in statement else 'null',
                                 'Principal': statement['Principal'], 'Resource': statement['Resource']} for statement in statements]
                elif type(statements) == dict:
                    raw_data = {'Sid': statements['Sid'], 'Condition': {'ArnLike': {'AWS:SourceArn': statements['Condition']['ArnLike']['AWS:SourceArn']}} if 'Condition' in statements else 'null',
                                'Principal': statements['Principal'], 'Resource': statements['Resource']}
                append_data(data, 'aws lambda get-policy --function-name ' + function['FunctionName'] + ' --query \"{Policy:Policy}\"', {'Policy': raw_data})
                append_summary(data, 'Lambda 함수의 권한 정책에서 허용하는 리소스와 계정 목록입니다.\n해당 목록의 계정들이 신뢰할 수 있는 계정인지 확인하시오.')
            else:
                check = 'Y'
                append_data(data, 'aws lambda get-policy --function-name ' + function['FunctionName'] + ' --query \"{Policy:Policy}\"',
                            {'Error': 'An error occurred (ResourceNotFoundException) when calling the GetPolicy operation'})

            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '003', function['FunctionName'], check, str(data)))
        print()

    def lambda_004(self):
        print('[Lambda_004] Lambda 함수가 모든 사람에게 노출되지 않는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if low_data.function_policies[function['FunctionName']]:
                function_policy = json.loads(low_data.function_policies[function['FunctionName']])
                append_data(data, 'aws lambda get-policy --function-name ' + function['FunctionName'] + ' --query \"{Policy:Policy}\"', {'Policy': function_policy})

                filtered_statements = [statement for statement in function_policy['Statement'] if 'AWS' in statement['Principal'] and statement['Principal']['AWS'] == '*']
                for statement in filtered_statements:
                    if 'Condition' in statement:
                        if 'StringEquals' not in statement['Condition'] or 'kms:CallerAccount' not in statement['Condition']['StringEquals']:
                            append_summary(data, function['FunctionName'] + ' Lambda 함수가 모든 사람에게 노출도록 구성되어 있습니다.')
                    else:
                        append_summary(data, function['FunctionName'] + ' Lambda 함수가 모든 사람에게 노출되도록 구성되어 있습니다.')
            else:
                append_data(data, 'aws lambda get-policy --function-name ' + function['FunctionName'] + ' --query \"{Policy:Policy}\"',
                            {'Error': 'An error occurred (ResourceNotFoundException) when calling the GetPolicy operation'})

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '004', function['FunctionName'], check, str(data)))
        print()

    def lambda_005(self):
        print('[Lambda_005] Lambda 함수에 최신 버전의 런타임 환경이 사용되는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, Runtime:Runtime}}\"',
                    {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'Runtime': function['Runtime']} for function in low_data.functions]})
        append_summary(data, '각 Lambda 함수의 런타임 환경이 최신 버전의 런타임 환경을 사용하는지 확인하시오.')

        print(check, data, 'Lambda', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'Lambda', '005', 'Lambda', check, str(data)))
        print()

    def lambda_006(self):
        print('[Lambda_006] Lambda 함수에 대해 추적이 활성화되어 있는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, TracingConfig:TracingConfig}}\"',
                        {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'TracingConfig': function['TracingConfig']}]})
            if function['TracingConfig']['Mode'] != 'Active':
                append_summary(data, function['FunctionName'] + ' Lambda 함수의 추적이 활성화되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '006', function['FunctionName'], check, str(data)))
        print()

    def lambda_007(self):
        print('[Lambda_007] Lambda 함수의 환경 변수에 대해 암호화가 활성화되어 있는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, Environment:Environment}}\"',
                        {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'Environment': function['Environment'] if 'Environment' in function else 'null'}]})
            if 'Environment' in function:
                if 'Error' in function['Environment'] and function['Environment']['Error']['ErrorCode'] == 'AccessDeniedException':
                    check = 'N'
                    append_summary(data, function['FunctionName'] + ' Lambda 함수의 환경 변수가 KMS CMK로 저장중 암호화되어 있어 접근할 수 없습니다.')
                elif 'Variables' in function['Environment']:
                    check = '?'
                    append_summary(data, function['FunctionName'] + ' Lambda 환경 변수가 암호화되어 있는지 확인하시오.')

            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '007', function['FunctionName'], check, str(data)))
        print()

    def lambda_008(self):
        print('[Lambda_008] Lambda 함수의 환경 변수가 KMS CMK로 암호화하는지 확인하시오.')
        for function in low_data.functions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws lambda list-functions --query \"{Functions:Functions[*].{FunctionName:FunctionName, FunctionArn:FunctionArn, KMSKeyArn:KMSKeyArn}}\"',
                        {'Functions': [{'FunctionName': function['FunctionName'], 'FunctionArn': function['FunctionArn'], 'KMSKeyArn': function['KMSKeyArn'] if 'KMSKeyArn' in function else 'null'}]})
            if 'KMSKeyArn' not in function:
                append_summary(data, function['FunctionName'] + ' Lambda 함수의 환경 변수가 KMS CMK로 암호화되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, function['FunctionName'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'Lambda', '008', function['FunctionName'], check, str(data)))
        print()