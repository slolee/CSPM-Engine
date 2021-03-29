from Common.data import low_data, AWS_CURRENT_ID
from Common.client import *
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class CloudWatch:
    def __init__(self):
        low_data.load_cloudwatch_low_data()
        self.vlun_data = {'cli': [], 'raw_data': [], 'summary': []}
        append_data(self.vlun_data, 'aws cloudtrail describe-trails --query \"trailList[*].{Name:Name, IsMultiRegionTrail:IsMultiRegionTrail, CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn}\"',
                    {'trailList': [{'Name': trail['Name'], 'IsMultiRegionTrail': trail['IsMultiRegionTrail'], 'CloudWatchLogsLogGroupArn': trail['CloudWatchLogsLogGroupArn'] if 'CloudWatchLogsLogGroupArn' in trail else 'null'}
                                   for trail in low_data.trails if low_data.trail_status[trail['TrailARN']]['IsLogging']]})

        for log_group in low_data.log_group_on_trails:
            append_data(self.vlun_data, 'aws logs describe-metric-filters --log-group-name ' + log_group['logGroupName'] + ' --query \"{metricFilters:metricFilters[*].{filterName:filterName, filterPattern:filterPattern}}\"',
                        {'metricFilters': [{'filterName': metric_filter['filterName'], 'filterPattern': metric_filter['filterPattern']} for metric_filter in low_data.metric_filters[log_group['logGroupName']]]})

    def audit_all(self):
        self.cloudwatch_001()
        self.cloudwatch_002()
        self.cloudwatch_003()
        self.cloudwatch_004()
        self.cloudwatch_005()
        self.cloudwatch_006()
        self.cloudwatch_007()
        self.cloudwatch_008()
        self.cloudwatch_009()
        self.cloudwatch_010()
        self.cloudwatch_011()
        self.cloudwatch_012()
        self.cloudwatch_013()
        self.cloudwatch_014()
        self.cloudwatch_015()
        self.cloudwatch_016()

    def check_metric_filter(self, data, result, dictionary):
        check = 'NOT_METRIC'
        if low_data.log_group_on_trails:
            for log_group in low_data.log_group_on_trails:
                for metric_filter in low_data.metric_filters[log_group['logGroupName']]:
                    if result == cloudwatch_parse(metric_filter['filterPattern'], dictionary, False):
                        this_trail = [trail for trail in low_data.trails if 'CloudWatchLogsLogGroupArn' in trail and trail['CloudWatchLogsLogGroupArn'] == log_group['arn']][0]
                        append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, IsMultiRegionTrail:IsMultiRegionTrail, CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn}}\"',
                                    {'trailList': {'Name': this_trail['Name'], 'IsMultiRegionTrail': this_trail['IsMultiRegionTrail'], 'CloudWatchLogsLogGroupArn': this_trail['CloudWatchLogsLogGroupArn']}})
                        append_data(data, 'aws logs describe-metric-filters --log-group-name ' + log_group['logGroupName'] + ' --query \"{metricFilters:metricFilters[*].{filterName:filterName, filterPattern:filterPattern}}\"',
                                    {'metricFilters': [{'filterName': metric_filter['filterName'], 'filterPattern': metric_filter['filterPattern']}]})
                        check = 'NOT_ALARM'

                        alarms = [alarm for alarm in low_data.metric_alarms if alarm['MetricName'] in [metric_transformation['metricName'] for metric_transformation in metric_filter['metricTransformations']]]
                        if alarms:
                            append_data(data, 'aws cloudwatch describe-alarms --query \"{MetricAlarms:MetricAlarms[*].{AlarmName:AlarmName, AlarmArn:AlarmArn, AlarmActions:AlarmActions, MetricName:MetricName}}\"',
                                        {'MetricAlarms': [{'AlarmName': alarm['AlarmName'], 'AlarmArn': alarm['AlarmArn'], 'AlarmActions': alarm['AlarmActions'], 'MetricName': alarm['MetricName']} for alarm in alarms]})
                            check = 'OK'
                        else:
                            append_summary(data, '패턴과 일치하는 Metric Filter는 존재하지만, 해당 Metric Filter의 경보가 생성되어있지 않습니다.')
        else:
            append_summary(data, '관리 이벤트를 기록해 CloudWatch Logs로 전송하는 활성화된 Trail이 존재하지 않습니다.')
        return check

    def cloudwatch_001(self):
        print('[CloudWatch_001] AWS 계정 Root 사용자의 사용을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS || $.eventType != "AwsServiceEvent" }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'].extend(self.vlun_data['cli'])
                data['raw_data'].extend(self.vlun_data['raw_data'])
            append_summary(data, 'AWS 계정 Root 사용자의 사용을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '001', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_002(self):
        print('[CloudWatch_002] 인증되지 않은 API 호출을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, '인증되지 않은 API 호출을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '002', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_003(self):
        print('[CloudWatch_003] AWS Management Console에 MFA 인증 없이 로그인하는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS Management Console에 MFA 인증 없이 로그인하는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '003', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_004(self):
        print('[CloudWatch_004] AWS Management Console에 인증실패를 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS Management Console에 인증실패를 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '004', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_005(self):
        print('[CloudWatch_005] AWS 계정에 IAM 구성이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = AddUserToGroup) || ($.eventName = AttachGroupPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = AttachUserPolicy) ' \
                        '|| ($.eventName = ChangePassword) || ($.eventName = CreateAccessKey) || ($.eventName = CreateAccountAlias) || ($.eventName = CreateGroup) ' \
                        '|| ($.eventName = CreateLoginProfile) || ($.eventName = CreateOpenIDConnectProvider) || ($.eventName = CreatePolicy) || ($.eventName = CreatePolicyVersion) ' \
                        '|| ($.eventName = CreateRole) || ($.eventName = CreateSAMLProvider) || ($.eventName = CreateServiceLinkedRole) || ($.eventName = CreateServiceSpecificCredential) ' \
                        '|| ($.eventName = CreateUser) || ($.eventName = CreateVirtualMFADevice) || ($.eventName = DeactivateMFADevice) || ($.eventName = DeleteAccessKey) ' \
                        '|| ($.eventName = DeleteAccountAlias) || ($.eventName = DeleteAccountPasswordPolicy) || ($.eventName = DeleteGroup) || ($.eventName = DeleteGroupPolicy) ' \
                        '|| ($.eventName = DeleteLoginProfile) || ($.eventName = DeleteOpenIDConnectProvider) || ($.eventName = DeletePolicy) || ($.eventName = DeletePolicyVersion) ' \
                        '|| ($.eventName = DeleteRole) || ($.eventName = DeleteRolePermissionsBoundary) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteSAMLProvider) ' \
                        '|| ($.eventName = DeleteServerCertificate) || ($.eventName = DeleteServiceLinkedRole) || ($.eventName = DeleteServiceSpecificCredential) ' \
                        '|| ($.eventName = DeleteSigningCertificate) || ($.eventName = DeleteSSHPublicKey) || ($.eventName = DeleteUser) || ($.eventName = DeleteUserPermissionsBoundary) ' \
                        '|| ($.eventName = DeleteUserPolicy) || ($.eventName = DeleteVirtualMFADevice) || ($.eventName = DetachGroupPolicy) || ($.eventName = DetachRolePolicy) ' \
                        '|| ($.eventName = DetachUserPolicy) || ($.eventName = EnableMFADevice) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePermissionsBoundary) ' \
                        '|| ($.eventName = PutRolePolicy) || ($.eventName = PutUserPermissionsBoundary) || ($.eventName = PutUserPolicy) || ($.eventName = RemoveClientIDFromOpenIDConnectProvider) ' \
                        '|| ($.eventName = RemoveUserFromGroup) || ($.eventName = ResetServiceSpecificCredential) || ($.eventName = SetDefaultPolicyVersion) || ($.eventName = UpdateAccessKey) ' \
                        '|| ($.eventName = UpdateAccountPasswordPolicy) || ($.eventName = UpdateAssumeRolePolicy) || ($.eventName = UpdateGroup) || ($.eventName = UpdateLoginProfile) ' \
                        '|| ($.eventName = UpdateOpenIDConnectProviderThumbprint) || ($.eventName = UpdateRole) || ($.eventName = UpdateSAMLProvider) || ($.eventName = UpdateServerCertificate) ' \
                        '|| ($.eventName = UpdateServiceSpecificCredential) || ($.eventName = UpdateSigningCertificate) || ($.eventName = UpdateSSHPublicKey) || ($.eventName = UpdateUser) ' \
                        '|| ($.eventName = UploadServerCertificate) || ($.eventName = UploadSigningCertificate) || ($.eventName = UploadSSHPublicKey) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS 계정에 IAM 구성이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '005', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_006(self):
        print('[CloudWatch_006] CloudTrail 설정이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'CloudTrail 설정이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '006', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_007(self):
        print('[CloudWatch_007] VPC가 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) ' \
                        '|| ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) ' \
                        '|| ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'VPC가 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '007', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_008(self):
        print('[CloudWatch_008] 보안 그룹이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) ' \
                        '|| ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, '보안 그룹이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '008', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_009(self):
        print('[CloudWatch_009] NACL(Network Access Control List)가 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) ' \
                        '|| ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'NACL(Network Access Control List)가 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '009', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_010(self):
        print('[CloudWatch_010] Route Table이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) ' \
                        '|| ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'Route Table이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '010', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_011(self):
        print('[CloudWatch_011] Network Gateway(Internet Gateway, NAT Gateway 등)가 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) ' \
                        '|| ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'Network Gateway(Internet Gateway, NAT Gateway 등)가 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '011', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_012(self):
        print('[CloudWatch_012] Amazon EC2 인스턴스의 상태가 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) ' \
                        '|| ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'Amazon EC2 인스턴스의 상태가 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '012', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_013(self):
        print('[CloudWatch_013] Amazon S3 Bucket 구성이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) ' \
                        '|| ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) ' \
                        '|| ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'Amazon S3 Bucket 구성이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '013', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_014(self):
        print('[CloudWatch_014] AWS KMS 구성이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventSource = kms.amazonaws.com) && (($.eventName = CreateAlias) || ($.eventName = CreateGrant) || ($.eventName = CreateKey) ' \
                        '|| ($.eventName = EnableKey) || ($.eventName = EnableKeyRotation) || ($.eventName = ImportKeyMaterial) || ($.eventName = PutKeyPolicy) ' \
                        '|| ($.eventName = RetireGrant) || ($.eventName = RevokeGrant) || ($.eventName = ScheduleKeyDeletion) || ($.eventName = TagResource) ' \
                        '|| ($.eventName = UntagResource) || ($.eventName = UpdateAlias) || ($.eventName = UpdateKeyDescription) || ($.eventName = DisableKey) ' \
                        '|| ($.eventName = DisableKeyRotation) || ($.eventName = CancelKeyDeletion) || ($.eventName = DeleteAlias) || ($.eventName = DeleteImportedKeyMaterial)) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS KMS 구성이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '014', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_015(self):
        print('[CloudWatch_015] AWS Config 설정이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) ' \
                        '|| ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS Config 설정이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '015', 'CloudWatch', check, str(data)))
        print()

    def cloudwatch_016(self):
        print('[CloudWatch_016] AWS Organization이 변경되는 것을 모니터링하고 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        dictionary = {}
        metric_filter = '{ ($.eventSource = organizations.amazonaws.com) && ($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) ' \
                        '|| ($.eventName = CancelHandshake) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganization) || ($.eventName = CreateOrganizationalUnit) ' \
                        '|| ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) ' \
                        '|| ($.eventName = DeletePolicy) || ($.eventName = EnableAllFeatures) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) ' \
                        '|| ($.eventName = LeaveOrganization) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = MoveAccount) ' \
                        '|| ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdateOrganizationalUnit) || ($.eventName = UpdatePolicy) }'
        result = cloudwatch_parse(metric_filter, dictionary)
        check_result = self.check_metric_filter(data, result, dictionary)
        if check_result != 'OK':
            if check_result == 'NOT_METRIC':
                data['cli'] = self.vlun_data['cli']
                data['raw_data'] = self.vlun_data['raw_data']
            append_summary(data, 'AWS Organization이 변경되는 것을 모니터링하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'CloudWatch', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'CloudWatch', '016', 'CloudWatch', check, str(data)))
        print()

