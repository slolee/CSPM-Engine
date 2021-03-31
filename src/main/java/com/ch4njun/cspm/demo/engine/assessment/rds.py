from Common.data import low_data
from Common.client import *
from Common.utils import *
from Common.db_profile import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class RDS:
    def __init__(self):
        low_data.load_rds_low_data()

    def audit_all(self):
        self.rds_001()
        self.rds_002()
        self.rds_003()
        self.rds_004()
        self.rds_005()
        self.rds_006()
        self.rds_007()
        self.rds_008()
        self.rds_009()
        self.rds_010()
        self.rds_011()
        self.rds_012()
        self.rds_013()
        self.rds_014()
        self.rds_015()
        self.rds_016()
        self.rds_017()
        self.rds_018()
        self.rds_019()
        self.rds_020()
        self.rds_021()
        self.rds_022()
        self.rds_023()
        self.rds_024()

    def rds_001(self):
        print('[RDS_001] IAM 데이터베이스 인증 기능이 활성화되어 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, IAMDatabaseAuthenticationEnabled:IAMDatabaseAuthenticationEnabled}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'IAMDatabaseAuthenticationEnabled': db_instance['IAMDatabaseAuthenticationEnabled']})
            if not db_instance['IAMDatabaseAuthenticationEnabled']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 IAM 데이터베이스 인증 기능이 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '001', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_002(self):
        print('[RDS_002] DB 스냅샷에 퍼블릭으로 액세스할 수 없는지 확인하시오.')
        for db_snapshot in low_data.db_snapshots:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-snapshot-attributes --db-snapshot-identifier ' + db_snapshot['DBSnapshotIdentifier'] + ' --query \"DBSnapshotAttributesResult.{DBSnapshotAttributes:DBSnapshotAttributes}\"',
                        {'DBSnapshotAttributes': low_data.db_snapshot_attributes[db_snapshot['DBSnapshotIdentifier']]})
            if [db_snapshot_attribute for db_snapshot_attribute in low_data.db_snapshot_attributes[db_snapshot['DBSnapshotIdentifier']] if 'all' in db_snapshot_attribute['AttributeValues']]:
                append_summary(data, db_snapshot['DBInstanceIdentifier'] + ' 인스턴스의 스냅샷 ' + db_snapshot['DBSnapshotIdentifier'] + ' 가 퍼블릭으로 액세스 할 수 있도록 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_snapshot['DBSnapshotIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '002', db_snapshot['DBSnapshotIdentifier'], db_snapshot['DBSnapshotArn'], check, str(data)))
        print()

    def rds_003(self):
        print('[RDS_003] AWS RDS 리소스에 이벤트 알림이 활성화되어 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        append_data(data, 'aws rds describe-event-subscriptions', {'EventSubscriptionList': low_data.event_subscriptions})
        if not low_data.event_subscriptions or not [event_subscription for event_subscription in low_data.event_subscriptions if event_subscription['Enabled']]:
            append_summary(data, 'AWS RDS 리소스에 활성화되어있는 이벤트 알림이 없습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        print(check, data, 'RDS', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'RDS', '003', 'RDS', 'RDS', check, str(data)))
        print()

    def rds_004(self):
        print('[RDS_004] DB 보안 그룹 이벤트에 대해 RDS 이벤트 알림 구독이 활성화되어 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        db_security_group_event = [event_subscription for event_subscription in low_data.event_subscriptions
                                   if event_subscription['Enabled'] and event_subscription['SourceType'] == 'db-security-group']
        if not db_security_group_event:
            append_data(data, 'aws rds describe-event-subscriptions', {'EventSubscriptionList': low_data.event_subscriptions})
            append_summary(data, 'DB 보안 그룹 이벤트에 대한 활성화된 RDS 이벤트 알림 구독이 없습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        else:
            append_data(data, 'aws rds describe-event-subscriptions', {'EventSubscriptionList': db_security_group_event})
        print(check, data, 'RDS', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'RDS', '004', 'RDS', 'RDS', check, str(data)))
        print()

    def rds_005(self):
        print('[RDS_005] DB 인스턴스 수준 이벤트에 대해 RDS 이벤트 알림 구독이 활성화되어 있는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        db_instance_event = [event_subscription for event_subscription in low_data.event_subscriptions
                             if event_subscription['Enabled'] and event_subscription['SourceType'] == 'db-instance']
        if not db_instance_event:
            append_data(data, 'aws rds describe-event-subscriptions', {'EventSubscriptionList': low_data.event_subscriptions})
            append_summary(data, 'DB 인스턴스 수준 이벤트에 대한 활성화된 RDS 이벤트 알림 구독이 없습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        else:
            append_data(data, 'aws rds describe-event-subscriptions', {'EventSubscriptionList': db_instance_event})
        print(check, data, 'RDS', sep='\n')
        execute_insert_sql((low_data.diagnosis_id, 'RDS', '005', 'RDS', 'RDS', check, str(data)))
        print()

    def rds_006(self):
        print('[RDS_006] RDS 인스턴스의 삭제 방지 기능이 활성화되어있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, DeletionProtection:DeletionProtection}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'DeletionProtection': db_instance['DeletionProtection']})
            if not db_instance['DeletionProtection']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 의 삭제 방지 기능이 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '006', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_007(self):
        print('[RDS_007] RDS 인스턴스가 다중 AZ 배포 구성을 사용하고 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, MultiAZ:MultiAZ}\"',
                        {'DBClusterIdentifier': db_instance['DBInstanceIdentifier'], 'MultiAZ': db_instance['MultiAZ']})
            if not db_instance['MultiAZ']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 다중 AZ 배포 구성을 사용하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '007', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_008(self):
        print('[RDS_008] RDS 인스턴스에 Storage AutoScaling 기능이 활성화되어 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, DeletionProtection:DeletionProtection}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'MaxAllocatedStorage': db_instance['MaxAllocatedStorage'] if 'MaxAllocatedStorage' in db_instance else 'null'})
            if 'MaxAllocatedStorage' not in db_instance:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 Storage AutoScaling 기능이 비활성화되어 있습니다.\n')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '008', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_009(self):
        print('[RDS_009] 디스크 공간이 부족한 것으로 보이는 RDS DB 인스턴스를 식별하고 이를 확장하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            if db_instance['DBInstanceStatus'] == 'available':
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                try:
                    get_metric_statistics = client.cloudwatch_client.get_metric_statistics(MetricName='FreeStorageSpace', StartTime=db_instance['InstanceCreateTime'],
                                                                                EndTime=datetime.datetime.now(), Period=3600, Namespace='AWS/RDS', Statistics=['Maximum'],
                                                                                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}])
                    threshold = (db_instance['AllocatedStorage'] * 1024 * 1024 * 1024) * 0.1
                    check_metric_statistics = [metric_statistic for metric_statistic in get_metric_statistics['Datapoints'] if metric_statistic['Maximum'] < threshold]
                    append_data(data, 'aws cloudwatch get-metric-statistics --metric-name FreeStorageSpace --start-time ' + db_instance['InstanceCreateTime'].strftime('%Y-%m-%dT%H:%M:%S') + ' --end-time ' + \
                                datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S') + ' --period 3600 --namespace AWS/RDS --statistics Maximum --dimensions Name=DBInstanceIdentifier,Value=' + db_instance['DBInstanceIdentifier'],
                                {'Label': 'FreeStorageSpace', 'Datapoints': check_metric_statistics})
                    if check_metric_statistics:
                        summary = db_instance['DBInstanceIdentifier'] + ' 인스턴스의 디스크 공간이 부족합니다.\n'
                        for check_metric_statistic in check_metric_statistics:
                            summary += str(check_metric_statistic['Timestamp']) + ' 에 잔여 디스크 공간 : ' + str(check_metric_statistic['Maximum']) + 'byte\n'
                        append_summary(data, summary)

                    if len(data['summary']) > 0:
                        check = 'N'
                except ClientError as e:
                    append_data(data, 'aws cloudwatch get-metric-statistics --metric-name FreeStorageSpace --start-time ' + db_instance['InstanceCreateTime'].strftime('%Y-%m-%dT%H:%M:%S') + ' --end-time ' + \
                                datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S') + ' --period 3600 --namespace AWS/RDS --statistics Maximum --dimensions Name=DBInstanceIdentifier,Value=' + db_instance['DBInstanceIdentifier'],
                                {'Error': 'An error occurred (AccessDenied) when calling the GetMetricStatistics operation'})
                    append_summary(data, '해당 항목을 확인하려면 \"GetMetricStatistics\" 권한을 부여해야 합니다.')
                    check = '?'

                print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'RDS', '009', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_010(self):
        print('[RDS_010] RDS 인스턴스가 범용 SSD를 사용하고 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, StorageType:StorageType}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'StorageType': db_instance['StorageType']})
            if db_instance['StorageType'] != 'gp2':
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 범용 SSD(gp2)를 사용하고있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '010', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_011(self):
        print('[RDS_011] RDS 인스턴스가 Data-tier를 위한 보안그룹을 사용하도록 구성되어 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = '?'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, VpcSecurityGroups:VpcSecurityGroups}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'VpcSecurityGroups': db_instance['VpcSecurityGroups']})
            append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에 연결된 보안그룹 ' + str([vpc_security_group['VpcSecurityGroupId'] for vpc_security_group in db_instance['VpcSecurityGroups']]) + ' 가 Data-tier를 위한 보안그룹인지 확인하시오.')

            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '011', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_012(self):
        print('[RDS_012] 과도하게 사용되는 것으로 보이는 RDS DB 인스턴스를 식별하고 업그레이드하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            if db_instance['DBInstanceStatus'] == 'available':
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                try:
                    get_metric_statistics = client.cloudwatch_client.get_metric_statistics(MetricName='CPUUtilization', StartTime=db_instance['InstanceCreateTime'],
                                                                                    EndTime=datetime.datetime.now(), Period=86400, Namespace='AWS/RDS', Statistics=['Average'],
                                                                                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}])
                    check_metric_statistics = [metric_statistic for metric_statistic in get_metric_statistics['Datapoints'] if metric_statistic['Average'] > 90]
                    append_data(data, 'aws cloudwatch get-metric-statistics --metric-name CPUUtilization --start-time ' + db_instance['InstanceCreateTime'].strftime('%Y-%m-%dT%H:%M:%S') + ' --end-time ' + \
                                datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S') + ' --period 86400 --namespace AWS/RDS --statistics Average --dimensions Name=DBInstanceIdentifier,Value=' + db_instance['DBInstanceIdentifier'],
                                {'Label': 'CPUUtilization', 'Datapoints': check_metric_statistics})
                    if check_metric_statistics:
                        summary = db_instance['DBInstanceIdentifier'] + ' 인스턴스가 과도하게 사용된 기록이 있습니다.\n'
                        for check_metric_statistic in check_metric_statistics:
                            summary += str(check_metric_statistic['Timestamp']) + ' 에 CPU 사용량 : ' + str(check_metric_statistic['Average']) + '%\n'
                        append_summary(data, summary)

                    if len(data['summary']) > 0:
                        check = 'N'
                except ClientError as e:
                    append_data(data, 'aws cloudwatch get-metric-statistics --metric-name CPUUtilization --start-time ' + db_instance['InstanceCreateTime'].strftime('%Y-%m-%dT%H:%M:%S') + ' --end-time ' + \
                                datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S') + ' --period 86400 --namespace AWS/RDS --statistics Average --dimensions Name=DBInstanceIdentifier,Value=' + db_instance['DBInstanceIdentifier'],
                                {'Error': 'An error occurred (AccessDenied) when calling the GetMetricStatistics operation'})
                    append_summary(data, '해당 항목을 확인하려면 \"GetMetricStatistics\" 권한을 부여해야 합니다.')
                    check = '?'
                print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'RDS', '012', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_013(self):
        print('[RDS_013] Amazon RDS의 암호를 자동으로 교체하도록 AWS Secrets Manager를 구성하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            flag = False
            if 'Error' in low_data.secret_values:
                append_data(data, 'aws secretsmanager get-secret-value --secret-id [SECRET_ARN] --query \"{SecretString:SecretString}\"',
                            {'Error': 'An error occurred (AccessDeniedException) when calling the GetSecretValue operation'})
                append_summary(data, '해당 항목을 확인하려면 \"GetSecretValue\" 권한을 부여해야 합니다.')
                check = '?'
            else:
                for secret in low_data.secrets:
                    secret_string = json.loads(low_data.secret_values[secret['ARN']])
                    if db_instance['DBInstanceIdentifier'] == secret_string['dbInstanceIdentifier']:
                        append_data(data, 'aws secretsmanager get-secret-value --secret-id ' + secret['ARN'] + ' --query \"{SecretString:SecretString}\"',
                                    {'SecretString': {'dbInstanceIdentifier': secret_string['dbInstanceIdentifier'], 'engine': secret_string['engine']}})
                        flag = True

                if not flag:
                    for secret in low_data.secrets:
                        secret_string = json.loads(low_data.secret_values[secret['ARN']])
                        append_data(data, 'aws secretsmanager get-secret-value --secret-id ' + secret['ARN'] + ' --query \"{SecretString:SecretString}\"',
                                    {'SecretString': {'dbInstanceIdentifier': secret_string['dbInstanceIdentifier'], 'engine': secret_string['engine']}})
                    append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 암호를 자동으로 교체하도록 AWS Secret Manager를 구성하지 않았습니다.')
                    check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '013', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    # aurora-mysql, mysql, mariadb, oracle-ee, oracle-se, oracle-se1, oracle-se2, sqlserver-ee, sqlserver-web, sqlserver-se, sqlserver-ex : admin
    # aurora-postgres, postgres : postgres
    def rds_014(self):
        print('[RDS_014] RDS 프로덕션 DB가 사용 된 RDS DB 엔진 유형의 마스터 사용자 이름을 기본값으로 사용하지 않는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, MasterUsername:MasterUsername}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'MasterUsername': db_instance['MasterUsername']})
            if db_instance['MasterUsername'] in ['postgres', 'awsuser', 'admin']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 마스터 사용자 이름이 기본 값(' + db_instance['MasterUsername'] + ' )으로 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '014', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_015(self):
        print('[RDS_015] DB 인스턴스에서 SSL/TLS 연결을 사용하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if db_instance['Engine'] in ['postgres', 'sqlserver-ex', 'sqlserver-ee', 'sqlserver-se', 'sqlserver-web']:
                append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                            ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, Engine:Engine, DBParameterGroups:DBParameterGroups}\"',
                            {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'Engine': db_instance['Engine'], 'DBParameterGroups': db_instance['DBParameterGroups']})
                for db_parameter_group in db_instance['DBParameterGroups']:
                    rds_force_ssl = [db_parameter for db_parameter in low_data.db_parameters[db_parameter_group['DBParameterGroupName']]
                                     if db_parameter['ParameterName'] == 'rds.force_ssl']
                    append_data(data, 'aws rds describe-db-parameters --db-parameter-group-name ' + db_parameter_group['DBParameterGroupName'] +
                                ' --query \"{Parameters:Parameters[*].{ParameterName:ParameterName, ParameterValue:ParameterValue}}\"',
                                {'Parameters': [{'ParameterName': rds_force_ssl[0]['ParameterName'], 'ParameterValue': (rds_force_ssl[0]['ParameterValue'] if 'ParameterValue' in rds_force_ssl[0] else 'null')}]})
                    if rds_force_ssl and 'ParameterValue' in rds_force_ssl[0] and rds_force_ssl[0]['ParameterValue'] == '0':
                        append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 SSL/TLS 연결을 사용하지 않습니다.')
            elif db_instance['Engine'] in ['oracle-ee', 'oracle-se', 'oracle-se1', 'oracle-se2']:
                append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                            ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, Engine:Engine, OptionGroupMemberships:OptionGroupMemberships}\"',
                            {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'Engine': db_instance['Engine'], 'OptionGroupMemberships': db_instance['OptionGroupMemberships']})

                flag = False
                for db_option_group in db_instance['OptionGroupMemberships']:
                    describe_option_groups = client.rds_client.get_paginator('describe_option_groups').paginate(OptionGroupName=db_option_group['OptionGroupName'])
                    options = [option_group for option_groups in describe_option_groups for option_group in option_groups['OptionGroupsList']][0]['Options']

                    append_data(data, 'aws rds describe-option-groups --option-group-name ' + db_option_group['OptionGroupName'] +
                                ' --query \"{OptionGroupsList:OptionGroupsList[*].{OptionGroupName:OptionGroupName, Options:Options[*].{OptionName:OptionName, OptionSettings:OptionSettings[*].{Name:Name, Value:Value}}}}\"',
                                {'OptionGroupsList': [{'OptionGroupName': db_option_group['OptionGroupName'],
                                                       'Options': [{'OptionName': option['OptionName'], 'OptionSettings': [{'Name': option_settings['Name'], 'Value': option_settings['Value']}
                                                                                                                           for option_settings in option['OptionSettings']]} for option in options]}]})
                    for option in options:
                        if option['OptionName'] == 'SSL':
                            for option_setting in option['OptionSettings']:
                                if option_setting['Name'] == 'FIPS.SSLFIPS_140' and option_setting['Value']:
                                    flag = True
                if not flag:
                    append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 SSL/TLS 연결을 사용하지 않습니다.')
            else:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 엔진 ' + db_instance['Engine'] + ' 에는 SSL/TLS 활성화여부를 확인하는 별도의 설정이 없습니다.\nRDS_016 항목의 결과를 확인하시오.')
            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '015', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_016(self):
        print('[RDS_016] DB 인스턴스에서 TLS(전송 보안 계층) 버전 1.1 이상을 사용하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            if db_instance['Engine'] in ['oracle-ee', 'oracle-se', 'oracle-se1', 'oracle-se2']:
                append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                            ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, Engine:Engine, OptionGroupMemberships:OptionGroupMemberships}\"',
                            {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'Engine': db_instance['Engine'], 'OptionGroupMemberships': db_instance['OptionGroupMemberships']})

                flag = False
                for db_option_group in db_instance['OptionGroupMemberships']:
                    describe_option_groups = client.rds_client.get_paginator('describe_option_groups').paginate(OptionGroupName=db_option_group['OptionGroupName'])
                    options = [option_group for option_groups in describe_option_groups for option_group in option_groups['OptionGroupsList']][0]['Options']

                    append_data(data, 'aws rds describe-option-groups --option-group-name ' + db_option_group['OptionGroupName'] +
                                ' --query \"{OptionGroupsList:OptionGroupsList[*].{OptionGroupName:OptionGroupName, Options:Options[*].{OptionName:OptionName, OptionSettings:OptionSettings[*].{Name:Name, Value:Value}}}}\"',
                                {'OptionGroupsList': [{'OptionGroupName': db_option_group['OptionGroupName'],
                                                       'Options': [{'OptionName': option['OptionName'], 'OptionSettings': [{'Name': option_settings['Name'], 'Value': option_settings['Value']}
                                                                                                                           for option_settings in option['OptionSettings']]} for option in options]}]})
                    for option in options:
                        if option['OptionName'] == 'SSL':
                            for option_setting in option['OptionSettings']:
                                if option_setting['Name'] == 'SQLNET.SSL_VERSION' and option_setting['Value'] == '1.2':
                                    flag = True
                if not flag:
                    append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 TLS 버전 1.1 미만의 사용을 허용하도록 구성되어 있습니다.')
            else:
                append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                            ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, DBParameterGroups:DBParameterGroups, Engine:Engine}\"',
                            {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'DBParameterGroups': db_instance['DBParameterGroups'], 'Engine': db_instance['Engine']})
                for db_parameter_group in db_instance['DBParameterGroups']:
                    # aurora, mysql, mariadb - tls_version
                    if db_instance['Engine'] in ['aurora', 'aurora-mysql', 'mysql', 'mariadb']:
                        tls_version = [db_parameter for db_parameter in low_data.db_parameters[db_parameter_group['DBParameterGroupName']]
                                       if db_parameter['ParameterName'] == 'tls_version']
                        append_data(data, 'aws rds describe-db-parameters --db-parameter-group-name ' + db_parameter_group['DBParameterGroupName'] + ' --query \"Parameters[*].{ParameterName:ParameterName, ParameterValue:ParameterValue}\"',
                                    {'ParameterName': tls_version[0]['ParameterName'], 'ParameterValue': (tls_version[0]['ParameterValue'] if 'ParameterValue' in tls_version[0] else 'null')})
                        if tls_version:
                            if 'ParameterValue' not in tls_version[0] or 'TLSv1' in tls_version[0]['ParameterValue'].split(','):
                                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 TLS 버전 1.1 미만의 사용을 허용하도록 구성되어 있습니다.')
                        else:
                             append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에 연결된 파라미터 그룹 ' + db_parameter_group['DBParameterGroupName'] + \
                                            ' 에 tls_version 파라미터가 없습니다.')
                    # postgres - ssl_min_protocol_version
                    elif db_instance['Engine'] in ['aurora-postgres', 'postgres']:
                        ssl_min_protocol_version = [db_parameter for db_parameter in low_data.db_parameters[db_parameter_group['DBParameterGroupName']]
                                                    if db_parameter['ParameterName'] == 'ssl_min_protocol_version']
                        append_data(data, 'aws rds describe-db-parameters --db-parameter-group-name ' + db_parameter_group['DBParameterGroupName'] + ' --query \"Parameters[*].{ParameterName:ParameterName, ParameterValue:ParameterValue}\"',
                                    {'ParameterName': ssl_min_protocol_version[0]['ParameterName'], 'ParameterValue': (ssl_min_protocol_version[0]['ParameterValue'] if 'ParameterValue' in ssl_min_protocol_version[0] else 'null')})
                        if ssl_min_protocol_version:
                            if 'ParameterValue' not in ssl_min_protocol_version[0] or 'TLSv1' in ssl_min_protocol_version[0]['ParameterValue'].split(','):
                                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 TLS 버전 1.1 미만의 사용을 허용하도록 구성되어 있습니다.')
                        else:
                            append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에 연결된 파라미터 그룹 ' + db_parameter_group['DBParameterGroupName'] + ' 에 ssl_min_protocol_version 파라미터가 없습니다.')
                    # sqlserver - rds_tls10, rds_tls11, rds_tls12
                    elif db_instance['Engine'] in ['sqlserver-ex', 'sqlserver-ee', 'sqlserver-web', 'sqlserver-se']:
                        rds_tls = [db_parameter for db_parameter in low_data.db_parameters[db_parameter_group['DBParameterGroupName']]
                                   if db_parameter['ParameterName'] in ['rds_tls10', 'rds_tls11', 'rds_tls12']]
                        append_data(data, 'aws rds describe-db-parameters --db-parameter-group-name ' + db_parameter_group['DBParameterGroupName'] + ' --query \"Parameters[*].{ParameterName:ParameterName, ParameterValue:ParameterValue}\"',
                                    {'Parameters': [{'ParameterName': rds_tls_tmp['ParameterName'], 'ParameterValue': (rds_tls_tmp['ParameterValue'] if 'ParameterValue' in rds_tls_tmp else 'null')} for rds_tls_tmp in rds_tls]})
                        if rds_tls:
                            if rds_tls[0]['ParameterValue'] in ['default', 'enabled']:
                                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 TLS 버전 1.1 미만의 사용을 허용하도록 구성되어 있습니다.')
                            elif rds_tls[1]['ParameterValue'] == 'disabled' and rds_tls[2]['ParameterValue'] == 'disabled':
                                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에서 TLS 버전 1.1 이상의 사용을 허용하지 않록 구성되어 있습니다.')
                        else:
                            append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에 연결된 파라미터 그룹 ' + db_parameter_group['DBParameterGroupName'] + \
                                           ' 에 tls_tls10, rds_tls11, rds_tls12 파라미터가 없습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '016', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_017(self):
        print('[RDS_017] DB 인스턴스에 로그 내보내기 기능이 활성화되어 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, Engine:Engine, EngineVersion:EngineVersion, EnabledCloudwatchLogsExports:EnabledCloudwatchLogsExports}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'Engine': db_instance['Engine'], 'EngineVersion': db_instance['EngineVersion'],
                         'EnabledCloudwatchLogsExports': db_instance['EnabledCloudwatchLogsExports'] if 'EnabledCloudwatchLogsExports' in db_instance else 'null'})

            if 'EnabledCloudwatchLogsExports' not in db_instance:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 로그 내보내기 기능이 비활성화되어 있습니다.')
            else:
                if db_instance['Engine'] in ['mysql', 'aurora', 'aurora-mysql', 'mariadb']:
                    exports = []
                    if not (db_instance['Engine'] == 'mysql' and db_instance['EngineVersion'].startswith('8.0')):
                        if 'audit' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('감사로그')
                    if 'error' not in db_instance['EnabledCloudwatchLogsExports']:
                        exports.append('에러로그')
                    if 'general' not in db_instance['EnabledCloudwatchLogsExports']:
                        exports.append('일반로그')
                    if 'slowquery' not in db_instance['EnabledCloudwatchLogsExports']:
                        exports.append('느린쿼리로그')
                    if exports:
                        append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 ' + ', '.join(exports) + ' 내보내기 기능이 비활성화되어 있습니다.')
                elif db_instance['Engine'] in ['postgres', 'aurora-postgres']:
                    if len(db_instance['EnabledCloudwatchLogsExports']) < 1:
                        exports = []
                        if 'postgresql' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('Postgresql 로그')
                        if db_instance['Engine'] == 'postgres' and db_instance['EngineVersion'].startswith('8.0'):
                            exports.append('업그레이드 로그')
                        if exports:
                            append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 ' + ', '.join(exports) + ' 내보내기 기능이 비활성화되어 있습니다.')
                elif db_instance['Engine'] in ['oracle-ee', 'oracle-se', 'oracle-se1', 'oracle-se2']:
                    if len(db_instance['EnabledCloudwatchLogsExports']) < 5:
                        exports = []
                        if 'alert' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('알림로그')
                        if 'audit' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('감사로그')
                        if 'listener' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('리스너로그')
                        if 'oemagent' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('oemagent로그')
                        if 'trace' not in db_instance['EnabledCloudwatchLogsExports']:
                            exports.append('추적로그')
                        if exports:
                            append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 ' + ', '.join(exports) + ' 내보내기 기능이 비활성화되어 있습니다.')
            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '014', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_018(self):
        print('[RDS_018] RDS DB 인스턴스가 최소 백업 보존 기간을 설정했는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, EnabledCloudwatchLogsExports:EnabledCloudwatchLogsExports}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'BackupRetentionPeriod': db_instance['BackupRetentionPeriod'] if 'BackupRetentionPeriod' in db_instance else 'null'})
            if 'BackupRetentionPeriod' not in db_instance or db_instance['BackupRetentionPeriod'] == 0:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스에 최소 백업 보존 기간이 설정되지 않거나 0일로 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '018', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_019(self):
        print('[RDS_019] MySQL 호환성 데이터베이스 클러스터가있는 Amazon Aurora에 역 추적 기능이 활성화되어 있는지 확인하시오.')
        for db_cluster in low_data.db_clusters:
            if db_cluster['Engine'] in ['aurora', 'aurora-mysql']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws rds describe-db-clusters --filter Name=db-cluster-id,Values=' + db_cluster['DBClusterIdentifier'] + \
                            ' --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier, Engine:Engine, BacktrackWindow:BacktrackWindow}\"',
                            {'DBClusterIdentifier': db_cluster['DBClusterIdentifier'], 'Engine': db_cluster['Engine'], 'BacktrackWindow': db_cluster['BacktrackWindow']})
                if db_cluster['BacktrackWindow'] == 0:
                    append_summary(data, db_cluster['DBClusterIdentifier'] + ' 클러스터에 역 추적 기능이 비활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                print(check, data, db_cluster['DBClusterIdentifier'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'RDS', '019', db_cluster['DBClusterIdentifier'], db_cluster['DBClusterArn'], check, str(data)))
        print()

    def rds_020(self):
        print('[RDS_020] RDS DB 인스턴스의 스냅샷을 Amazon Backup 서비스를 사용해 관리하는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            flag = False
            if 'Error' in low_data.backup_selections:
                if [backup_plan for backup_plan in low_data.backup_plans if 'Error' in backup_plan]:
                    append_data(data, 'aws backup list-backup-plans --query \"{BackupPlansList:BackupPlansList[*].{BackupPlanArn:BackupPlanArn, BackupPlanId:BackupPlanId}}\"',
                                {'Error': 'An error occurred (AccessDeniedException) when calling the ListBackupPlans operation'})
                    append_summary(data, '해당 항목을 확인하려면 \"ListBackupPlans\" 권한을 부여해야 합니다.')
                append_data(data, 'aws backup list-backup-selections --backup-plan-id [PLAN_ID] '
                                  '--query \"{BackupSelectionsList:BackupSelectionsList[*].{SelectionId:SelectionId, BackupPlanId:BackupPlanId}}\"',
                            {'Error': 'An error occurred (AccessDeniedException) when calling the ListBackupSelections operation'})
                append_summary(data, '해당 항목을 확인하려면 \"ListBackupSelections\" 권한을 부여해야 합니다.')
                append_data(data, 'aws backup get-backup-selection --backup-plan-id [PLAN_ID] --selection-id [SELECTION_ID] '
                                  '--query \"{BackupSelection:BackupSelection, BackupPlanId:BackupPlanId, SelectionId:SelectionId}\"',
                            {'Error': 'An error occurred (AccessDeniedException) when calling the GetBackupSelection operation'})
                append_summary(data, '해당 항목을 확인하려면 \"GetBackupSelection\" 권한을 부여해야 합니다.')
                check = '?'
            else:
                for backup_selection in low_data.backup_selections.keys():
                    if db_instance['DBInstanceArn'] in low_data.backup_selections[backup_selection]['BackupSelection']['Resources']:
                        append_data(data, 'aws backup get-backup-selection --backup-plan-id ' + low_data.backup_selections[backup_selection]['BackupPlanId'] + \
                                    ' --selection-id ' + low_data.backup_selections[backup_selection]['SelectionId'] + \
                                    '--query \"{BackupSelection:BackupSelection, BackupPlanId:BackupPlanId, SelectionId:SelectionId}\"', low_data.backup_selections[backup_selection])
                        flag = True

                if not flag:
                    append_data(data, 'aws backup list-backup-plans --query \"{BackupPlansList:BackupPlansList[*].{BackupPlanArn:BackupPlanArn, BackupPlanId:BackupPlanId}}\"',
                                {'BackupPlansList': [{'BackupPlanArn': backup_plan['BackupPlanArn'], 'BackupPlanId': backup_plan['BackupPlanId']} for backup_plan in low_data.backup_plans]})
                    for backup_plan in low_data.backup_plans:
                        append_data(data, 'aws backup list-backup-selections --backup-plan-id ' + backup_plan['BackupPlanId'] +
                                    ' --query \"{BackupSelectionsList:BackupSelectionsList[*].{SelectionId:SelectionId, SelectionName:SelectionName, BackupPlanId:BackupPlanId}}\"',
                                    {'BackupSelectionsList': [{'SelectionId': backup_selection['SelectionId'], 'SelectionName': backup_selection['SelectionName'], 'BackupPlanId': backup_selection['BackupPlanId']}
                                                              for backup_selection in low_data.list_backup_selections['BackupSelectionsList']]})
                        for backup_selection in low_data.list_backup_selections['BackupSelectionsList']:
                            append_data(data, 'aws backup get-backup-selection --backup-plan-id ' + backup_plan['BackupPlanId'] + ' --selection-id ' + backup_selection['SelectionId'] + \
                                        ' --query \"{BackupSelection:BackupSelection, BackupPlanId:BackupPlanId, SelectionId:SelectionId}\"', low_data.backup_selections[backup_selection['SelectionId']])
                    append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 스냅샷이 Amazon Backup 서비스를 이용해 관리되지 않습니다.')
                    check = 'N'

            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '020', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_021(self):
        print('[RDS_021] RDS DB 인스턴스의 자동 마이너 업그레이드 기능이 활성화되어 있는지 확인하시오.')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, AutoMinorVersionUpgrade:AutoMinorVersionUpgrade}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'AutoMinorVersionUpgrade': db_instance['AutoMinorVersionUpgrade'] if 'AutoMinorVersionUpgrade' in db_instance else 'null'})
            if 'AutoMinorVersionUpgrade' not in db_instance or not db_instance['AutoMinorVersionUpgrade']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스의 자동 마이너 업그레이드 기능이 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '021', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    # 기존 22번 이전 세대의 인스턴스 클래스가 엄청엄청많고, 엔진마다 다른데 어떻게 처리할지...
    def rds_022(self):
        print('[RDS_022] 프로비저닝 된 모든 RDS 데이터베이스 인스턴스가 최신 세대의 인스턴스 클래스를 사용하고 있는지 확인하시오.')
        previous_db_instance_class = ['db.m1.micro', 'db.m1.small', 'db.m1.medium', 'db.m1.large', 'db.m1.xlarge', 'db.m3.medium', 'db.m3.large', 'db.m3.xlarge', 'db.m3.2xlarge',
                                      'db.cr1.8xlarge', 'db.m2.xlarge', 'db.m2.2xlarge', 'db.m2.4xlarge', 'db.r3.large', 'db.r3.xlarge', 'db.r3.2xlarge', 'db.r3.4xlarge', 'db.r3.8xlarge']
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, DBInstanceClass:DBInstanceClass}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'DBInstanceClass': db_instance['DBInstanceClass']})
            if db_instance['DBInstanceClass'] in previous_db_instance_class:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 이전 세대의 인스턴스 클래스(' + db_instance['DBInstanceClass'] + ' )를 사용하고 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '022', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_023(self):
        print('[RDS_023] AES-256 수준 암호화를 사용하여 RDS 인스턴스의 암호화를 보장하는지 확인하시오')
        for db_instance in low_data.db_instances:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-instances --filter Name=db-instance-id,Values=' + db_instance['DBInstanceIdentifier'] + \
                        ' --query \"DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier, StorageEncrypted:StorageEncrypted, KmsKeyId:KmsKeyId}\"',
                        {'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'], 'StorageEncrypted': db_instance['StorageEncrypted'], 'KmsKeyId': db_instance['KmsKeyId'] if 'KmsKeyId' in db_instance else 'null'})
            if not db_instance['StorageEncrypted']:
                append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 암호화되지 않았습니다.')
            else:
                aliases = [alias for alias in low_data.aliases if alias['TargetKeyId'] == db_instance['KmsKeyId']]
                if [alias for alias in aliases if alias['AliasName'] == 'alias/aws/rds']:
                    append_summary(data, db_instance['DBInstanceIdentifier'] + ' 볼륨이 KMS 고객 관리형 키(CMK)로 암호화되지만 AWS에서 제공하는 KMS 고객 관리형 키를 사용합니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_instance['DBInstanceIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '023', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], check, str(data)))
        print()

    def rds_024(self):
        print('[RDS_024] AES-256 수준의 암호화를 사용하여 RDS 스냅샷의 암호화를 보장하는지 확인하시오.')
        for db_snapshot in low_data.db_snapshots:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws rds describe-db-snapshots --filter Name=db-snapshot-id,Values=' + db_snapshot['DBSnapshotIdentifier'] + ' --query \"DBSnapshots[*].{DBSnapshotIdentifier:DBSnapshotIdentifier, DBInstanceIdentifier:DBInstanceIdentifier, Encrypted:Encrypted}\"',
                        {'DBSnapshotIdentifier': db_snapshot['DBSnapshotIdentifier'], 'DBInstanceIdentifier': db_snapshot['DBInstanceIdentifier'], 'Encrypted': db_snapshot['Encrypted']})
            if not db_snapshot['Encrypted']:
                append_summary(data, db_snapshot['DBInstanceIdentifier'] + ' 인스턴스의 스냅샷 ' + db_snapshot['DBSnapshotIdentifier'] + ' 이 암호화되지 않았습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, db_snapshot['DBSnapshotIdentifier'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'RDS', '024', db_snapshot['DBSnapshotIdentifier'], db_snapshot['DBSnapshotArn'], check, str(data)))
        print()

