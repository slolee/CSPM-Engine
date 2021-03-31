from Common.data import low_data
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class CloudTrail:
    def __init__(self):
        low_data.load_cloudtrail_low_data()

    def audit_all(self):
        self.cloudtrail_001()
        self.cloudtrail_002()
        self.cloudtrail_003()
        self.cloudtrail_004()
        self.cloudtrail_005()
        self.cloudtrail_006()
        self.cloudtrail_007()
        self.cloudtrail_008()
        self.cloudtrail_009()
        self.cloudtrail_010()

    def cloudtrail_001(self):
        print('[CloudTrail_001] AWS 계정에 활성화되어 있는 CloudTrail의 Trail이 존재하는지 확인하시오.')
        check = 'Y'
        data = {'cli': [], 'raw_data': [], 'summary': []}

        append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN}}\"',
                    {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN']} for trail in low_data.trails]})
        logging_trails = [trail for trail in low_data.trails if low_data.trail_status[trail['TrailARN']]['IsLogging']]
        if not logging_trails:
            append_summary(data, 'AWS 계정에 활성화되어 있는 CloudTrail의 Trail이 존재하지 않습니다.')

        if len(data['summary']) > 0:
            check = 'N'
        else:
            for trail in logging_trails:
                append_data(data, 'aws cloudtrail get-trail-status --name ' + trail['TrailARN'] + ' --query \"{IsLogging:IsLogging}\"',
                            {'IsLogging': low_data.trail_status[trail['TrailARN']]['IsLogging']})
        execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '001', 'CloudTrail', 'CloudTrail', check, str(data)))
        print()

    def cloudtrail_002(self):
        print('[CloudTrail_002] CloudTrail의 Trail이 모든 리전에서 이벤트를 로깅하도록 설정했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, IsMultiRegionTrail:IsMultiRegionTrail}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'IsMultiRegionTrail': trail['IsMultiRegionTrail']}]})
                if not trail['IsMultiRegionTrail']:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 모든 리전에서 이벤트를 로깅하도록 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '002', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_003(self):
        print('[CloudTrail_003] CloudTrail의 각 Trail이 CloudWatch Logs와 통합되어 있는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'CloudWatchLogsLogGroupArn': (trail['CloudWatchLogsLogGroupArn'] if 'CloudWatchLogsLogGroupArn' in trail else 'null')}]})

                if 'CloudWatchLogsLogGroupArn' in trail:
                    append_data(data, 'aws cloudtrail get-trail-status --name ' + trail['TrailARN'] + ' --query \"{LatestCloudWatchLogsDeliveryTime:LatestCloudWatchLogsDeliveryTime}\"',
                                {'LatestCloudWatchLogsDeliveryTime': ('LatestCloudWatchLogsDeliveryTime' in low_data.trail_status[trail['TrailARN']]['LatestCloudWatchLogsDeliveryTime'] if low_data.trail_status[trail['TrailARN']] else 'null')})
                    if 'LatestCloudWatchLogsDeliveryTime' in low_data.trail_status[trail['TrailARN']]:
                        if (datetime.datetime.now(timezone('Asia/Seoul')) - low_data.trail_status[trail['TrailARN']]['LatestCloudWatchLogsDeliveryTime']).days > 0:
                            append_summary(data, 'Trail ' + trail['Name'] + ' 와 통합되어 있는 CloudWatch Logs의 로그그룹에 로그가 전송된지 하루이상 지났습니다.')
                    else:
                        append_summary(data, 'Trail ' + trail['Name'] + ' 에 CloudWatch Logs는 연결되어 있지만 로그가 전송된 기록이 없습니다.')
                else:
                    append_summary(data, 'Trail ' + trail['Name'] + ' 이 CloudWatch Logs와 통합되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '003', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_004(self):
        print('[CloudTrail_004] CloudTrail 로그 파일이 S3 Bucket으로 전송될 때 Amazon SNS Topic을 통한 알림을 설정했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, SnsTopicARN:SnsTopicARN}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'SnsTopicARN': (trail['SnsTopicARN'] if 'SnsTopicARN' in trail else 'null')}]})
                if 'SnsTopicARN' not in trail:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 로그 파일이 S3 Bucket으로 전송될 때 Amazon SNS Topic을 통한 알림을 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '004', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_005(self):
        print('[CloudTrail_005] CloudTrail의 각 Trail의 Insights Event가 활성화 되어있는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, HasInsightSelectors:HasInsightSelectors}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'HasInsightSelectors': trail['HasInsightSelectors']}]})

                if not trail['HasInsightSelectors']:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 Insights Event가 활성화 되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '005', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_006(self):
        print('[CloudTrail_006] CloudTrail의 각 Trail이 S3 Bucket와 SNS에 정상적으로 로그를 전달했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail get-trail-status --name ' + trail['TrailARN'] + \
                            ' --query \"{LatestDeliveryTime:LatestDeliveryTime, LatestDeliveryError:LatestDeliveryError, LatestNotificationTime:LatestNotificationTime, LatestNotificationError:LatestNotificationError}\"',
                            {'LatestDeliveryTime': (str(low_data.trail_status[trail['TrailARN']]['LatestDeliveryTime']) if 'LatestDeliveryTime' in low_data.trail_status[trail['TrailARN']] else 'null'),
                             'LatestDeliveryError': (str(low_data.trail_status[trail['TrailARN']]['LatestDeliveryError']) if 'LatestDeliveryError' in low_data.trail_status[trail['TrailARN']] else 'null'),
                             'LatestNotificationTime': (str(low_data.trail_status[trail['TrailARN']]['LatestNotificationTime']) if 'LatestNotificationTime' in low_data.trail_status[trail['TrailARN']] else 'null'),
                             'LatestNotificationError': (str(low_data.trail_status[trail['TrailARN']]['LatestNotificationError']) if 'LatestNotificationError' in low_data.trail_status[trail['TrailARN']] else 'null')})

                if 'LatestDeliveryTime' not in low_data.trail_status[trail['TrailARN']] or (datetime.datetime.now(timezone('Asia/Seoul')) - low_data.trail_status[trail['TrailARN']]['LatestDeliveryTime']).days > 0:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 의 로그파일이 하루이상 S3 Bucket에 전달되지 않았습니다.')
                if 'LatestDeliveryError' in low_data.trail_status[trail['TrailARN']]:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 의 로그파일이' + low_data.trail_status[trail['TrailARN']]['LatestDeliveryError'] + ' 에러로 인해 S3 Bucket에 전달되지 않았습니다.')
                if 'LatestNotificationTime' not in low_data.trail_status[trail['TrailARN']] or (datetime.datetime.now(timezone('Asia/Seoul')) - low_data.trail_status[trail['TrailARN']]['LatestNotificationTime']).days > 0:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 의 로그파일이 하루이상 SNS 알림 전달되지 않았습니다.')
                if 'LatestNotificationError' in low_data.trail_status[trail['TrailARN']]:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 의 로그파일이' + low_data.trail_status[trail['TrailARN']]['LatestDeliveryError'] + ' 에러로 인해 SNS 알림이 전달되지 않았습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '006', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_007(self):
        print('[CloudTrail_007] CloudTrail 로그를 저장하기 위한 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트를 설정했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                get_event_selectors = low_data.event_selectors[trail['TrailARN']]
                # Event Selector와 Advanced Event Selector를 판단
                if 'EventSelectors' in get_event_selectors:
                    append_data(data, 'aws cloudtrail get-event-selectors --trail-name' + trail['TrailARN'], {'TrailARN': get_event_selectors['TrailARN'], 'EventSelectors': get_event_selectors['EventSelectors']})
                    # DataResource가 존재하는 Event Selector들만 필터
                    data_event_selectors = [event_selector for event_selector in get_event_selectors['EventSelectors'] if event_selector['DataResources']]
                    if data_event_selectors:
                        # AWS::S3::Object 데이터 이벤트가 있었는지 확인하기 위한 Flag
                        s3_check = False
                        for data_event_selector in data_event_selectors:
                            if {'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']} in data_event_selector['DataResources']:
                                s3_check = True
                                # 읽기전용일 경우와 쓰기전용일 경우 출력을 다르게
                                if data_event_selector['ReadWriteType'] == 'ReadOnly':
                                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지만, 읽기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                                elif data_event_selector['ReadWriteType'] == 'WriteOnly':
                                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지만, 쓰기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                        if not s3_check:
                            append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지 않습니다.')
                    else:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지 않습니다.')
                elif 'AdvancedEventSelectors' in get_event_selectors:
                    append_data(data, 'aws cloudtrail get-event-selectors --trail-name' + trail['TrailARN'], {'TrailARN': get_event_selectors['TrailARN'], 'AdvancedEventSelectors': get_event_selectors['AdvancedEventSelectors']})
                    advanced_event_selectors = get_event_selectors['AdvancedEventSelectors']
                    # Advanced Event Selector중 Field가 eventCategory이고 Equals가 Data인 것들만 필터링
                    data_field_selectors = [advanced_event_selector['FieldSelectors'] for advanced_event_selector in advanced_event_selectors
                                            if {'Field': 'eventCategory', 'Equals': ['Data']} in advanced_event_selector['FieldSelectors']]

                    # 리소스 타입이 AWS::S3::Object 인 것들만 필터링
                    s3_data_field_selectors = [data_field_selector for data_field_selector in data_field_selectors
                                               if {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']} in data_field_selector]
                    # for data_field_selector in data_field_selectors:
                    #     if {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']} in data_field_selector:
                    #         s3_data_field_selectors.append(data_field_selector)

                    if s3_data_field_selectors:
                        # 읽기전용과 쓰기전용의 출력을 다르게 하기 위한 Flag
                        # 일반 Event Selector와 다르게 여러개가 존재하며 각각 readOnly, writeOnly일 수 있다.
                        read_check, write_check = False, False
                        for s3_data_field_selector in s3_data_field_selectors:
                            if {'Field': 'readOnly', 'Equals': ['true']} in s3_data_field_selector:
                                read_check = True
                            elif {'Field': 'readOnly', 'Equals': ['false']} in s3_data_field_selector:
                                write_check = True
                            else:
                                read_check, write_check = True, True

                        if not (read_check and write_check):
                            if read_check:
                                append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지만, 읽기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                            else:
                                append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지만, 쓰기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                    else:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 S3 Bucket의 액세스 로깅을 하도록 데이터 이벤트가 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '007', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_008(self):
        print('[CloudTrail_008] CloudTrail의 각 Trail이 중요한 작업을 기록하기 위한 관리 이벤트를 설정했는지 확인하시오')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                get_event_selectors = low_data.event_selectors[trail['TrailARN']]
                if 'EventSelectors' in get_event_selectors:
                    append_data(data, 'aws cloudtrail get-event-selectors --trail-name' + trail['TrailARN'], {'TrailARN': get_event_selectors['TrailARN'], 'EventSelectors': get_event_selectors['EventSelectors']})
                    management_event_selectors = [event_selector for event_selector in get_event_selectors['EventSelectors'] if event_selector['IncludeManagementEvents']]
                    if not management_event_selectors:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지 않습니다.')
                    else:
                        management_event_selectors_read_write_type = [management_event_selector['ReadWriteType'] for management_event_selector in management_event_selectors]
                        if 'All' not in management_event_selectors_read_write_type:
                            if 'ReadOnly' in management_event_selectors_read_write_type:
                                append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지만, 읽기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                            elif 'WriteOnly' in management_event_selectors_read_write_type:
                                append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지만, 쓰기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                elif 'AdvancedEventSelectors' in get_event_selectors:
                    append_data(data, 'aws cloudtrail get-event-selectors --trail-name' + trail['TrailARN'], {'TrailARN': get_event_selectors['TrailARN'], 'AdvancedEventSelectors': get_event_selectors['AdvancedEventSelectors']})
                    management_field_selectors = [advanced_event_selector['FieldSelectors'] for advanced_event_selector in get_event_selectors['AdvancedEventSelectors']
                                                  if {'Field': 'eventCategory', 'Equals': ['Management']} in advanced_event_selector['FieldSelectors']]
                    if not management_field_selectors:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지 않습니다.')
                    elif {'Field': 'readOnly', 'Equals': ['true']} in management_field_selectors[0]:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지만, 읽기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')
                    elif {'Field': 'readOnly', 'Equals': ['false']} in management_field_selectors[0]:
                        append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 중요한 작업을 기록하기 위한 관리 이벤트를 설정되어있지만, 쓰기전용 API에 대해서만 로깅하도록 설정되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '008', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_009(self):
        print('[CloudTrail_009] CloudTrail의 각 Trail이 로그파일 무결성 검증을 하도록 설정했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, LogFileValidationEnabled:LogFileValidationEnabled}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'LogFileValidationEnabled': trail['LogFileValidationEnabled']}]})

                if not trail['LogFileValidationEnabled']:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 로그파일 무결성 검증을 하도록 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '009', trail['Name'], trail['Name'], check, str(data)))
        print()

    def cloudtrail_010(self):
        print('[CloudTrail_009] CloudTrail 로그가 KMS CMKs를 통해 암호화되도록 설정했는지 확인하시오.')
        for trail in low_data.trails:
            if low_data.trail_status[trail['TrailARN']]['IsLogging']:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                append_data(data, 'aws cloudtrail describe-trails --query \"{trailList:trailList[*].{Name:Name, TrailARN:TrailARN, KmsKeyId:KmsKeyId}}\"',
                            {'trailList': [{'Name': trail['Name'], 'TrailARN': trail['TrailARN'], 'KmsKeyId': (trail['KmsKeyId'] if 'KmsKeyId' in trail else 'null')}]})

                if 'KmsKeyId' not in trail:
                    append_summary(data, '현재 로깅중인 Trail ' + trail['Name'] + ' 은 로그가 KMS CMKs를 통해 암호화되도록 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_sql((low_data.diagnosis_id, 'CloudTrail', '010', trail['Name'], trail['Name'], check, str(data)))
        print()
