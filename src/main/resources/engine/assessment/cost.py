# def rds_004(self):
#     print('[RDS_004] AES-256 수준 암호화를 사용하여 RDS 인스턴스의 암호화를 보장하는지 확인하시오.')
#     for db_instance in low_data.db_instances:
#         if not db_instance['StorageEncrypted']:
#             append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 암호화되지 않았습니다.\n')
#     print('[+] Complete!')
#
# def rds_023(self):
#     print('[RDS_023] 유휴 상태로 보이는 RDS DB 인스턴스를 식별하고 삭제했는지 확인하시오.')
#     for db_instance in low_data.db_instances:
#         get_metric_statistics = cloudwatch_client.get_metric_statistics(MetricName='DatabaseConnections', StartTime=db_instance['InstanceCreateTime'],
#                                                                         EndTime=datetime.datetime.now(), Period=3600, Namespace='AWS/RDS', Statistics=['Average'],
#                                                                         Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}])
#         check_metric_statistics_1 = [metric_statistic for metric_statistic in get_metric_statistics['Datapoints'] if metric_statistic['Average'] < 1]
#
#         get_metric_statistics = cloudwatch_client.get_metric_statistics(MetricName='ReadIOPS', StartTime=db_instance['InstanceCreateTime'],
#                                                                         EndTime=datetime.datetime.now(), Period=3600, Namespace='AWS/RDS', Statistics=['Sum'],
#                                                                         Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}])
#         check_metric_statistics_2 = [metric_statistic for metric_statistic in get_metric_statistics['Datapoints'] if metric_statistic['Sum'] < 20]
#
#         get_metric_statistics = cloudwatch_client.get_metric_statistics(MetricName='writeIOPS', StartTime=db_instance['InstanceCreateTime'],
#                                                                         EndTime=datetime.datetime.now(), Period=3600, Namespace='AWS/RDS', Statistics=['Sum'],
#                                                                         Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}])
#         check_metric_statistics_3 = [metric_statistic for metric_statistic in get_metric_statistics['Datapoints'] if metric_statistic['Sum'] < 20]
#
#         if len(check_metric_statistics_1) + len(check_metric_statistics_2) + len(check_metric_statistics_3) > 0:
#             append_summary(data, db_instance['DBInstanceIdentifier'] + ' 인스턴스가 유휴상태입니다.\n')
#             for check_metric_statistic in check_metric_statistics_1:
#                 append_summary(data, str(check_metric_statistic['Timestamp']) + ' 에 연결한 수 : ' + str(check_metric_statistic['Average']) + '회\n')
#             for check_metric_statistic in check_metric_statistics_2:
#                 append_summary(data, str(check_metric_statistic['Timestamp']) + ' 에 초당 읽기 작업 수 : ' + str(check_metric_statistic['Sum']) + '회\n')
#             for check_metric_statistic in check_metric_statistics_3:
#                 append_summary(data, str(check_metric_statistic['Timestamp']) + ' 에 초당 쓰기 작업 수 : ' + str(check_metric_statistic['Sum']) + '회\n')
#     print('[+] Complete!')
#
# def rds_025(self):
#     print('[RDS_025] 7일 내에 Amazon RDS 예약 DB 인스턴스 임대가 만료되는지 확인하시오.')
#     for reserved_db_instance in low_data.reserved_db_instances:
#         if from_now(reserved_db_instance['StartTime'] + datetime.timedelta(0, reserved_db_instance['Duration'])) > 0:
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스의 임대가 만료되었습니다.\n')
#         elif from_now(reserved_db_instance['StartTime'] + datetime.timedelta(0, reserved_db_instance['Duration'])) > -7:
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스의 임대가 ' + str(reserved_db_instance['StartTime'] + datetime.timedelta(0, reserved_db_instance['Duration']) * -1) + '일 남았습니다.\n')
#     print('[+] Complete!')
#
# def rds_026(self):
#     print('[RDS_026] AWS RDS 예약 인스턴스 구매가 실패하지 않았는지 확인하시오.')
#     for reserved_db_instance in low_data.reserved_db_instances:
#         if reserved_db_instance['State'] == 'payment-failed':
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스 구매가 실패했습니다.\n')
#     print('[+] Complete!')
#
# def rds_027(self):
#     print('[RDS_027] Amazon RDS 예약 인스턴스 구매가 보류 중이 아닌지 확인하시오.')
#     for reserved_db_instance in low_data.reserved_db_instances:
#         if reserved_db_instance['State'] == 'payment-pending':
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스 보류되었습니다.\n')
#     print('[+] Complete!')
#
# def rds_028(self):
#     print('[RDS_028] 비용 최적화를 위해 RDS 예약 인스턴스 구매를 정기적으로 확인하시오.')
#     recent_reserved_db_instance = [reserved_db_instance for reserved_db_instance in low_data.reserved_db_instances if from_now(reserved_db_instance['StartTime']) < 7]
#     if recent_reserved_db_instance:
#         # print('최근 7일간 구매한 RDS 예약 인스턴스입니다.')
#         for reserved_db_instance in recent_reserved_db_instance:
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스의 구매 일자 : ' + reserved_db_instance['StartTime'] + '\n')
#     print('[+] Complete!')
#
# def rds_029(self):
#     print('[RDS_029] 미사용중인 Amazon RDS 예약 인스턴스가 존재하는지 확인하시오.')
#     for reserved_db_instance in low_data.reserved_db_instances:
#         if reserved_db_instance['DBInstanceClass'] not in [db_instance['DBInstanceClass'] for db_instance in low_data.db_instances]:
#             append_summary(data, reserved_db_instance['ReservedDBInstanceId'] + ' 예약 인스턴스가 사용되지 않습니다.\n')
#     print('[+] Complete!')
