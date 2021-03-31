from Common.data import low_data
from Common.db_profile import *
from Common.utils import *
import boto3, json, datetime
from pytz import timezone
from botocore.exceptions import ClientError

class CloudFront:
    def __init__(self):
        low_data.load_cloudfront_low_data()

    def audit_all(self):
        self.cloudfront_001()
        self.cloudfront_002()
        self.cloudfront_003()
        self.cloudfront_004()
        self.cloudfront_005()
        self.cloudfront_006()
        self.cloudfront_007()
        self.cloudfront_008()

    def cloudfront_001(self):
        print('[CloudFront_001] CloudFront 배포에 지리적 제한이 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{Restrictions:Restrictions}}}\"',
                        {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'Restrictions': low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Restrictions']}}})
            if low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Restrictions']['GeoRestriction']['RestrictionType'] == 'none':
                append_summary(data, distribution['Id'] + ' CloudFront 배포에 지리적 제한이 설정되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, distribution['Id'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '001', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_002(self):
        print('[CloudFront_002] CloudFront 배포에 AWS WAF 웹 ACL이 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{WebACLId:WebACLId}}}\"',
                        {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'WebACLId': low_data.distribution_detail[distribution['Id']]['DistributionConfig']['WebACLId']}}})
            if not low_data.distribution_detail[distribution['Id']]['DistributionConfig']['WebACLId']:
                append_summary(data, distribution['Id'] + ' CloudFront 배포에 AWS WAF 웹 ACL이 설정되어있지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, distribution['Id'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '002', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_003(self):
        print('[CloudFront_003] CloudFront 배포의 S3 오리진에 버킷 액세스 제한이 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            s3_origins = [item for item in low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Origins']['Items'] if item['DomainName'].endswith('s3.amazonaws.com')]
            if s3_origins:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{Origins:Origins.{Items:Items[*].{S3OriginConfig:S3OriginConfig, Id:Id}}}}}\"',
                            {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'Origins': {'Items': [{'S3OriginConfig': item['S3OriginConfig'], 'Id': item['Id']} for item in s3_origins]}}}})
                for origin in s3_origins:
                    if not origin['S3OriginConfig']['OriginAccessIdentity']:
                        append_summary(data, distribution['Id'] + ' CloudFront 배포의 S3 오리진 ' + origin['Id'] + ' 에 버킷 액세스 제한이 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                print(check, data, distribution['Id'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '003', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_004(self):
        print('[CloudFront_004] CloudFront 배포의 S3가 아닌 오리진에 최소 오리진 프로토콜이 "TLSv1.1" 또는 "TLSv1.2" 이상으로 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            not_s3_origins = [item for item in low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Origins']['Items'] if not item['DomainName'].endswith('s3.amazonaws.com')]
            if not_s3_origins:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + \
                            ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{Origins:Origins.{Items:Items[*].{CustomOriginConfig:CustomOriginConfig.{OriginSslProtocols:OriginSslProtocols}, Id:Id}}}}}\"',
                            {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'Origins': {'Items': [{'CustomOriginConfig': {'OriginSslProtocols': item['CustomOriginConfig']['OriginSslProtocols']}, 'Id': item['Id']} for item in not_s3_origins]}}}})
                for origin in not_s3_origins:
                    ssl_versions = [ssl_version for ssl_version in ['TLSv1', 'SSLv3'] if ssl_version in origin['CustomOriginConfig']['OriginSslProtocols']['Items']]
                    if ssl_versions:
                        append_summary(data, distribution['Id'] + ' CloudFront 배포의 오리진 ' + origin['Id'] + ' 의 최소 오리진 프로토콜이 ' + str(ssl_versions) + ' 을 허용하도록 설정되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                print(check, data, distribution['Id'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '004', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_005(self):
        print('[CloudFront_005] CloudFront 배포의 S3가 아닌 오리진에 오리진 프로토콜 정책이 "HTTPS 만" 또는 "매치 뷰어"로 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            not_s3_origins = [item for item in low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Origins']['Items'] if not item['DomainName'].endswith('s3.amazonaws.com')]
            if not_s3_origins:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + \
                            ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{Origins:Origins.{Items:Items[*].{CustomOriginConfig:CustomOriginConfig.{OriginProtocolPolicy:OriginProtocolPolicy}, Id:Id}}}}}\"',
                            {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'Origins': {'Items': [{'CustomOriginConfig': {'OriginProtocolPolicy': item['CustomOriginConfig']['OriginProtocolPolicy']}, 'Id': item['Id']} for item in not_s3_origins]}}}})
                for origin in not_s3_origins:
                    if origin['CustomOriginConfig']['OriginProtocolPolicy'] == 'http-only':
                        append_summary(data, distribution['Id'] + ' CloudFront 배포의 오리진 ' + origin['Id'] + ' 의 오리진 프로토콜 정책이 "HTTPS 만" 또는 "매치 뷰어"로 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                print(check, data, distribution['Id'], sep='\n')
                execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '005', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_006(self):
        print('[CloudFront_006] CloudFront 배포의 Behaviors의 뷰어 프로토콜 정책이 "HTTP를 HTTPS로 리다이렉션" 또는 "HTTPS 만"으로 설정되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            default_cache_behavior = low_data.distribution_detail[distribution['Id']]['DistributionConfig']['DefaultCacheBehavior']
            cache_behaviors = low_data.distribution_detail[distribution['Id']]['DistributionConfig']['CacheBehaviors']
            cache_behaviors_items = cache_behaviors['Items'] if 'Items' in cache_behaviors else []
            append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + \
                        ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{DefaultCacheBehavior:DefaultCacheBehavior.{ViewerProtocolPolicy:ViewerProtocolPolicy},'
                        ' CacheBehaviors:CacheBehaviors.{Items:Items[*].{PathPattern:PathPattern, ViewerProtocolPolicy:ViewerProtocolPolicy}}}}}\"',
                        {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'DefaultCacheBehavior': {'ViewerProtocolPolicy': default_cache_behavior['ViewerProtocolPolicy']},
                         'CacheBehaviors': {'Items': [{'ViewerProtocolPolicy': behavior_item['ViewerProtocolPolicy'], 'PathPattern': behavior_item['PathPattern']} for behavior_item in cache_behaviors_items]} if cache_behaviors_items else 'null'}}})

            if default_cache_behavior['ViewerProtocolPolicy'] == 'allow-all':
                append_summary(data, distribution['Id'] + ' CloudFront 배포의 기본 Behaviors(*)의 뷰어 프로토콜 정책이 "HTTP and HTTPS"로 설정되어 있습니다.')
            for behavior_item in cache_behaviors_items:
                if behavior_item['ViewerProtocolPolicy'] == 'allow-all':
                    append_summary(data, distribution['Id'] + ' CloudFront 배포의 \'' + behavior_item['PathPattern'] + '\' 패턴의 뷰어 프로토콜 정책이 "HTTP and HTTPS"로 설정되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, distribution['Id'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '006', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_007(self):
        print('[CloudFront_007] CloudFront 배포에 실시간 로그 활성화되어 있는지 확인하시오.')
        for distribution in low_data.distributions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{Logging:Logging}}}\"',
                        {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'Logging': low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Logging']}}})
            if not low_data.distribution_detail[distribution['Id']]['DistributionConfig']['Logging']['Enabled']:
                append_summary(data, distribution['Id'] + ' CloudFront 배포에 실시간 로그가 비활성화되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, distribution['Id'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '007', distribution['Id'], distribution['ARN'], check, str(data)))
        print()

    def cloudfront_008(self):
        print('[CloudFront_008] CloudFront 웹 배포의 각 Behavior에 필드 수준 암호화를 실행하는지 확인하시오.')
        for distribution in low_data.distributions:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            default_cache_behavior = low_data.distribution_detail[distribution['Id']]['DistributionConfig']['DefaultCacheBehavior']
            cache_behaviors = low_data.distribution_detail[distribution['Id']]['DistributionConfig']['CacheBehaviors']
            cache_behaviors_items = cache_behaviors['Items'] if 'Items' in cache_behaviors else []
            append_data(data, 'aws cloudfront get-distribution --id ' + distribution['Id'] + \
                        ' --query \"{Distribution:Distribution.{Id:Id, DistributionConfig:DistributionConfig.{DefaultCacheBehavior:DefaultCacheBehavior.{ViewerProtocolPolicy:ViewerProtocolPolicy},'
                        ' CacheBehaviors:CacheBehaviors.{Items:Items[*].{PathPattern:PathPattern, ViewerProtocolPolicy:ViewerProtocolPolicy}}}}}\"',
                        {'Distribution': {'Id': distribution['Id'], 'DistributionConfig': {'DefaultCacheBehavior': {'FieldLevelEncryptionId': default_cache_behavior['FieldLevelEncryptionId']},
                         'CacheBehaviors': {'Items': [{'FieldLevelEncryptionId': behavior_item['FieldLevelEncryptionId'], 'PathPattern': behavior_item['PathPattern']} for behavior_item in cache_behaviors_items]} if cache_behaviors_items else 'null'}}})

            if not default_cache_behavior['FieldLevelEncryptionId']:
                append_summary(data, distribution['Id'] + ' CloudFront 배포의 기본 Behaviors(*)에서 필드 수준 암호화를 실행하지 않습니다.')
            for behavior_item in cache_behaviors_items:
                if not behavior_item['FieldLevelEncryptionId']:
                    append_summary(data, distribution['Id'] + ' CloudFront 배포의 \'' + behavior_item['PathPattern'] + '\' 패턴에서 필드 수준 암호화를 실행하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            print(check, data, distribution['Id'], sep='\n')
            execute_insert_sql((low_data.diagnosis_id, 'CloudFront', '008', distribution['Id'], distribution['ARN'], check, str(data)))
        print()
