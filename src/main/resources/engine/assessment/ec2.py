from common.client import *
from common.utils import *
from common.db import *

class EC2:
    def __init__(self):
        low_data.load_ec2_low_data()

    def audit_all(self):
        self.ec2_001()
        self.ec2_002()
        self.ec2_003()
        self.ec2_004()
        self.ec2_005()
        self.ec2_006()
        self.ec2_007()
        self.ec2_008()
        self.ec2_009()
        self.ec2_010()
        self.ec2_011()
        self.ec2_012()
        self.ec2_013()
        self.ec2_014()

    def ec2_001(self):
        try:
            print('[EC2_001] 모든 AWS 계정이 AMI에 접근할 수 없도록 설정되어있는지 확인하시오.')
            for image in low_data.images:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws ec2 describe-images --owners self --filter Name=image-id,Values=' + image['ImageId'] + ' --query \"Images[*].{ImageId:ImageId, Public:Public}\"',
                            {'ImageId': image['ImageId'], 'Public': image['Public']})
                if image['Public']:
                    append_summary(data, image['ImageId'] + ' AMI가 모든 AWS 계정에서 접근할 수 있도록 설정되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '001', image['Name'], image['ImageId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_002(self):
        try:
            print('[EC2_002] 백엔드 EC2 인스턴스가 공개된 서브넷에서 실행되지 않는지 확인하시오.')
            for instance in low_data.instances:
                if instance['State']['Name'] == 'running':
                    check = '?'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    append_data(data, 'aws ec2 describe-instances --filter Name=instance-id,Values=' + instance['InstanceId'] + ' --query \"Reservations[*].{Instances:Instances[*].{InstanceId:InstanceId, VpcId:VpcId, SubnetId:SubnetId}}\"',
                                {'Instances': {'InstanceId': instance['InstanceId'], 'VpcId': instance['VpcId'], 'SubnetId': instance['SubnetId']}})
                    this_route_table = None
                    default_route_table = None
                    for route_table in low_data.route_tables:
                        for association in route_table['Associations']:
                            if association['Main']:
                                default_route_table = route_table
                            if 'SubnetId' in association and association['SubnetId'] == instance['SubnetId']:
                                this_route_table = route_table

                    if not this_route_table:
                        append_summary(data, instance['InstanceId'] + ' 인스턴스가 명시적으로 지정된 라우팅 테이블이 아니라 VPC의 기본 라우팅 테이블과 연결된 서브넷 ' + instance['SubnetId'] + ' 에서 실행되고 있습니다.')
                        this_route_table = default_route_table
                    append_data(data, 'aws ec2 describe-route-tables --filter Name=route-table-id,Values=' + this_route_table['RouteTableId'] + ' --query \"RouteTables[*].{Associations:Associations, RouteTableId:RouteTableId, Routes:Routes, VpcId:VpcId}\"',
                                {'Associations': this_route_table['Associations'], 'RouteTableId': this_route_table['RouteTableId'], 'Routes': this_route_table['Routes'], 'VpcId': this_route_table['VpcId']})
                    if [route for route in this_route_table['Routes']
                            if route['State'] == 'active' and route['DestinationCidrBlock'] in ['0.0.0.0/0', '::/0'] and route['GatewayId'].startswith('igw-')]:
                        append_summary(data, instance['InstanceId'] + ' 인스턴스가 공개된 서브넷 ' + instance['SubnetId'] + ' 에서 실행되고 있습니다.')

                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '002', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_003(self):
        try:
            print('[EC2_003] App-tier ELB가 internal로써 생성되어있는지 확인하시오.')
            for elb in low_data.load_balancers_v1:
                check = '?'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                if elb['Scheme'] != 'internal':
                    append_data(data, 'aws elb describe-load-balancers \"{LoadBalancerDescriptions:LoadBalancerDescriptions.{LoadBalancerName:LoadBalancerName, Scheme:Scheme}}\"',
                                {'LoadBalancerDescriptions': [{'LoadBalancerName': elb['LoadBalancerName'], 'Scheme': elb['Scheme']}]})
                    append_summary(data, elb['LoadBalancerName'] + ' ELB가 internal로써 생성되어있지 않습니다.')

                if len(data['summary']) > 0:
                    append_summary(data, elb['LoadBalancerName'] + ' 이 App-tier ELB 인지 확인하시오.')
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '003', elb['LoadBalancerName'], elb['LoadBalancerName'], check, str(data)))

            for elbv2 in low_data.load_balancers_v2:
                if elbv2['Type'] == 'application':
                    check = '?'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    if elbv2['Scheme'] != 'internal':
                        append_data(data, 'aws elbv2 describe-load-balancers \"{LoadBalancers:LoadBalancers.{LoadBalancerName:LoadBalancerName, Scheme:Scheme}}\"',
                                    {'LoadBalancers': [{'LoadBalancerName': elbv2['LoadBalancerName'], 'Scheme': elbv2['Scheme']}]})
                        append_summary(data, elbv2['LoadBalancerName'] + ' ELB가 internal로써 생성되어있지 않습니다.')

                    if len(data['summary']) > 0:
                        append_summary(data, elbv2['LoadBalancerName'] + ' 이 App-tier ELB 인지 확인하시오.')
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '003', elbv2['LoadBalancerName'], elbv2['LoadBalancerArn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_004(self):
        try:
            print('[EC2_004] 인스턴스의 \'보안 그룹 이름\'이 \'launch-wizard\'로 시작하는 보안 그룹과 연결되어 있지 않도록 설정했는지 확인하시오.')
            for instance in low_data.instances:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws ec2 describe-instances --filter Name=instance-id,Values=' + instance['InstanceId'] + ' --query \"Reservations[*].{Instances:Instances[*].{InstanceId:InstanceId, SecurityGroups:SecurityGroups}}\"',
                            {'Instances': [{'InstanceId': instance['InstanceId'], 'SecurityGroups': instance['SecurityGroups']}]})
                launch_wizard_sgs = [security_group for security_group in instance['SecurityGroups'] if security_group['GroupName'].startswith('launch-wizard')]
                if launch_wizard_sgs:
                    append_summary(data, instance['InstanceId'] + ' 인스턴스가 \'launch-wizard\'로 시작하는 보안그룹 ' + str([launch_wizard_sg['GroupName'] for launch_wizard_sg in launch_wizard_sgs]) + ' 와 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '004', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_005(self):
        try:
            print('[EC2_005] ASG(Auto Scaling Group)의 시작 구성에 \'AutoScaling-Security-Group-xx\'로 시작하는 보안 그룹과 연결되어 있지 않도록 설정했는지 확인하시오.')
            for launch_configuration in low_data.launch_configurations:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws autoscaling describe-launch-configurations --query \"{LaunchConfigurations:LaunchConfigurations[*].{LaunchConfigurationName:LaunchConfigurationName, SecurityGroups:SecurityGroups}}\"',
                            {'LaunchConfigurationName': launch_configuration['LaunchConfigurationName'], 'SecurityGroups': launch_configuration['SecurityGroups']})
                autoscaling_sgs = []
                for security_group_id in launch_configuration['SecurityGroups']:
                    security_group = [security_group for security_group in low_data.security_groups if security_group_id == security_group['GroupId']]
                    if security_group and security_group[0]['GroupName'].startswith('AutoScaling-Security-Group'):
                        autoscaling_sgs.append(security_group[0]['GroupName'])

                if autoscaling_sgs:
                    append_summary(data, launch_configuration['LaunchConfigurationName'] + ' 시작 구성이 \'AutoScaling-Security-Group\'로 시작하는 보안그룹 ' + str(autoscaling_sgs) + ' 와 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '005', launch_configuration['LaunchConfigurationName'], launch_configuration['LaunchConfigurationARN'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_006(self):
        try:
            print('[EC2_006] 기본보안그룹과 연결된 EC2 인스턴스가 존재하는지 확인하시오.')
            for instance in low_data.instances:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws ec2 describe-instances --filter Name=instance-id,Values=' + instance['InstanceId'] + ' --query \"Reservations[*].{Instances:Instances[*].{InstanceId:InstanceId, SecurityGroups:SecurityGroups}}\"',
                            {'Instances': [{'InstanceId': instance['InstanceId'], 'SecurityGroups': instance['SecurityGroups']}]})
                default_sg = [security_group for security_group in instance['SecurityGroups'] if security_group['GroupName'] == 'default']
                if default_sg:
                    append_summary(data, instance['InstanceId'] + ' 인스턴스가 기본보안그룹과 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '006', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_007(self):
        try:
            print('[EC2_007] 기본보안그룹과 연결된 EC2 시작 구성/시작 템플릿이 존재하는지 확인하시오.')
            for launch_configuration in low_data.launch_configurations:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws autoscaling describe-launch-configurations --query \"{LaunchConfigurations:LaunchConfigurations[*].{LaunchConfigurationName:LaunchConfigurationName, SecurityGroups:SecurityGroups}}\"',
                            {'LaunchConfigurationName': launch_configuration['LaunchConfigurationName'], 'SecurityGroups': launch_configuration['SecurityGroups']})
                default_sg = []
                for security_group_id in launch_configuration['SecurityGroups']:
                    security_group = [security_group for security_group in low_data.security_groups if security_group_id == security_group['GroupId']]
                    if security_group and security_group[0]['GroupName'] == 'default':
                        default_sg.append(security_group[0]['GroupName'])
                if default_sg:
                    append_summary(data, launch_configuration['LaunchConfigurationName'] + ' 시작 구성이 기본보안그룹과 연결되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '007', launch_configuration['LaunchConfigurationName'], launch_configuration['LaunchConfigurationARN'], check, str(data)))

            for launch_template in low_data.launch_templates:
                if 'SecurityGroupIds' in low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]:
                    check = 'Y'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    append_data(data, 'aws ec2 describe-launch-template-versions --launch-template-id ' + launch_template['LaunchTemplateName'] + \
                                ' --query \"{LaunchTemplateVersions:LaunchTemplateVersions[*].{LaunchTemplateId:LaunchTemplateId, LaunchTemplateName:LaunchTemplateName, VersionNumber:VersionNumber, DefaultVersion:DefaultVersion, LaunchTemplateData:LaunchTemplateData}}\"',
                                {'LaunchTemplateVersions': [{'LaunchTemplateId': launch_template_version['LaunchTemplateId'], 'LaunchTemplateName': launch_template_version['LaunchTemplateName'], 'VersionNumber': launch_template_version['VersionNumber'],
                                                             'DefaultVersion': launch_template_version['DefaultVersion'], 'LaunchTemplateData': launch_template_version['LaunchTemplateData']}
                                                            for launch_template_version in low_data.launch_template_versions[launch_template['LaunchTemplateName']]]})
                    default_sg = []
                    for security_group_id in low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]['LaunchTemplateData']:
                        security_group = [security_group for security_group in low_data.security_groups if security_group_id == security_group['GroupId']]
                        if security_group and security_group[0]['GroupName'] == 'default':
                            default_sg.append(security_group[0]['GroupName'])
                    if default_sg:
                        append_summary(data, launch_template['LaunchTemplateName'] + ' 시작 템플릿이 기본보안그룹과 연결되어 있습니다.')

                    if len(data['summary']) > 0:
                        check = 'N'
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '007', launch_template['LaunchTemplateName'], launch_template['LaunchTemplateId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_008(self):
        try:
            print('[EC2_008] EBS를 사용하는 EC2 인스턴스가 최대 절전모드 기능이 활성화되어 있는지 확인하시오.')
            for instance in low_data.instances:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws ec2 describe-instances --filter Name=instance-id,Values=' + instance['InstanceId'] +
                            ' --query \"Reservations[*].{Instances:Instances[*].{InstanceId:InstanceId, HibernationOptions:HibernationOptions}}\"',
                            {'Instances': [{'InstanceId': instance['InstanceId'], 'HibernationOptions': instance['HibernationOptions']}]})
                if not instance['HibernationOptions']['Configured']:
                    append_summary(data, instance['InstanceId'] + ' 인스턴스의 최대 절전모드 기능이 비활성화되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '008', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_009(self):
        try:
            print('[EC2_009] ASG(Auto Scaling Groups)에 속하지 않는 인스턴스에 대해 종료 방지 기능을 사용하도록 설정했는지 확인하시오.')
            for instance in low_data.instances:
                if instance['State']['Name'] == 'running':
                    check = 'Y'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    if instance['InstanceId'] not in [auto_scaling_instance['InstanceId'] for auto_scaling_instance in low_data.auto_scaling_instances]:
                        append_data(data, 'aws autoscaling describe-auto-scaling-instances --query \"{AutoScalingInstances:AutoScalingInstances[*].{InstanceId:InstanceId, AutoScalingGroupName:AutoScalingGroupName, LaunchConfigurationName:LaunchConfigurationName}}\"',
                                    {'AutoScalingInstances': [{'InstanceId': auto_scaling_instance['InstanceId'], 'AutoScalingGroupName': auto_scaling_instance['AutoScalingGroupName'],
                                                               'LaunchConfigurationName': auto_scaling_instance['LaunchConfigurationName'] if 'LaunchConfigurationName' in auto_scaling_instance else 'null',
                                                               'LaunchTemplate': auto_scaling_instance['LaunchTemplate'] if 'LaunchTemplate' in auto_scaling_instance else 'null'}
                                                              for auto_scaling_instance in low_data.auto_scaling_instances]})

                        describe_instance_attribute = client.ec2_client.describe_instance_attribute(InstanceId=instance['InstanceId'], Attribute='disableApiTermination')
                        append_data(data, 'aws ec2 describe-instance-attribute --instance-id ' + instance['InstanceId'] + ' --attribute disableApiTermination',
                                    {'DisableApiTermination': {'Value': describe_instance_attribute['DisableApiTermination']}, 'InstanceId': instance['InstanceId']})
                        if not describe_instance_attribute['DisableApiTermination']['Value']:
                            append_summary(data, 'ASG에 속하지 않는 인스턴스 ' + instance['InstanceId'] + ' 가 종료 방지 기능을 사용하지 않습니다.')
                    else:
                        append_data(data, 'aws autoscaling describe-auto-scaling-instances --query \"{AutoScalingInstances:AutoScalingInstances[*].{InstanceId:InstanceId, AutoScalingGroupName:AutoScalingGroupName, LaunchConfigurationName:LaunchConfigurationName}}\"',
                                    {'AutoScalingInstances': [{'InstanceId': auto_scaling_instance['InstanceId'], 'AutoScalingGroupName': auto_scaling_instance['AutoScalingGroupName'],
                                                               'LaunchConfigurationName': auto_scaling_instance['LaunchConfigurationName'] if 'LaunchConfigurationName' in auto_scaling_instance else 'null',
                                                               'LaunchTemplate': auto_scaling_instance['LaunchTemplate'] if 'LaunchTemplate' in auto_scaling_instance else 'null'}
                                                              for auto_scaling_instance in low_data.auto_scaling_instances if auto_scaling_instance['InstanceId'] == instance['InstanceId']]})

                    if len(data['summary']) > 0:
                        check = 'N'
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '009', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_010(self):
        try:
            print('[EC2_010] 인스턴스가 ASG(Auto Scaling Groups) 내에서 실행되었는지 확인하시오.')
            for instance in low_data.instances:
                if instance['State']['Name'] == 'running':
                    check = 'Y'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    if instance['InstanceId'] not in [auto_scaling_instance['InstanceId'] for auto_scaling_instance in low_data.auto_scaling_instances]:
                        append_data(data, 'aws autoscaling describe-auto-scaling-instances --query \"{AutoScalingInstances:AutoScalingInstances[*].{InstanceId:InstanceId, AutoScalingGroupName:AutoScalingGroupName, LaunchConfigurationName:LaunchConfigurationName}}\"',
                                    {'AutoScalingInstances': [{'InstanceId': auto_scaling_instance['InstanceId'], 'AutoScalingGroupName': auto_scaling_instance['AutoScalingGroupName'],
                                                               'LaunchConfigurationName': auto_scaling_instance['LaunchConfigurationName'] if 'LaunchConfigurationName' in auto_scaling_instance else 'null',
                                                               'LaunchTemplate': auto_scaling_instance['LaunchTemplate'] if 'LaunchTemplate' in auto_scaling_instance else 'null'}
                                                              for auto_scaling_instance in low_data.auto_scaling_instances]})
                        append_summary(data, instance['InstanceId'] + ' 인스턴스가 ASG(Auto Scaling Groups) 내에서 실행되지 않습니다.')
                    else:
                        append_data(data, 'aws autoscaling describe-auto-scaling-instances --query \"{AutoScalingInstances:AutoScalingInstances[*].{InstanceId:InstanceId, AutoScalingGroupName:AutoScalingGroupName, LaunchConfigurationName:LaunchConfigurationName}}\"',
                                    {'AutoScalingInstances': [{'InstanceId': auto_scaling_instance['InstanceId'], 'AutoScalingGroupName': auto_scaling_instance['AutoScalingGroupName'],
                                                               'LaunchConfigurationName': auto_scaling_instance['LaunchConfigurationName'] if 'LaunchConfigurationName' in auto_scaling_instance else 'null',
                                                               'LaunchTemplate': auto_scaling_instance['LaunchTemplate'] if 'LaunchTemplate' in auto_scaling_instance else 'null'}
                                                              for auto_scaling_instance in low_data.auto_scaling_instances if auto_scaling_instance['InstanceId'] == instance['InstanceId']]})

                    if len(data['summary']) > 0:
                        check = 'N'
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '010', instance['InstanceId'], instance['InstanceId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_011(self):
        try:
            print('[EC2_011] 인스턴스의 ASG(Auto Scaling Groups)의 시작 구성/시작 템플릿에 각 계층에서 사용하는 보안그룹을 적용하여 구성했는지 확인하시오.')
            for launch_configuration in low_data.launch_configurations:
                check = '?'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws autoscaling describe-launch-configurations --query \"{LaunchConfigurations:LaunchConfigurations[*].{LaunchConfigurationName:LaunchConfigurationName, SecurityGroups:SecurityGroups}}\"',
                            {'LaunchConfigurationName': launch_configuration['LaunchConfigurationName'], 'SecurityGroups': launch_configuration['SecurityGroups']})
                append_summary(data, launch_configuration['LaunchConfigurationName'] + ' 시작 구성에 ' + str(launch_configuration['SecurityGroups']) + ' 이 연결되어 있습니다.\n'
                               '각 계층을 위한 보안그룹이 올바르게 연결되어있는지 확인하시오.')

                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '011', launch_configuration['LaunchConfigurationName'], launch_configuration['LaunchConfigurationARN'], check, str(data)))
            for launch_template in low_data.launch_templates:
                if 'SecurityGroupIds' in low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]:
                    check = '?'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    append_data(data, 'aws ec2 describe-launch-template-versions --launch-template-id ' + launch_template['LaunchTemplateName'] + \
                                ' --query \"{LaunchTemplateVersions:LaunchTemplateVersions[*].{LaunchTemplateId:LaunchTemplateId, LaunchTemplateName:LaunchTemplateName, VersionNumber:VersionNumber, DefaultVersion:DefaultVersion, LaunchTemplateData:LaunchTemplateData}}\"',
                                {'LaunchTemplateVersions': [{'LaunchTemplateId': launch_template_version['LaunchTemplateId'], 'LaunchTemplateName': launch_template_version['LaunchTemplateName'], 'VersionNumber': launch_template_version['VersionNumber'],
                                                             'DefaultVersion': launch_template_version['DefaultVersion'], 'LaunchTemplateData': launch_template_version['LaunchTemplateData']}
                                                            for launch_template_version in low_data.launch_template_versions[launch_template['LaunchTemplateName']]]})
                    append_summary(data, launch_template['LaunchTemplateName'] + ' 시작 템플릿에 ' + \
                                   str(low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]['LaunchTemplateData']['SecurityGroupIds']) + ' 이 연결되어 있습니다.\n'
                                   '각 계층을 위한 보안그룹이 올바르게 연결되어있는지 확인하시오.')
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '011', launch_template['LaunchTemplateName'], launch_template['LaunchTemplateId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_12_util(self, data, security_groups, name):
        for launch_configuration in low_data.launch_configurations:
            check_sg = [security_group for security_group in security_groups if security_group in launch_configuration['SecurityGroups']]
            if check_sg:
                append_data(data, 'aws autoscaling describe-launch-configurations --query \"{LaunchConfigurations:LaunchConfigurations[*].{LaunchConfigurationName:LaunchConfigurationName, SecurityGroups:SecurityGroups}}\"',
                            {'LaunchConfigurationName': launch_configuration['LaunchConfigurationName'], 'SecurityGroups': launch_configuration['SecurityGroups']})
                append_summary(data, name + ' 에 연결된 보안그룹 ' + str(check_sg) + ' 이 시작 구성 ' + launch_configuration['LaunchConfigurationName'] + ' 에 연결되어 있습니다.')
        for launch_template in low_data.launch_templates:
            if 'SecurityGroupIds' in low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]:
                check_sg = [security_group for security_group in security_groups if security_group in low_data.launch_template_versions[launch_template['LaunchTemplateName']][0]['LaunchTemplateData']['SecurityGroupIds']]
                if check_sg:
                    append_data(data, 'aws ec2 describe-launch-template-versions --launch-template-id ' + launch_template['LaunchTemplateName'] + \
                                ' --query \"{LaunchTemplateVersions:LaunchTemplateVersions[*].{LaunchTemplateId:LaunchTemplateId, LaunchTemplateName:LaunchTemplateName, VersionNumber:VersionNumber, DefaultVersion:DefaultVersion, LaunchTemplateData:LaunchTemplateData}}\"',
                                {'LaunchTemplateVersions': [{'LaunchTemplateId': launch_template_version['LaunchTemplateId'], 'LaunchTemplateName': launch_template_version['LaunchTemplateName'], 'VersionNumber': launch_template_version['VersionNumber'],
                                                             'DefaultVersion': launch_template_version['DefaultVersion'], 'LaunchTemplateData': launch_template_version['LaunchTemplateData']}
                                                            for launch_template_version in low_data.launch_template_versions[launch_template['LaunchTemplateName']]]})
                    append_summary(data, name + ' 에 연결된 보안그룹 ' + str(check_sg) + ' 이 시작 템플릿 ' + launch_template['LaunchTemplateName'] + ' 에 연결되어 있습니다.')
        for instance in low_data.instances:
            check_sg = [security_group for security_group in security_groups if security_group in [security_group['GroupId'] for security_group in instance['SecurityGroups']]]
            if check_sg:
                append_data(data, 'aws ec2 describe-instances --filter Name=instance-id,Values=' + instance['InstanceId'] + ' --query \"Reservations[*].{Instances:Instances[*].{InstanceId:InstanceId, SecurityGroups:SecurityGroups}}\"',
                            {'Instances': [{'InstanceId': instance['InstanceId'], 'SecurityGroups': instance['SecurityGroups']}]})
                append_summary(data, name + ' 에 연결된 보안그룹 ' + str(check_sg) + ' 이 인스턴스 ' + instance['InstanceId'] + ' 에 연결되어 있습니다.')

    def ec2_012(self):
        try:
            print('[EC2_012]Web-tier ELB에 연결된 보안그룹이 다른 계층에서 사용되고 있는지 확인하시오.')
            for elb in low_data.load_balancers_v1:
                check = '?'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                security_groups = elb['SecurityGroups']
                self.ec2_12_util(data, security_groups, elb['LoadBalancerName'])

                if len(data['summary']) > 0:
                    append_summary(data, elb['LoadBalancerName'] + ' 이 Web-tier ELB가 아닌지 확인하시오.')
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '012', elb['LoadBalancerName'], elb['LoadBalancerName'], check, str(data)))

            for elbv2 in low_data.load_balancers_v2:
                if elbv2['Type'] == 'application':
                    check = '?'
                    data = {'cli': [], 'raw_data': [], 'summary': []}

                    security_groups = elbv2['SecurityGroups']
                    self.ec2_12_util(data, security_groups, elbv2['LoadBalancerName'])

                    if len(data['summary']) > 0:
                        append_summary(data, elbv2['LoadBalancerName'] + ' 이 Web-tier ELB가 아닌지 확인하시오.')
                    execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '012', elbv2['LoadBalancerName'], elbv2['LoadBalancerArn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_013(self):
        try:
            print('[EC2_013] ELB의 로깅이 설정되어있는지 확인하시오.')
            for load_balancer in low_data.load_balancers_v1:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws elb describe-load-balancer-attributes --load-balancer-name ' + load_balancer['LoadBalancerName'] +
                            ' --query \"{LoadBalancerAttributes:LoadBalancerAttributes.{AccessLog:AccessLog}}\"',
                            {'LoadBalancerAttributes': {'AccessLog': low_data.load_balancer_attribute_v1[load_balancer['LoadBalancerName']]['AccessLog']}})
                if not low_data.load_balancer_attribute_v1[load_balancer['LoadBalancerName']]['AccessLog']['Enabled']:
                    append_summary(data, load_balancer['LoadBalancerName'] + ' ELB의 로깅이 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '013', load_balancer['LoadBalancerName'], load_balancer['LoadBalancerName'], check, str(data)))

            for load_balancer in low_data.load_balancers_v2:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                access_log_attribute = [load_balancer_attribute for load_balancer_attribute in low_data.load_balancer_attribute_v2[load_balancer['LoadBalancerArn']]
                                        if load_balancer_attribute['Key'] == 'access_logs.s3.enabled'][0]
                append_data(data, 'aws elbv2 describe-load-balancer-attributes --load-balancer-arn ' + load_balancer['LoadBalancerArn'],
                            {'Attributes': access_log_attribute})
                if access_log_attribute['Value'] == 'false':
                    append_summary(data, load_balancer['LoadBalancerName'] + ' ELB의 로깅이 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '013', load_balancer['LoadBalancerName'], load_balancer['LoadBalancerArn'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)

    def ec2_014(self):
        try:
            print('[EC2_014] AMI의 암호화를 설정했는지 확인하시오.')
            for image in low_data.images:
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}

                append_data(data, 'aws ec2 describe-images --owners self --filter Name=image-id,Values=' + image['ImageId'] + ' --query \"Images[*].{ImageId:ImageId, BlockDeviceMappings:BlockDeviceMappings}\"',
                            {'ImageId': image['ImageId'], 'Public': image['Public']})
                if [block_device_mapping for block_device_mapping in image['BlockDeviceMappings'] if not block_device_mapping['Ebs']['Encrypted']]:
                    append_summary(data, image['ImageId'] + ' AMI이 암호화가 설정되어있지 않습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                execute_insert_assessment_result_sql((low_data.diagnosis_id, 'EC2', '014', image['Name'], image['ImageId'], check, str(data)))
            print('[+] Complete!')
        except Exception as e:
            print('[!] Error : ' + e)



