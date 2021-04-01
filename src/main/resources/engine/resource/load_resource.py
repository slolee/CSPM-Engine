from common.client import client
from common.db import execute_insert_resource_sql
from botocore.exceptions import ClientError

class LoadResource:
    def __init__(self):
        self.access_key = None

    def set_access_key(self, access_key):
        self.access_key = access_key

    def load_iam_resource(self):
        execute_insert_resource_sql((self.access_key, 'IAM', 'Service', 'IAM', 'IAM', str([])))

        list_users = client.iam_client.get_paginator('list_users').paginate()
        users = [user for users in list_users for user in users['Users']]
        for user in users:
            get_user = client.iam_client.get_user(UserName=user['UserName'])
            tags = get_user['User']['Tags'] if 'Tags' in get_user['User'] else []
            execute_insert_resource_sql((self.access_key, 'IAM', 'User', user['UserName'], user['Arn'], str(tags)))

        list_groups = client.iam_client.get_paginator('list_groups').paginate()
        groups = [group for groups in list_groups for group in groups['Groups']]
        for group in groups:
            execute_insert_resource_sql((self.access_key, 'IAM', 'Group', group['GroupName'], group['Arn'], str([])))

        list_roles = client.iam_client.get_paginator('list_roles').paginate()
        roles = [role for roles in list_roles for role in roles['Roles']]
        for role in roles:
            get_role = client.iam_client.get_role(RoleName=role['RoleName'])
            tags = get_role['Role']['Tags'] if 'Tags' in get_role['Role'] else []
            execute_insert_resource_sql((self.access_key, 'IAM', 'Role', role['RoleName'], role['Arn'], str(tags)))

        # policy에 태그를 설정할 수는 있는데 가져와지지가 않는다... get-policy로 왜 안가져와지지
        list_policies = client.iam_client.get_paginator('list_policies').paginate(Scope='Local')
        policies = [policy for policies in list_policies for policy in policies['Policies']]
        for policy in policies:
            execute_insert_resource_sql((self.access_key, 'IAM', 'Policy', policy['PolicyName'], policy['Arn'], str([])))

    def load_vpc_resource(self):
        execute_insert_resource_sql((self.access_key, 'VPC', 'Service', 'VPC', 'VPC', str([])))

        describe_vpcs = client.ec2_client.get_paginator('describe_vpcs').paginate()
        vpcs = [vpc for vpcs in describe_vpcs for vpc in vpcs['Vpcs']]
        for vpc in vpcs:
            tags = vpc['Tags'] if 'Tags' in vpc else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Vpc', vpc['VpcId'], vpc['VpcId'], str(tags)))

        describe_security_gruops = client.ec2_client.get_paginator('describe_security_groups').paginate()
        security_gruops = [security_gruop for security_gruops in describe_security_gruops for security_gruop in security_gruops['SecurityGroups']]
        for security_gruop in security_gruops:
            tags = security_gruop['Tags'] if 'Tags' in security_gruop else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Security Group', security_gruop['GroupId'], security_gruop['GroupId'], str(tags)))

        describe_network_acls = client.ec2_client.get_paginator('describe_network_acls').paginate()
        network_acls = [network_acl for network_acls in describe_network_acls for network_acl in network_acls['NetworkAcls']]
        for network_acl in network_acls:
            tags = network_acl['Tags'] if 'Tags' in network_acl else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Network ACL', network_acl['NetworkAclId'], network_acl['NetworkAclId'], str(tags)))

        describe_subnets = client.ec2_client.get_paginator('describe_subnets').paginate()
        subnets = [subnet for subnets in describe_subnets for subnet in subnets['Subnets']]
        for subnet in subnets:
            tags = subnet['Tags'] if 'Tags' in subnet else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Subnet', subnet['SubnetId'], subnet['SubnetArn'], str(tags)))

        describe_route_tables = client.ec2_client.get_paginator('describe_route_tables').paginate()
        route_tables = [route_table for route_tables in describe_route_tables for route_table in route_tables['RouteTables']]
        for route_table in route_tables:
            tags = route_table['Tags'] if 'Tags' in route_table else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Route Table', route_table['RouteTableId'], route_table['RouteTableId'], str(tags)))

        describe_internet_gateways = client.ec2_client.get_paginator('describe_internet_gateways').paginate()
        internet_gateways = [internet_gateway for internet_gateways in describe_internet_gateways for internet_gateway in internet_gateways['InternetGateways']]
        for internet_gateway in internet_gateways:
            tags = internet_gateway['Tags'] if 'Tags' in internet_gateway else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Internet Gateway', internet_gateway['InternetGatewayId'], internet_gateway['InternetGatewayId'], str(tags)))

        describe_egress_only_internet_gateways = client.ec2_client.get_paginator('describe_egress_only_internet_gateways').paginate()
        egress_only_internet_gateways = [egress_only_internet_gateway for egress_only_internet_gateways in describe_egress_only_internet_gateways for egress_only_internet_gateway in egress_only_internet_gateways['EgressOnlyInternetGateways']]
        for egress_only_internet_gateway in egress_only_internet_gateways:
            tags = egress_only_internet_gateway['Tags'] if 'Tags' in egress_only_internet_gateway else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Egress Only Internet Gateway', egress_only_internet_gateway['EgressOnlyInternetGatewayId'], egress_only_internet_gateway['EgressOnlyInternetGatewayId'], str(tags)))

        describe_addresses = client.ec2_client.describe_addresses()
        addresses = describe_addresses['Addresses']
        for address in addresses:
            tags = address['Tags'] if 'Tags' in address else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Elastic Ip', address['AllocationId'], address['AllocationId'], str(tags)))

        describe_nat_gateways = client.ec2_client.get_paginator('describe_nat_gateways').paginate()
        nat_gateways = [nat_gateway for nat_gateways in describe_nat_gateways for nat_gateway in nat_gateways['NatGateways']]
        for nat_gateway in nat_gateways:
            tags = nat_gateway['Tags'] if 'Tags' in nat_gateway else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Nat Gateway', nat_gateway['NatGatewayId'], nat_gateway['NatGatewayId'], str(tags)))

        describe_managed_prefix_lists = client.ec2_client.get_paginator('describe_managed_prefix_lists').paginate()
        managed_prefix_lists = [managed_prefix_list for managed_prefix_lists in describe_managed_prefix_lists for managed_prefix_list in managed_prefix_lists['PrefixLists']]
        for managed_prefix_list in managed_prefix_lists:
            tags = managed_prefix_list['Tags'] if 'Tags' in managed_prefix_list else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Prefix List', managed_prefix_list['PrefixListName'], managed_prefix_list['PrefixListArn'], str(tags)))

        describe_vpc_endpoints = client.ec2_client.get_paginator('describe_vpc_endpoints').paginate()
        vpc_endpoints = [vpc_endpoint for vpc_endpoints in describe_vpc_endpoints for vpc_endpoint in vpc_endpoints['VpcEndpoints']]
        for vpc_endpoint in vpc_endpoints:
            tags = vpc_endpoint['Tags'] if 'Tags' in vpc_endpoint else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Vpc Endpoint', vpc_endpoint['VpcEndpointId'], vpc_endpoint['VpcEndpointId'], str(tags)))

        describe_vpc_peering_connections = client.ec2_client.get_paginator('describe_vpc_peering_connections').paginate()
        vpc_peering_connections = [vpc_peering_connection for vpc_peering_connections in describe_vpc_peering_connections for vpc_peering_connection in vpc_peering_connections['VpcPeeringConnections']]
        for vpc_peering_connection in vpc_peering_connections:
            tags = vpc_peering_connection['Tags'] if 'Tags' in vpc_peering_connection else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Vpc Peering Connection', vpc_peering_connection['VpcPeeringConnectionId'], vpc_peering_connection['VpcPeeringConnectionId'], str(tags)))

        describe_customer_gateways = client.ec2_client.describe_customer_gateways()
        customer_gateways = describe_customer_gateways['CustomerGateways']
        for customer_gateway in customer_gateways:
            tags = customer_gateway['Tags'] if 'Tags' in customer_gateway else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Customer Gateway', customer_gateway['CustomerGatewayId'], customer_gateway['CustomerGatewayId'], str(tags)))

        describe_vpn_gateways = client.ec2_client.describe_vpn_gateways()
        vpn_gateways = describe_vpn_gateways['VpnGateways']
        for vpn_gateway in vpn_gateways:
            tags = vpn_gateway['Tags'] if 'Tags' in vpn_gateway else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Vpn Gateway', vpn_gateway['VpnGatewayId'], vpn_gateway['VpnGatewayId'], str(tags)))

        describe_vpn_connections = client.ec2_client.describe_vpn_connections()
        vpn_connections = describe_vpn_connections['VpnConnections']
        for vpn_connection in vpn_connections:
            tags = vpn_connection['Tags'] if 'Tags' in vpn_connection else []
            execute_insert_resource_sql((self.access_key, 'VPC', 'Vpn Connection', vpn_connection['VpnConnectionId'], vpn_connection['VpnConnectionId'], str(tags)))

    def load_ec2_resource(self):
        execute_insert_resource_sql((self.access_key, 'EC2', 'Service', 'EC2', 'EC2', str([])))

        describe_instances = client.ec2_client.get_paginator('describe_instances').paginate()
        instances = []
        for reservation in [instance for instances in describe_instances for instance in instances['Reservations']]:
            instances.extend(reservation['Instances'])
        for instance in instances:
            tags = instance['Tags'] if 'Tags' in instance else []
            execute_insert_resource_sql((self.access_key, 'EC2', 'Instance', instance['InstanceId'], instance['InstanceId'], str(tags)))

        describe_images = client.ec2_client.describe_images(Owners=['self'])
        images = describe_images['Images']
        for image in images:
            tags = image['Tags'] if 'Tags' in image else []
            execute_insert_resource_sql((self.access_key, 'EC2', 'Amazon Machine Image', image['Name'], image['ImageId'], str(tags)))

        describe_auto_scaling_groups = client.autoscaling_client.get_paginator('describe_auto_scaling_groups').paginate()
        auto_scaling_groups = [auto_scaling_group for auto_scaling_groups in describe_auto_scaling_groups for auto_scaling_group in auto_scaling_groups['AutoScalingGroups']]
        for auto_scaling_group in auto_scaling_groups:
            tags = auto_scaling_group['Tags'] if 'Tags' in auto_scaling_group else []
            execute_insert_resource_sql((self.access_key, 'EC2', 'Auto Scaling Group', auto_scaling_group['AutoScalingGroupName'], auto_scaling_group['AutoScalingGroupARN'], str(tags)))

        describe_launch_configurations = client.autoscaling_client.get_paginator('describe_launch_configurations').paginate()
        launch_configurations = [launch_configuration for launch_configurations in describe_launch_configurations for launch_configuration in launch_configurations['LaunchConfigurations']]
        for launch_configuration in launch_configurations:
            execute_insert_resource_sql((self.access_key, 'EC2', 'Launch Configuration', launch_configuration['LaunchConfigurationName'], launch_configuration['LaunchConfigurationARN'], str([])))

        describe_launch_templates = client.ec2_client.get_paginator('describe_launch_templates').paginate()
        launch_templates = [launch_template for launch_templates in describe_launch_templates for launch_template in launch_templates['LaunchTemplates']]
        for launch_template in launch_templates:
            tags = launch_template['Tags'] if 'Tags' in launch_template else []
            execute_insert_resource_sql((self.access_key, 'EC2', 'Launch Template', launch_template['LaunchTemplateName'], launch_template['LaunchTemplateId'], str(tags)))

        describe_load_balancers = client.elb_client.get_paginator('describe_load_balancers').paginate()
        load_balancers_v1 = [load_balancer for load_balancers in describe_load_balancers for load_balancer in load_balancers['LoadBalancerDescriptions']]
        for load_balancer in load_balancers_v1:
            describe_tags = client.elb_client.describe_tags(LoadBalancerNames=[load_balancer['LoadBalancerName']])
            tags = []
            for tag_description in describe_tags['TagDescriptions']:
                tags.extend(tag_description['Tags'])
            execute_insert_resource_sql((self.access_key, 'EC2', 'Load Balancer v1', load_balancer['LoadBalancerName'], load_balancer['LoadBalancerName'], str(tags)))

        describe_load_balancers = client.elbv2_client.get_paginator('describe_load_balancers').paginate()
        load_balancers_v2 = [load_balancer for load_balancers in describe_load_balancers for load_balancer in load_balancers['LoadBalancers']]
        for load_balancer in load_balancers_v2:
            describe_tags = client.elbv2_client.describe_tags(ResourceArns=[load_balancer['LoadBalancerArn']])
            tags = []
            for tag_description in describe_tags['TagDescriptions']:
                tags.extend(tag_description['Tags'])
            execute_insert_resource_sql((self.access_key, 'EC2', 'Load Balancer v2', load_balancer['LoadBalancerName'], load_balancer['LoadBalancerArn'], str(tags)))

    def load_rds_resource(self):
        execute_insert_resource_sql((self.access_key, 'RDS', 'Service', 'RDS', 'RDS', str([])))

        describe_db_instances = client.rds_client.get_paginator('describe_db_instances').paginate()
        db_instances = [db_instance for db_instances in describe_db_instances for db_instance in db_instances['DBInstances']]
        for db_instance in db_instances:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=db_instance['DBInstanceArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Instance', db_instance['DBInstanceIdentifier'], db_instance['DBInstanceArn'], str(tags)))

        describe_db_snapshots = client.rds_client.get_paginator('describe_db_snapshots').paginate()
        db_snapshots = [db_snapshot for db_snapshots in describe_db_snapshots for db_snapshot in db_snapshots['DBSnapshots']]
        for db_snapshot in db_snapshots:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=db_snapshot['DBSnapshotArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Snapshot', db_snapshot['DBSnapshotIdentifier'], db_snapshot['DBSnapshotArn'], str(tags)))

        describe_db_clusters = client.rds_client.get_paginator('describe_db_clusters').paginate()
        db_clusters = [db_cluster for db_clusters in describe_db_clusters for db_cluster in db_clusters['DBClusters']]
        for db_cluster in db_clusters:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=db_cluster['DBClusterArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Cluster', db_cluster['DBClusterIdentifier'], db_cluster['DBClusterArn'], str(tags)))

        describe_db_subnet_groups = client.rds_client.get_paginator('describe_db_subnet_groups').paginate()
        db_subnet_groups = [db_subnet_group for db_subnet_groups in describe_db_subnet_groups for db_subnet_group in db_subnet_groups['DBSubnetGroups']]
        for db_subnet_group in db_subnet_groups:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=db_subnet_group['DBSubnetGroupArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Subnet Group', db_subnet_group['DBSubnetGroupName'], db_subnet_group['DBSubnetGroupArn'], str(tags)))

        describe_db_parameter_groups = client.rds_client.get_paginator('describe_db_parameter_groups').paginate()
        db_parameter_groups = [db_parameter_group for db_parameter_groups in describe_db_parameter_groups for db_parameter_group in db_parameter_groups['DBParameterGroups']]
        for db_parameter_group in db_parameter_groups:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=db_parameter_group['DBParameterGroupArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Parameter Group', db_parameter_group['DBParameterGroupName'], db_parameter_group['DBParameterGroupArn'], str(tags)))

        describe_option_groups = client.rds_client.get_paginator('describe_option_groups').paginate()
        option_groups = [option_group for option_groups in describe_option_groups for option_group in option_groups['OptionGroupsList']]
        for option_group in option_groups:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=option_group['OptionGroupArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Option Group', option_group['OptionGroupName'], option_group['OptionGroupArn'], str(tags)))

        describe_event_subscriptions = client.rds_client.get_paginator('describe_event_subscriptions').paginate()
        event_subscriptions = [event_subscription for event_subscriptions in describe_event_subscriptions for event_subscription in event_subscriptions['EventSubscriptionsList']]
        for event_subscription in event_subscriptions:
            list_tags_for_resource = client.rds_client.list_tags_for_resource(ResourceName=event_subscription['EventSubscriptionArn'])
            tags = list_tags_for_resource['TagList']
            execute_insert_resource_sql((self.access_key, 'RDS', 'Database Event Subscription', event_subscription['CustSubscriptionId'], event_subscription['EventSubscriptionArn'], str(tags)))

    def load_ebs_resource(self):
        execute_insert_resource_sql((self.access_key, 'EBS', 'Service', 'EBS', 'EBS', str([])))

        describe_volumes = client.ec2_client.get_paginator('describe_volumes').paginate()
        volumes = [volume for volumes in describe_volumes for volume in volumes['Volumes']]
        for volume in volumes:
            tags = volume['Tags'] if 'Tags' in volume else []
            execute_insert_resource_sql((self.access_key, 'EBS', 'EBS Volume', volume['VolumeId'], volume['VolumeId'], str(tags)))

        describe_snapshots = client.ec2_client.get_paginator('describe_snapshots').paginate(OwnerIds=[client.AWS_CURRENT_ID['Account']])
        snapshots = [snapshot for snapshots in describe_snapshots for snapshot in snapshots['Snapshots']]
        for snapshot in snapshots:
            tags = snapshot['Tags'] if 'Tags' in snapshot else []
            execute_insert_resource_sql((self.access_key, 'EBS', 'EBS Volume Snapshot', snapshot['SnapshotId'], snapshot['SnapshotId'], str(tags)))

    def load_s3_resource(self):
        execute_insert_resource_sql((self.access_key, 'S3', 'Service', 'S3', 'S3', str([])))

        list_buckets = client.s3_client.list_buckets()
        buckets = list_buckets['Buckets']
        for bucket in buckets:
            tags = []
            try:
                get_bucket_tagging = client.s3_client.get_bucket_tagging(Bucket=bucket['Name'])
                tags = get_bucket_tagging['TagSet']
            except ClientError as e:
                pass
            execute_insert_resource_sql((self.access_key, 'S3', 'S3 Bucket', bucket['Name'], 'arn:aws:s3:::' + bucket['Name'], str(tags)))

    def load_cloudtrail_resource(self):
        execute_insert_resource_sql((self.access_key, 'CloudTrail', 'Service', 'CloudTrail', 'CloudTrail', str([])))

        describe_trails = client.cloudtrail_client.describe_trails()
        trails = describe_trails['trailList']
        for trail in trails:
            list_tags = client.cloudtrail_client.get_paginator('list_tags').paginate(ResourceIdList=[trail['TrailARN']])
            tags = []
            for resource_tag_list in [tag for tags in list_tags for tag in tags['ResourceTagList']]:
                tags.extend(resource_tag_list['TagsList'])
            execute_insert_resource_sql((self.access_key, 'CloudTrail', 'Trail', trail['Name'], trail['TrailARN'], str(tags)))

    def load_cloudwtach_resource(self):
        execute_insert_resource_sql((self.access_key, 'CloudWatch', 'Service', 'CloudWatch', 'CloudWatch', str([])))

        describe_log_groups = client.logs_client.get_paginator('describe_log_groups').paginate()
        log_groups = [log_group for log_groups in describe_log_groups for log_group in log_groups['logGroups']]
        for log_group in log_groups:
            list_tags_log_group = client.logs_client.list_tags_log_group(logGroupName=log_group['logGroupName'])
            tags = [{'Key': key, 'Value': list_tags_log_group['tags'][key]} for key in list_tags_log_group['tags'].keys()]
            execute_insert_resource_sql((self.access_key, 'CloudWatch', 'Log Group', log_group['logGroupName'], log_group['arn'], str(tags)))

        describe_alarms = client.cloudwatch_client.get_paginator('describe_alarms').paginate()
        alarms = [alarm for alarms in describe_alarms for alarm in alarms['MetricAlarms']]
        for alarm in alarms:
            execute_insert_resource_sql((self.access_key, 'CloudWatch', 'Alarm', alarm['AlarmName'], alarm['AlarmArn'], str([])))

    def load_cloudfront_resource(self):
        execute_insert_resource_sql((self.access_key, 'CloudFront', 'Service', 'CloudFront', 'CloudFront', str([])))

        list_distributions = client.cloudfront_client.get_paginator('list_distributions').paginate()
        distributions = [distribution for distributions in list_distributions for distribution in distributions['DistributionList']['Items']]
        for distribution in distributions:
            list_tags_for_resource = client.cloudfront_client.list_tags_for_resource(Resource=distribution['ARN'])
            tags = list_tags_for_resource['Tags']['Items']
            execute_insert_resource_sql((self.access_key, 'CloudFront', 'Distribution', distribution['Id'], distribution['ARN'], str(tags)))

    def load_kms_resource(self):
        execute_insert_resource_sql((self.access_key, 'KMS', 'Service', 'KMS', 'KMS', str([])))

        customer_keys_id = []
        list_aliases = client.kms_client.get_paginator('list_aliases').paginate()
        aliases = [alias for aliases in list_aliases for alias in aliases['Aliases'] if 'TargetKeyId' in alias]
        customer_keys_id = [alias['TargetKeyId'] for alias in aliases if not alias['AliasName'].startswith('alias/aws') and alias['TargetKeyId'] not in customer_keys_id]

        for key in customer_keys_id:
            describe_key = client.kms_client.describe_key(KeyId=key)
            key_detail = describe_key['KeyMetadata']

            list_resource_tags = client.kms_client.list_resource_tags(KeyId=key_detail['KeyId'])
            tags = list_resource_tags['Tags']
            execute_insert_resource_sql((self.access_key, 'KMS', 'Customer Key', key_detail['KeyId'], key_detail['Arn'], str(tags)))

    def load_lambda_resource(self):
        execute_insert_resource_sql((self.access_key, 'Lambda', 'Service', 'Lambda', 'Lambda', str([])))

        list_functions = client.lambda_client.get_paginator('list_functions').paginate()
        functions = [function for functions in list_functions for function in functions['Functions']]
        for function in functions:
            list_tags = client.lambda_client.list_tags(Resource=function['FunctionArn'])
            tags = [{'Key': key, 'Value': list_tags['Tags'][key]} for key in list_tags['Tags'].keys()]
            execute_insert_resource_sql((self.access_key, 'Lambda', 'Function', function['FunctionName'], function['FunctionArn'], str(tags)))


load_resource = LoadResource()