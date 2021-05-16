from botocore.exceptions import ClientError
from common.client import client

class LowData:
    def __init__(self):
        self.diagnosis_id = None

        # IAM
        self.users = []
        self.groups = []
        self.roles = []
        self.credential_report = []
        self.account_summary = None
        self.virtual_mfa_devices = []
        self.policies_only_attached = []
        self.policies_local = []
        self.account_password_policy = None
        self.ssh_public_keys = {}
        self.attached_user_policies = {}
        self.access_keys = {}
        self.user_policies = {}
        self.group_policies = {}
        self.role_policies = {}
        self.server_certificates = []

        # VPC
        self.vpcs = []
        self.security_groups = []
        self.network_acls = []
        self.subnets = []
        self.flow_logs = []
        self.vpc_endpoints = []
        self.vpc_peering_connections = []
        self.vpn_connections = []
        self.nat_gateways = []

        # EC2
        self.images = []
        self.instances = []
        self.auto_scaling_instances = []
        self.launch_configurations = []
        self.launch_templates = []
        self.launch_template_versions = {}
        self.route_tables = []
        self.load_balancers_v1 = []
        self.load_balancers_v2 = []
        self.load_balancer_attribute_v1 = {}
        self.load_balancer_attribute_v2 = {}

        # RDS
        self.db_instances = []
        self.db_parameter_groups = []
        self.db_parameters = {}
        self.option_groups = []
        self.db_snapshots = []
        self.db_snapshot_attributes = {}
        self.event_subscriptions = []
        self.reserved_db_instances = []
        self.db_clusters = []
        self.secrets = []
        self.secret_values = {}
        self.backup_plans = []
        self.list_backup_selections = []
        self.backup_selections = {}

        # S3
        self.buckets = []
        self.buckets_policy = {}
        self.buckets_acl = {}
        self.buckets_encryption = {}
        self.buckets_versioning = {}
        self.buckets_lifecycle_configuration = {}
        self.buckets_object_lock_configuration = {}
        self.buckets_logging = {}

        # EBS
        self.snapshots = []
        self.volumes = []
        self.ebs_encryption_by_default = None

        # CloudTrail
        self.trails = []
        self.trail_status = {}
        self.event_selectors = {}

        # CloudWatch
        self.log_groups = []
        self.metric_filters = {}
        self.log_group_on_trails = []
        self.metric_alarms = []

        # CloudFront
        self.distributions = []
        self.distribution_detail = {}

        # KMS
        self.aliases = []
        self.customer_keys_id = []
        self.key_policies = {}
        self.keys = {}

        # Lambda
        self.functions = []
        self.function_policies = {}

    def init_diagnosis_id(self, diagnosis_id):
        self.diagnosis_id = diagnosis_id

    def load_iam_low_data(self):
        get_credential_report = None
        while not get_credential_report:
            try:
                get_credential_report = client.iam_client.get_credential_report()
            except ClientError as e:
                client.iam_client.generate_credential_report()

        credentials = get_credential_report['Content'].decode('UTF-8').split('\n')
        for i in range(1, len(credentials)):
            credential = {}
            for j in range(len(credentials[i].split(','))):
                credential[credentials[0].split(',')[j]] = credentials[i].split(',')[j]
            self.credential_report.append(credential)

        if not self.users:
            list_users = client.iam_client.get_paginator('list_users').paginate()
            self.users = [user for users in list_users for user in users['Users']]
        if not self.groups:
            list_groups = client.iam_client.get_paginator('list_groups').paginate()
            self.groups = [group for groups in list_groups for group in groups['Groups']]
        if not self.roles:
            list_roles = client.iam_client.get_paginator('list_roles').paginate()
            self.roles = [role for roles in list_roles for role in roles['Roles']]
        if not self.account_summary:
            self.account_summary = client.iam_client.get_account_summary()['SummaryMap']
        if not self.virtual_mfa_devices:
            list_virtual_mfa_devices = client.iam_client.get_paginator('list_virtual_mfa_devices').paginate()
            self.virtual_mfa_devices = [virtual_mfa_device for virtual_mfa_devices in list_virtual_mfa_devices for virtual_mfa_device in virtual_mfa_devices['VirtualMFADevices']]
        if not self.policies_only_attached:
            list_policies_only_attached = client.iam_client.get_paginator('list_policies').paginate(OnlyAttached=True)
            self.policies_only_attached = [policy_only_attached for policies_only_attached in list_policies_only_attached for policy_only_attached in policies_only_attached['Policies']]
        if not self.policies_local:
            list_policies_local = client.iam_client.get_paginator('list_policies').paginate(Scope='Local')
            self.policies_local = [policy_local for policies_local in list_policies_local for policy_local in policies_local['Policies']]
        if not self.account_password_policy:
            try:
                self.account_password_policy = client.iam_client.get_account_password_policy()['PasswordPolicy']
            except ClientError as e:
                self.account_password_policy = {}
        if not self.ssh_public_keys:
            for user in self.users:
                list_ssh_public_keys = client.iam_client.get_paginator('list_ssh_public_keys').paginate(UserName=user['UserName'])
                self.ssh_public_keys[user['UserName']] = [ssh_public_key for ssh_public_keys in list_ssh_public_keys for ssh_public_key in ssh_public_keys['SSHPublicKeys']]
        if not self.attached_user_policies:
            for user in self.users:
                list_attached_user_policies = client.iam_client.get_paginator('list_attached_user_policies').paginate(UserName=user['UserName'])
                self.attached_user_policies[user['UserName']] = [attached_user_policie for attached_user_policies in list_attached_user_policies for attached_user_policie in attached_user_policies['AttachedPolicies']]
        if not self.access_keys:
            for user in self.users:
                list_access_keys = client.iam_client.get_paginator('list_access_keys').paginate(UserName=user['UserName'])
                self.access_keys[user['UserName']] = [access_key for access_keys in list_access_keys for access_key in access_keys['AccessKeyMetadata']]
        if not self.user_policies:
            for user in self.users:
                list_user_policies = client.iam_client.get_paginator('list_user_policies').paginate(UserName=user['UserName'])
                self.user_policies[user['UserName']] = [user_policy for user_policies in list_user_policies for user_policy in user_policies['PolicyNames']]
        if not self.group_policies:
            for group in self.groups:
                list_group_policies = client.iam_client.get_paginator('list_group_policies').paginate(GroupName=group['GroupName'])
                self.group_policies[group['GroupName']] = [group_policy for group_policies in list_group_policies for group_policy in group_policies['PolicyNames']]
        if not self.role_policies:
            for role in self.roles:
                list_role_policies = client.iam_client.get_paginator('list_role_policies').paginate(RoleName=role['RoleName'])
                self.role_policies[role['RoleName']] = [role_policy for role_policies in list_role_policies for role_policy in role_policies['PolicyNames']]
        if not self.server_certificates:
            list_server_certificates = client.iam_client.get_paginator('list_server_certificates').paginate()
            server_certificates_name = [server_certificate['ServerCertificateName'] for server_certificates in list_server_certificates for server_certificate in server_certificates['ServerCertificateMetadataList']]
            for name in server_certificates_name:
                self.server_certificates = client.iam_client.get_server_certificate(ServerCertificateName=name)['ServerCertificate']

    def load_vpc_low_data(self):
        if not self.vpcs:
            describe_vpcs = client.ec2_client.get_paginator('describe_vpcs').paginate()
            self.vpcs = [vpc for vpcs in describe_vpcs for vpc in vpcs['Vpcs']]
        if not self.security_groups:
            describe_security_groups = client.ec2_client.get_paginator('describe_security_groups').paginate()
            self.security_groups = [security_group for security_groups in describe_security_groups for security_group in security_groups['SecurityGroups']]
        if not self.network_acls:
            describe_network_acls = client.ec2_client.get_paginator('describe_network_acls').paginate()
            self.network_acls = [network_acl for network_acls in describe_network_acls for network_acl in network_acls['NetworkAcls']]
        if not self.subnets:
            describe_subnets = client.ec2_client.get_paginator('describe_subnets').paginate()
            self.subnets = [subnet for subnets in describe_subnets for subnet in subnets['Subnets']]
        if not self.flow_logs:
            describe_flow_logs = client.ec2_client.get_paginator('describe_flow_logs').paginate()
            self.flow_logs = [flow_log for flow_logs in describe_flow_logs for flow_log in flow_logs['FlowLogs']]
        if not self.vpc_endpoints:
            describe_vpc_endpoints = client.ec2_client.get_paginator('describe_vpc_endpoints').paginate()
            self.vpc_endpoints = [vpc_endpoint for vpc_endpoints in describe_vpc_endpoints for vpc_endpoint in vpc_endpoints['VpcEndpoints']]
        if not self.vpc_peering_connections:
            describe_vpc_peering_connections = client.ec2_client.get_paginator('describe_vpc_peering_connections').paginate()
            self.vpc_peering_connections = [vpc_peering_connection for vpc_peering_connections in describe_vpc_peering_connections for vpc_peering_connection in vpc_peering_connections['VpcPeeringConnections']]
        if not self.vpn_connections:
            describe_vpn_connections = client.ec2_client.describe_vpn_connections()
            self.vpn_connections = describe_vpn_connections['VpnConnections']
        if not self.nat_gateways:
            describe_nat_gateways = client.ec2_client.get_paginator('describe_nat_gateways').paginate()
            self.nat_gateways = [nat_gateway for nat_gateways in describe_nat_gateways for nat_gateway in nat_gateways['NatGateways']]

    def load_ec2_low_data(self):
        if not self.images:
            describe_images = client.ec2_client.describe_images(Owners=['self'])
            self.images = describe_images['Images']
        if not self.instances:
            describe_instances = client.ec2_client.get_paginator('describe_instances').paginate()
            for reservation in [instance for instances in describe_instances for instance in instances['Reservations']]:
                self.instances.extend(reservation['Instances'])
        if not self.auto_scaling_instances:
            describe_auto_scaling_instances = client.autoscaling_client.get_paginator('describe_auto_scaling_instances').paginate()
            self.auto_scaling_instances = [auto_scaling_instance for auto_scaling_instances in describe_auto_scaling_instances for auto_scaling_instance in auto_scaling_instances['AutoScalingInstances']]
        if not self.launch_configurations:
            describe_launch_configurations = client.autoscaling_client.get_paginator('describe_launch_configurations').paginate()
            self.launch_configurations = [launch_configuration for launch_configurations in describe_launch_configurations for launch_configuration in launch_configurations['LaunchConfigurations']]
        if not self.launch_templates:
            describe_launch_templates = client.ec2_client.get_paginator('describe_launch_templates').paginate()
            self.launch_templates = [launch_template for launch_templates in describe_launch_templates for launch_template in launch_templates['LaunchTemplates']]
        if not self.launch_template_versions:
            for launch_template in self.launch_templates:
                describe_launch_template_versions = client.ec2_client.get_paginator('describe_launch_template_versions').paginate(LaunchTemplateName=launch_template['LaunchTemplateName'])
                self.launch_template_versions[launch_template['LaunchTemplateName']] = [launch_template_version for launch_template_versions in describe_launch_template_versions
                                                                                        for launch_template_version in launch_template_versions['LaunchTemplateVersions'] if launch_template_version['DefaultVersion']]
        if not self.route_tables:
            describe_route_tables = client.ec2_client.get_paginator('describe_route_tables').paginate()
            self.route_tables = [route_table for route_tables in describe_route_tables for route_table in route_tables['RouteTables']]
        if not self.load_balancers_v1:
            describe_load_balancers = client.elb_client.get_paginator('describe_load_balancers').paginate()
            self.load_balancers_v1 = [load_balancer for load_balancers in describe_load_balancers for load_balancer in load_balancers['LoadBalancerDescriptions']]
        if not self.load_balancers_v2:
            describe_load_balancers = client.elbv2_client.get_paginator('describe_load_balancers').paginate()
            self.load_balancers_v2 = [load_balancer for load_balancers in describe_load_balancers for load_balancer in load_balancers['LoadBalancers']]
        if not self.load_balancer_attribute_v1:
            for load_balancer in self.load_balancers_v1:
                describe_load_balancer_attributes = client.elb_client.describe_load_balancer_attributes(LoadBalancerName=load_balancer['LoadBalancerName'])
                self.load_balancer_attribute_v1[load_balancer['LoadBalancerName']] = describe_load_balancer_attributes['LoadBalancerAttributes']
        if not self.load_balancer_attribute_v2:
            for load_balancer in self.load_balancers_v2:
                describe_load_balancer_attributes = client.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer['LoadBalancerArn'])
                self.load_balancer_attribute_v2[load_balancer['LoadBalancerArn']] = describe_load_balancer_attributes['Attributes']
        if not self.security_groups:
            describe_security_groups = client.ec2_client.get_paginator('describe_security_groups').paginate()
            self.security_groups = [security_group for security_groups in describe_security_groups for security_group in security_groups['SecurityGroups']]

    def load_rds_low_data(self):
        if not self.db_instances:
            describe_db_instances = client.rds_client.get_paginator('describe_db_instances').paginate()
            self.db_instances = [db_instance for db_instances in describe_db_instances for db_instance in db_instances['DBInstances']]
        if not self.db_parameter_groups:
            describe_db_parameter_groups = client.rds_client.get_paginator('describe_db_parameter_groups').paginate()
            self.db_parameter_groups = [db_parameter_group for db_parameter_groups in describe_db_parameter_groups for db_parameter_group in db_parameter_groups['DBParameterGroups']]
        if not self.db_parameters:
            for db_parameter_group in self.db_parameter_groups:
                describe_db_parameters = client.rds_client.get_paginator('describe_db_parameters').paginate(DBParameterGroupName=db_parameter_group['DBParameterGroupName'])
                self.db_parameters[db_parameter_group['DBParameterGroupName']] = [db_parameter for db_parameters in describe_db_parameters for db_parameter in db_parameters['Parameters']]
        if not self.db_snapshots:
            describe_db_snapshots = client.rds_client.get_paginator('describe_db_snapshots').paginate()
            self.db_snapshots = [db_snapshot for db_snapshots in describe_db_snapshots for db_snapshot in db_snapshots['DBSnapshots']]
        if not self.db_snapshot_attributes:
            for db_snapshot in self.db_snapshots:
                describe_db_snapshot_attributes = client.rds_client.describe_db_snapshot_attributes(DBSnapshotIdentifier=db_snapshot['DBSnapshotIdentifier'])
                self.db_snapshot_attributes[db_snapshot['DBSnapshotIdentifier']] = describe_db_snapshot_attributes['DBSnapshotAttributesResult']['DBSnapshotAttributes']
        if not self.event_subscriptions:
            describe_event_subscriptions = client.rds_client.get_paginator('describe_event_subscriptions').paginate()
            self.event_subscriptions = [event_subscription for event_subscriptions in describe_event_subscriptions for event_subscription in event_subscriptions['EventSubscriptionsList']]
        if not self.reserved_db_instances:
            describe_reserved_db_instances = client.rds_client.get_paginator('describe_reserved_db_instances').paginate()
            self.reserved_db_instances = [reserved_db_instance for reserved_db_instances in describe_reserved_db_instances for reserved_db_instance in reserved_db_instances['ReservedDBInstances']]
        if not self.db_clusters:
            describe_db_clusters = client.rds_client.get_paginator('describe_db_clusters').paginate()
            self.db_clusters = [db_cluster for db_clusters in describe_db_clusters for db_cluster in db_clusters['DBClusters']]
        if not self.aliases:
            list_aliases = client.kms_client.get_paginator('list_aliases').paginate()
            self.aliases = [alias for aliases in list_aliases for alias in aliases['Aliases'] if 'TargetKeyId' in alias]
            self.customer_keys_id = [alias['TargetKeyId'] for alias in self.aliases if not alias['AliasName'].startswith('alias/aws') and alias['TargetKeyId'] not in self.customer_keys_id]
        if not self.keys:
            for key in self.customer_keys_id:
                describe_key = client.kms_client.describe_key(KeyId=key)
                self.keys[key] = describe_key['KeyMetadata']
        if not self.secrets:
            list_secrets = client.secretsmanager_client.get_paginator('list_secrets').paginate()
            self.secrets = [secret for secrets in list_secrets for secret in secrets['SecretList']]
        if not self.secret_values:
            try:
                for secret in self.secrets:
                    get_secret_value = client.secretsmanager_client.get_secret_value(SecretId=secret['ARN'])
                    self.secret_values[secret['ARN']] = get_secret_value['SecretString']
            except ClientError as e:
                self.secret_values = {'Error': 'Error'}
        if not self.backup_plans:
            try:
                list_backup_plans = client.backup_client.list_backup_plans()
                self.backup_plans = list_backup_plans['BackupPlansList']
            except ClientError as e:
                self.backup_plans = [{'Error': 'Error'}]
        if not self.backup_selections:
            if [backup_plan for backup_plan in self.backup_plans if 'Error' in backup_plan]:
                self.backup_selections = {'Error': 'Error'}
            else:
                try:
                    for backup_plan in self.backup_plans:
                        self.list_backup_selections = client.backup_client.list_backup_selections(BackupPlanId=backup_plan['BackupPlanId'])
                        for backup_selection in self.list_backup_selections['BackupSelectionsList']:
                            get_backup_selection = client.backup_client.get_backup_selection(BackupPlanId=backup_plan['BackupPlanId'], SelectionId=backup_selection['SelectionId'])
                            self.backup_selections[backup_selection['SelectionId']] = \
                                {'BackupSelection': get_backup_selection['BackupSelection'], 'BackupPlanId': get_backup_selection['BackupPlanId'], 'SelectionId': get_backup_selection['SelectionId']}
                except ClientError as e:
                    self.backup_selections = {'Error': 'Error'}

    def load_ebs_low_data(self):
        if not self.snapshots:
            describe_snapshots = client.ec2_client.get_paginator('describe_snapshots').paginate(OwnerIds=[client.AWS_CURRENT_ID['Account']])
            self.snapshots = [snapshot for snapshots in describe_snapshots for snapshot in snapshots['Snapshots']]
        if not self.volumes:
            describe_volumes = client.ec2_client.get_paginator('describe_volumes').paginate()
            self.volumes = [volume for volumes in describe_volumes for volume in volumes['Volumes']]
        if not self.ebs_encryption_by_default:
            try:
                self.ebs_encryption_by_default = client.ec2_client.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
            except ClientError as e:
                self.ebs_encryption_by_default = 'Error'
        if not self.aliases:
            list_aliases = client.kms_client.get_paginator('list_aliases').paginate()
            self.aliases = [alias for aliases in list_aliases for alias in aliases['Aliases'] if 'TargetKeyId' in alias]
            self.customer_keys_id = [alias['TargetKeyId'] for alias in self.aliases if not alias['AliasName'].startswith('alias/aws') and alias['TargetKeyId'] not in self.customer_keys_id]
        if not self.keys:
            for key in self.customer_keys_id:
                describe_key = client.kms_client.describe_key(KeyId=key)
                self.keys[key] = describe_key['KeyMetadata']
        if not self.aliases:
            list_aliases = client.kms_client.get_paginator('list_aliases').paginate()
            self.aliases = [alias for aliases in list_aliases for alias in aliases['Aliases'] if 'TargetKeyId' in alias]
            self.customer_keys_id = [alias['TargetKeyId'] for alias in self.aliases if not alias['AliasName'].startswith('alias/aws') and alias['TargetKeyId'] not in self.customer_keys_id]

    def load_s3_low_data(self):
        if not self.buckets:
            list_buckets = client.s3_client.list_buckets()
            self.buckets = list_buckets['Buckets']
        if not self.buckets_policy:
            for bucket in self.buckets:
                try:
                    get_bucket_policy = client.s3_client.get_bucket_policy(Bucket=bucket['Name'])
                    self.buckets_policy[bucket['Name']] = get_bucket_policy['Policy']
                except ClientError as e:
                    self.buckets_policy[bucket['Name']] = []
        if not self.buckets_acl:
            for bucket in self.buckets:
                get_bucket_acl = client.s3_client.get_bucket_acl(Bucket=bucket['Name'])
                self.buckets_acl[bucket['Name']] = get_bucket_acl['Grants']
        if not self.buckets_encryption:
            for bucket in self.buckets:
                try:
                    get_bucket_encryption = client.s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                    self.buckets_encryption[bucket['Name']] = get_bucket_encryption['ServerSideEncryptionConfiguration']['Rules']
                except ClientError as e:
                    self.buckets_encryption[bucket['Name']] = []
        if not self.buckets_versioning:
            for bucket in self.buckets:
                get_bucket_versioning = client.s3_client.get_bucket_versioning(Bucket=bucket['Name'])
                if 'Status' in get_bucket_versioning:
                    self.buckets_versioning[bucket['Name']] = get_bucket_versioning
                else:
                    self.buckets_versioning[bucket['Name']] = {}
        if not self.buckets_lifecycle_configuration:
            for bucket in self.buckets:
                try:
                    get_bucket_lifecycle_configuration = client.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket['Name'])
                    self.buckets_lifecycle_configuration[bucket['Name']] = get_bucket_lifecycle_configuration['Rules']
                except ClientError as e:
                    self.buckets_lifecycle_configuration[bucket['Name']] = []
        if not self.buckets_object_lock_configuration:
            for bucket in self.buckets:
                try:
                    get_object_lock_configuration = client.s3_client.get_object_lock_configuration(Bucket=bucket['Name'])
                    self.buckets_object_lock_configuration[bucket['Name']] = get_object_lock_configuration['ObjectLockConfiguration']
                except ClientError as e:
                    self.buckets_object_lock_configuration[bucket['Name']] = {}
        if not self.buckets_logging:
            for bucket in self.buckets:
                get_bucket_logging = client.s3_client.get_bucket_logging(Bucket=bucket['Name'])
                if 'LoggingEnabled' in get_bucket_logging:
                    self.buckets_logging[bucket['Name']] = get_bucket_logging['LoggingEnabled']
                else:
                    self.buckets_logging[bucket['Name']] = {}

    def load_cloudtrail_low_data(self):
        if not self.trails:
            describe_trails = client.cloudtrail_client.describe_trails()
            self.trails = describe_trails['trailList']
        if not self.trail_status:
            for trail in self.trails:
                self.trail_status[trail['TrailARN']] = client.cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
        if not self.event_selectors:
            for trail in self.trails:
                self.event_selectors[trail['TrailARN']] = client.cloudtrail_client.get_event_selectors(TrailName=trail['TrailARN'])

    def load_cloudwatch_low_data(self):
        if not self.trails:
            describe_trails = client.cloudtrail_client.describe_trails()
            self.trails = describe_trails['trailList']
        if not self.trail_status:
            for trail in self.trails:
                self.trail_status[trail['TrailARN']] = client.cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
        if not self.event_selectors:
            for trail in self.trails:
                self.event_selectors[trail['TrailARN']] = client.cloudtrail_client.get_event_selectors(TrailName=trail['TrailARN'])
        if not self.log_groups:
            describe_log_groups = client.logs_client.get_paginator('describe_log_groups').paginate()
            self.log_groups = [log_group for log_groups in describe_log_groups for log_group in log_groups['logGroups']]
        if not self.log_group_on_trails:
            for trail in self.trails:
                if trail['IsMultiRegionTrail'] and low_data.trail_status[trail['TrailARN']]['IsLogging']:
                    get_event_selectors = low_data.event_selectors[trail['TrailARN']]
                    if 'EventSelectors' in get_event_selectors:
                        management_event_selectors = [event_selector for event_selector in get_event_selectors['EventSelectors'] if event_selector['IncludeManagementEvents']]
                        if management_event_selectors:
                            management_event_selectors_read_write_type = [management_event_selector['ReadWriteType'] for management_event_selector in management_event_selectors]
                            if 'All' in management_event_selectors_read_write_type:
                                self.log_group_on_trails.extend([log_group for log_group in low_data.log_groups if 'CloudWatchLogsLogGroupArn' in trail and log_group['arn'] == trail['CloudWatchLogsLogGroupArn']])
                    elif 'AdvancedEventSelectors' in get_event_selectors:
                        management_field_selectors = [advanced_event_selector['FieldSelectors'] for advanced_event_selector in get_event_selectors['AdvancedEventSelectors']
                                                      if {'Field': 'eventCategory', 'Equals': ['Management']} in advanced_event_selector['FieldSelectors']]
                        if management_field_selectors and {'Field': 'readOnly', 'Equals': ['true']} not in management_field_selectors[0] and {'Field': 'readOnly', 'Equals': ['false']} not in management_field_selectors[0]:
                            self.log_group_on_trails.extend([log_group for log_group in low_data.log_groups if 'CloudWatchLogsLogGroupArn' in trail and log_group['arn'] == trail['CloudWatchLogsLogGroupArn']])
        if not self.metric_filters:
            for log_group in self.log_groups:
                describe_metric_filters = client.logs_client.get_paginator('describe_metric_filters').paginate(logGroupName=log_group['logGroupName'])
                self.metric_filters[log_group['logGroupName']] = [metric_filter for metric_filters in describe_metric_filters for metric_filter in metric_filters['metricFilters']]
        if not self.metric_alarms:
            describe_alarms = client.cloudwatch_client.get_paginator('describe_alarms').paginate()
            self.metric_alarms = [alarm for alarms in describe_alarms for alarm in alarms['MetricAlarms']]

    def load_cloudfront_low_data(self):
        if not self.distributions:
            list_distributions = client.cloudfront_client.get_paginator('list_distributions').paginate()
            self.distributions = [distribution for distributions in list_distributions if 'Items' in distributions['DistributionList'] for distribution in distributions['DistributionList']['Items']]
        if not self.distribution_detail:
            for distribution in self.distributions:
                get_distribution_config = client.cloudfront_client.get_distribution(Id=distribution['Id'])
                self.distribution_detail[distribution['Id']] = get_distribution_config['Distribution']

    def load_kms_low_data(self):
        if not self.aliases:
            list_aliases = client.kms_client.get_paginator('list_aliases').paginate()
            self.aliases = [alias for aliases in list_aliases for alias in aliases['Aliases'] if 'TargetKeyId' in alias]
            self.customer_keys_id = [alias['TargetKeyId'] for alias in self.aliases if not alias['AliasName'].startswith('alias/aws') and alias['TargetKeyId'] not in self.customer_keys_id]
        if not self.key_policies:
            for alias in self.aliases:
                get_key_policy = client.kms_client.get_key_policy(KeyId=alias['TargetKeyId'], PolicyName='default')
                self.key_policies[alias['TargetKeyId']] = get_key_policy['Policy']
        if not self.keys:
            for key in self.customer_keys_id:
                describe_key = client.kms_client.describe_key(KeyId=key)
                self.keys[key] = describe_key['KeyMetadata']

    def load_lambda_low_data(self):
        if not self.functions:
            list_functions = client.lambda_client.get_paginator('list_functions').paginate()
            self.functions = [function for functions in list_functions for function in functions['Functions']]
        if not self.function_policies:
            for function in self.functions:
                try:
                    get_policy = client.lambda_client.get_policy(FunctionName=function['FunctionName'])
                    self.function_policies[function['FunctionName']] = get_policy['Policy']
                except ClientError as e:
                    self.function_policies[function['FunctionName']] = ''


low_data = LowData()