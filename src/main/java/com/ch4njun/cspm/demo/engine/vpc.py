from Common.data import low_data, AWS_CURRENT_ID
from Common.client import *
from Common.db_profile import execute_insert_sql
from Common.utils import *
import boto3, json
from botocore.exceptions import ClientError

class VPC:
    def __init__(self):
        low_data.load_vpc_low_data()

    def audit_all(self):
        self.vpc_001()
        self.vpc_002()
        self.vpc_003()
        self.vpc_004()
        self.vpc_005()
        self.vpc_006()
        self.vpc_007()
        self.vpc_008()
        self.vpc_009()
        self.vpc_010()
        self.vpc_011()
        self.vpc_012()
        self.vpc_013()
        self.vpc_014()
        self.vpc_015()
        self.vpc_016()
        self.vpc_017()
        self.vpc_018()
        self.vpc_019()
        self.vpc_020()
        self.vpc_021()
        self.vpc_022()
        self.vpc_023()

    def vpc_001(self):
        print('[VPC_001] 기본 보안그룹에 트래픽을 허용하는 규칙이 존재하는지 확인하시오.')

        for security_group in low_data.security_groups:
            if security_group['GroupName'] == 'default':
                check = 'Y'
                data = {'cli': [], 'raw_data': [], 'summary': []}
                if security_group['IpPermissions']:
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
                    append_summary(data, '기본 보안그룹 ' + security_group['GroupId'] + ' 에 인바운드 트래픽을 허용하는 규칙이 포함되어 있습니다.')
                if security_group['IpPermissionsEgress']:
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissionsEgress:IpPermissionsEgress}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
                    append_summary(data, '기본 보안그룹 ' + security_group['GroupId'] + ' 에 아웃바운드 트래픽을 허용하는 규칙이 포함되어 있습니다.')

                if len(data['summary']) > 0:
                    check = 'N'
                else:
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions, IpPermissionsEgress:IpPermissionsEgress}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
                execute_insert_sql((low_data.diagnosis_id, 'VPC', '001', security_group['GroupId'], check, str(data)))
        print()

    def vpc_002(self):
        print('[VPC_002] 모든 포트에 대한 트래픽을 허용하는 인바운드 혹은 아웃바운드 규칙을 포함하는 보안그룹이 존재하는지 확인하시오.')
        for security_group in low_data.security_groups:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            for ipPermission in security_group['IpPermissions']:
                if ipPermission['IpProtocol'] == '-1':
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
                    append_summary(data, security_group['GroupId'] + ' 에 모든 트래픽을 허용하는 인바운드 규칙이 포함되어 있습니다.')
                elif ipPermission['FromPort'] == 0 and ipPermission['ToPort'] == 65535:
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
                    append_summary(data, security_group['GroupId'] + ' 에 모든 포트에 대한 트래픽을 허용하는 인바운드 규칙이 포함되어 있습니다.')
            for ipPermissionEgress in security_group['IpPermissionsEgress']:
                if ipPermissionEgress['IpProtocol'] == '-1':
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissionsEgress:IpPermissionsEgress}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
                    append_summary(data, security_group['GroupId'] + ' 에 모든 트래픽을 허용하는 아웃바운드 규칙이 포함되어 있습니다.')
                elif ipPermissionEgress['FromPort'] == 0 and ipPermissionEgress['ToPort'] == 65535:
                    append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissionsEgress:IpPermissionsEgress}\"',
                                {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
                    append_summary(data, security_group['GroupId'] + ' 에 모든 포트에 대한 트래픽을 허용하는 아웃바운드 규칙이 포함되어 있습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            else:
                append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions, IpPermissionsEgress:IpPermissionsEgress}\"',
                            {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '002', security_group['GroupId'], check, str(data)))
        print()

    def vpc_003(self):
        print('[VPC_003] 보안그룹에 0.0.0.0/0 혹은 ::/0 에서 불필요한 포트로 액세스하는 것을 허용하는 인바운드 규칙이 존재하는지 확인하시오.')
        tcp_ports = [20, 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 11211, 27017]
        udp_ports = [53, 137, 138, 6379, 11211]
        for security_group in low_data.security_groups:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                        {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
            for ipPermission in security_group['IpPermissions']:
                if '0.0.0.0/0' in [ipRange['CidrIp'] for ipRange in ipPermission['IpRanges']] or \
                        '::/0' in [ipRange['CidrIpv6'] for ipRange in ipPermission['Ipv6Ranges']]:
                    if ipPermission['IpProtocol'] == '-1':
                        append_summary(data, security_group['GroupId'] + ' 에 모든 트래픽을 허용하는 인바운드 규칙이 포함되어 있습니다.')
                    elif ipPermission['IpProtocol'] == 'tcp':
                        result = filter(lambda tcp_port: ipPermission['FromPort'] <= tcp_port <= ipPermission['ToPort'], tcp_ports)
                        append_summary(data, security_group['GroupId'] + ' 에 0.0.0.0/0 혹은 ::/0 에서 tcp ' + str(list(result)) + '번 포트로 액세스하는 것을 허용하는 인바운드 규칙이 존재합니다.')
                    elif ipPermission['IpProtocol'] == 'udp':
                        result = filter(lambda udp_port: ipPermission['FromPort'] <= udp_port <= ipPermission['ToPort'], udp_ports)
                        append_summary(data, security_group['GroupId'] + ' 에 0.0.0.0/0 혹은 ::/0 에서 udp ' + str(list(result)) + '번 포트로 액세스하는 것을 허용하는 인바운드 규칙이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '003', security_group['GroupId'], check, str(data)))
        print()

    def vpc_004(self):
        print('[VPC_004] 보안그룹에 0.0.0.0/0 혹은 ::/0 에서 ICMP, ICMPv6 액세스하는 것을 허용하는 인바운드 규칙이 존재하는지 확인하시오.')
        for security_group in low_data.security_groups:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                        {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
            for ipPermission in security_group['IpPermissions']:
                if '0.0.0.0/0' in [ipRange['CidrIp'] for ipRange in ipPermission['IpRanges']] or \
                        '::/0' in [ipRange['CidrIpv6'] for ipRange in ipPermission['Ipv6Ranges']]:
                    if ipPermission['IpProtocol'] == '-1':
                        append_summary(data, security_group['GroupId'] + ' 에 모든 트래픽을 허용하는 인바운드 규칙이 포함되어 있습니다.')
                    elif ipPermission['IpProtocol'] == 'icmp':
                        if ipPermission['FromPort'] == -1 and ipPermission['ToPort'] == -1:
                            append_summary(data, security_group['GroupId'] + ' 에 0.0.0.0/0 에서 ICMP 액세스하는 것을 허용하는 인바운드 규칙이 존재합니다.')
                    elif ipPermission['IpProtocol'] == 'icmpv6':
                        if ipPermission['FromPort'] == -1 and ipPermission['ToPort'] == -1:
                            append_summary(data, security_group['GroupId'] + ' 에 ::/0 에서 ICMPv6 액세스하는 것을 허용하는 인바운드 규칙이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '004', security_group['GroupId'], check, str(data)))
        print()

    def vpc_005(self):
        print('[VPC_005] 보안그룹에 0.0.0.0/0 혹은 ::/0 에 액세스하는 것을 허용하는 아웃바운드 규칙이 존재하는지 확인하시오.')
        for security_group in low_data.security_groups:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissionsEgress:IpPermissionsEgress}\"',
                        {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissionsEgress': security_group['IpPermissionsEgress']})
            for ipPermissionEgress in security_group['IpPermissionsEgress']:
                if '0.0.0.0/0' in [ipRange['CidrIp'] for ipRange in ipPermissionEgress['IpRanges']] or \
                        '::/0' in [ipRange['CidrIpv6'] for ipRange in ipPermissionEgress['Ipv6Ranges']]:
                    append_summary(data, security_group['GroupId'] + ' 에 0.0.0.0/0 혹은 ::/0 에 액세스하는 것을 허용하는 아웃바운드 규칙이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '005', security_group['GroupId'], check, str(data)))
        print()

    def vpc_006(self):
        print('[VPC_006] 보안그룹에 RFC-1918에 지정된 사설 네트워크망 IP 주소 범위(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)에서 '
              '액세스하는 것을 허용하는 인바운드 규칙이 존재하는지 확인하시오.')
        for security_group in low_data.security_groups:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-security-groups --filter Name=group-id,Values=' + security_group['GroupId'] + ' --query \"SecurityGroups[*].{GroupId:GroupId, GroupName:GroupName, IpPermissions:IpPermissions}\"',
                        {'GroupId': security_group['GroupId'], 'GroupName': security_group['GroupName'], 'IpPermissions': security_group['IpPermissions']})
            for ipPermission in security_group['IpPermissions']:
                ipRanges = [ipRange['CidrIp'] for ipRange in ipPermission['IpRanges']]
                if [ipRange for ipRange in ipRanges if ipRange in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]:
                    append_summary(data, security_group['GroupId'] + ' 에 RFC-1918에 지정된 사설 네트워크망 IP 주소 범위(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)에서 액세스하는 것을 허용하는 아웃바운드 규칙이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '006', security_group['GroupId'], check, str(data)))
        print()

    def vpc_007(self):
        print('[VPC_007] 기본 Network ACL에 트래픽을 허용하는 규칙이 존재하는지 확인하시오.')
        for network_acl in low_data.network_acls:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            if network_acl['IsDefault']:
                append_data(data, 'aws ec2 describe-network-acls --filter Name=network-acl-id,Values=' + network_acl['NetworkAclId'] + ' --query \"NetworkAcls[*].{IsDefault:IsDefault, Entries:Entries}\"',
                            {'IsDefault': network_acl['IsDefault'], 'Entries': network_acl['Entries']})
                if len([entry for entry in network_acl['Entries'] if not entry['Egress'] and entry['RuleAction'] == 'allow']) > 0:
                    append_summary(data, '기본 Network ACL에 ' + network_acl['NetworkAclId'] + ' 에 인바운드 트래픽을 허용하는 규칙이 존재합니다.')
                if len([entry for entry in network_acl['Entries'] if entry['Egress'] and entry['RuleAction'] == 'allow']) > 0:
                    append_summary(data, '기본 Network ACL에 ' + network_acl['NetworkAclId'] + ' 에 아웃바운드 트래픽을 허용하는 규칙이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '007', network_acl['NetworkAclId'], check, str(data)))
        print()

    def vpc_008(self):
        print('[VPC_008] 모든 포트에 대한 트래픽을 허용하는 인바운드 혹은 아웃바운드 규칙을 포함하는 Network ACL이 존재하는지 확인하시오.')
        for network_acl in low_data.network_acls:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-network-acls --filter Name=network-acl-id,Values=' + network_acl['NetworkAclId'] + ' --query \"NetworkAcls[*].{IsDefault:IsDefault, Entries:Entries}\"',
                        {'IsDefault': network_acl['IsDefault'], 'Entries': network_acl['Entries']})
            for entry in [entry for entry in network_acl['Entries'] if not entry['Egress'] and entry['RuleAction'] == 'allow']:
                if entry['Protocol'] == -1:
                    append_summary(data, network_acl['NetworkAclId'] + ' 에 모든 트래픽을 허용하는 인바운드 규칙(규칙번호:' + str(entry['RuleNumber']) + ')이 존재합니다.')
                elif entry['Protocol'] in [6, 17]:
                    if entry['PortRange']['From'] == 0 and entry['PortRange']['To'] == 65535:
                        append_summary(data, network_acl['NetworkAclId'] + ' 에 모든 포트에 대한 트래픽을 허용하는 인바운드 규칙(규칙번호:' + str(entry['RuleNumber']) + ')이 존재합니다.')
            for entry in [entry for entry in network_acl['Entries'] if entry['Egress'] and entry['RuleAction'] == 'allow']:
                if entry['Protocol'] == -1:
                    append_summary(data, network_acl['NetworkAclId'] + ' 에 모든 트래픽을 허용하는 아웃바운드 규칙(규칙번호:' + str(entry['RuleNumber']) + ')이 존재합니다.')
                elif entry['Protocol'] in [6, 17]:
                    if entry['PortRange']['From'] == 0 and entry['PortRange']['To'] == 65535:
                        append_summary(data, network_acl['NetworkAclId'] + ' 에 모든 포트에 대한 트래픽을 허용하는 아웃바운드 규칙(규칙번호:' + str(entry['RuleNumber']) + ')이 존재합니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '008', network_acl['NetworkAclId'], check, str(data)))
        print()

    def vpc_009(self):
        print('[VPC_009] VPC 엔드포인트가 외부에 노출되어있는지 확인하시오.')
        for vpc_endpoint in low_data.vpc_endpoints:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-vpc-endpoints --filter Name=vpc-endpoint-id,Values=' + vpc_endpoint['VpcEndpointId'] + ' --query \"VpcEndpoints[*].{VpcEndpointId:VpcEndpointId, PolicyDocument:PolicyDocument}\"',
                        {'VpcEndpointId': vpc_endpoint['VpcEndpointId'], 'PolicyDocument': vpc_endpoint['PolicyDocument']})

            policy_document = json.loads(vpc_endpoint['PolicyDocument'])  # 이 부분 JSON으로 넘겨서 정책처리
            policy_effect_principals = [(statement['Effect'], statement['Principal']) for statement in policy_document['Statement']]
            for policy_effect_principal in policy_effect_principals:
                if policy_effect_principal == ('Allow', '*'):
                    append_summary(data, vpc_endpoint['VpcEndpointId'] + '가 외부에 노출되어 있습니다.')
                    break
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '009', vpc_endpoint['VpcEndpointId'], check, str(data)))
        print()

    def vpc_010(self):
        print('[VPC_010] AWS Organization 구성원 이외의 계정과 연결된 VPC 피어링 연결이 존재하는지 확인하시오.')

        try:
            list_accounts = organizations_client.get_paginator('list_accounts').paginate()
            accounts = [account['Id'] for accounts in list_accounts for account in accounts['Accounts']]
        except ClientError as e:  # 여기오면 N/A 처리로
            return

        if not accounts:
            accounts.append(AWS_CURRENT_ID['Account'])

        for vpc_peering_connection in low_data.vpc_peering_connections:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-vpc-peering-connections --filter Name=vpc-peering-connection-id,Values=' + vpc_peering_connection['VpcPeeringConnectionId'] +
                        ' --query \"VpcPeeringConnections[*].{VpcPeeringConnectionId:VpcPeeringConnectionId, AccepterVpcInfo:AccepterVpcInfo, RequesterVpcInfo:RequesterVpcInfo}\"',
                        {'VpcPeeringConnectionId': vpc_peering_connection['VpcPeeringConnectionId'], 'AccepterVpcInfo': vpc_peering_connection['AccepterVpcInfo'], 'RequesterVpcInfo': vpc_peering_connection['RequesterVpcInfo']})
            if (vpc_peering_connection['AccepterVpcInfo']['OwnerId'] not in accounts) or (vpc_peering_connection['RequesterVpcInfo']['OwnerId'] not in accounts):
                append_summary(data, 'AWS Organization 구성원 이외의 계정과 연결된 VPC 피어링 연결 ' + vpc_peering_connection['VpcPeeringConnectionId'] + ' 가 존재합니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '010', vpc_peering_connection['VpcPeeringConnectionId'], check, str(data)))
        print()

    def vpc_011(self):
        print('[VPC_011] 기본 VPC가 사용되고 있는지 확인하시오.')
        for vpc in low_data.vpcs:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-vpcs --filter Name=vpc-id,Values=' + vpc['VpcId'] + ' Name=is-default,Values=true --query \"Vpcs[*].{VpcId:VpcId, IsDefault:IsDefault}\"',
                        {'VpcId': vpc['VpcId'], 'IsDefault': vpc['IsDefault']})
            if vpc['IsDefault']:
                append_summary(data, '기본 VPC ' + vpc['VpcId'] + ' 가 존재합니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '011', vpc['VpcId'], check, str(data)))
        print()

    def vpc_012(self):
        print('[VPC_012] AWS VPN에 두 터널이 활성화되어 있는지 확인하시오.')
        for vpn_connection in low_data.vpn_connections:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-vpn-connections --filter Name=vpn-connection-id,Values=' + vpn_connection['VpnConnectionId'] + ' --query \"VpnConnections[*].{VpnConnectionId:VpnConnectionId, VgwTelemetry:VgwTelemetry}\"',
                        {'VpnConnectionId': vpn_connection['VpnConnectionId'], 'VgwTelemetry': vpn_connection['VgwTelemetry']})

            tunnel_count = 0
            for vgw_telemetry in vpn_connection['VgwTelemetry']:
                if vgw_telemetry['Status'] == 'UP':
                    tunnel_count += 1
            if tunnel_count < 2:
                append_summary(data, vpn_connection['VpnConnectionId'] + ' 에 활성화되어 있는 터널이 2개 미만입니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '012', vpn_connection['VpnConnectionId'], check, str(data)))
        print()

    def vpc_013(self):
        print('[VPC_013] NAT Gateway가 2개 이상의 가용영역(AZ)에서 구현되어 있는지 확인하시오.')
        for vpc in low_data.vpcs:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=' + vpc['VpcId'] + ' --query \"{NatGateways: NatGateways[*].{NatGatewayId:NatGatewayId, State:State, VpcId:VpcId}}\"',
                        {'NatGateways': [{'NatGatewayId': nat_gateway['NatGatewayId'], 'State': nat_gateway['State'], 'VpcId': nat_gateway['VpcId']} for nat_gateway in low_data.nat_gateways]})

            nat_gateway_subnets = [nat_gateway['SubnetId'] for nat_gateway in low_data.nat_gateways if nat_gateway['VpcId'] == vpc['VpcId']]
            if len(nat_gateway_subnets) == 1:
                append_summary(data, vpc['VpcId'] + ' 의 NAT Gateway가 2개 이상 구현되어있지 않습니다.')
            else:
                subnets = []
                for subnet in low_data.subnets:
                    if subnet['SubnetId'] in nat_gateway_subnets:
                        if subnet['AvailabilityZone'] not in [subnet['AvailabilityZone'] for subnet in subnets]:
                            subnets.append(subnet)

                append_data(data, 'aws ec2 describe-subnets --filter Name=subnet-id,Values=' + str([subnet['SubnetId'] for subnet in subnets]) + ' --query \"{Subnets:Subnets[*].{AvailabilityZone:AvailabilityZone, AvailabilityZoneId:AvailabilityZoneId, SubnetId:SubnetId, VpcId:VpcId}}\"',
                            {'Subnets': [{'AvailabilityZone': subnet['AvailabilityZone'], 'AvailabilityZoneId': subnet['AvailabilityZoneId'], 'SubnetId': subnet['SubnetId'], 'VpcId': subnet['VpcId']} for subnet in subnets]})
                if len(subnets) < 2:
                    append_summary(data, vpc['VpcId'] + ' 의 NAT Gateway가 2개 이상의 가용영역(AZ)에서 구현되어있지 않습니다.')
            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '013', vpc['VpcId'], check, str(data)))
        print()

    def vpc_014(self):
        print('[VPC_014] 각 Tier를 위한 서브넷을 2개 이상의 가용영역(AZ)에 생성했는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, '각 Tier를 위한 서브넷을 2개 이상의 가용영역(AZ)에 생성했는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '014', 'VPC', check, str(data)))
        print()

    def vpc_015(self):
        print('[VPC_015] Public 서브넷(Web-tier ELB)에 연결된 라우팅 테이블에 0.0.0.0/0에서 Internet Gateway로 라우팅하는 규칙이 존재하는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'Public 서브넷(Web-tier ELB)에 연결된 라우팅 테이블에 0.0.0.0/0에서 Internet Gateway로 라우팅하는 규칙이 존재하는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '015', 'VPC', check, str(data)))
        print()

    def vpc_016(self):
        print('[VPC_016] Private 서브넷(Web-tier, App-tier, Data-tier)에 연결된 라우팅 테이블에 0.0.0.0/0 NAT Gateway로 라우팅하는 규칙이 존재하는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'Private 서브넷(Web-tier, App-tier, Data-tier)에 연결된 라우팅 테이블에 0.0.0.0/0 NAT Gateway로 라우팅하는 규칙이 존재하는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '016', 'VPC', check, str(data)))
        print()

    def vpc_017(self):
        print('[VPC_017] Web-tier ELB에 연결된 보안그룹이 80(HTTP)/443(HTTPS)포트의 인바운드 트래픽만을 허용하도록 구성되어 있는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'Web-tier ELB에 연결된 보안그룹이 80(HTTP)/443(HTTPS)포트의 인바운드 트래픽만을 허용하도록 구성되어 있는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '017', 'VPC', check, str(data)))
        print()

    def vpc_018(self):
        print('[VPC_018] Web-tier에 연결된 보안그룹이 Web-tier ELB에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'Web-tier에 연결된 보안그룹이 Web-tier ELB에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '018', 'VPC', check, str(data)))
        print()

    def vpc_019(self):
        print('[VPC_019] App-tier ELB에 연결된 보안그룹이 Web-tier에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'App-tier ELB에 연결된 보안그룹이 Web-tier에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '019', 'VPC', check, str(data)))
        print()

    def vpc_020(self):
        print('[VPC_020] App-tier에 연결된 보안그룹이 App-tier ELB에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'App-tier에 연결된 보안그룹이 App-tier ELB에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '020', 'VPC', check, str(data)))
        print()

    def vpc_021(self):
        print('[VPC_021] Data-tier에 연결된 보안그룹이 App-tier에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 확인하시오.')
        check = '?'
        data = {'cli': [], 'raw_data': [], 'summary': []}
        append_summary(data, 'Data-tier에 연결된 보안그룹이 App-tier에 연결된 보안그룹으로부터의 인바운드 트래픽만을 허용하도록 구성되어 있는지 AWS Management Console을 통해 확인하시오.')
        execute_insert_sql((low_data.diagnosis_id, 'VPC', '021', 'VPC', check, str(data)))
        print()

    def vpc_022(self):
        print('[VPC_022] 각 VPC의 네트워크 인터페이스를 오가는 트래픽을 CloudWatch Logs/Amazon S3에 캡처해 관리하는 흐름로그가 존재하는지 확인하시오.')
        for vpc in low_data.vpcs:
            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}

            flow_logs = [flow_log for flow_log in low_data.flow_logs if flow_log['ResourceId'] == vpc['VpcId']]
            append_data(data, 'aws ec2 describe-flow-logs --filter Name=resource-id,Values=' + vpc['VpcId'] + ' --query \"{FlowLogs:FlowLogs[*].{FlowLogId:FlowLogId, FlowLogStatus:FlowLogStatus, VpcId:ResourceId}}\"',
                        {'FlowLogs': [{'FlowLogId': flow_log['FlowLogId'], 'FlowLogStatus': flow_log['FlowLogStatus'], 'VpcId': flow_log['ResourceId']} for flow_log in flow_logs]})
            if not flow_logs:
                append_summary(data, vpc['VpcId'] + ' 에 연결된 흐름로그가 존재하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '022', vpc['VpcId'], check, str(data)))
        print()

    def vpc_023(self):
        print('[VPC_023] 각 Subnet의 네트워크 인터페이스를 오가는 트래픽을 CloudWatch Logs/Amazon S3에 캡처해 관리하는 흐름로그가 존재하는지 확인하시오.')
        for subnet in low_data.subnets:
            flow_logs = [flow_log for flow_log in low_data.flow_logs if flow_log['ResourceId'] == subnet['SubnetId']]

            check = 'Y'
            data = {'cli': [], 'raw_data': [], 'summary': []}
            append_data(data, 'aws ec2 describe-flow-logs --filter Name=resource-id,Values=' + subnet['SubnetId'] + ' --query \"{FlowLogs:FlowLogs[*].{FlowLogId:FlowLogId, FlowLogStatus:FlowLogStatus, SubnetId:ResourceId}}\"',
                        {'FlowLogs': [{'FlowLogId': flow_log['FlowLogId'], 'FlowLogStatus': flow_log['FlowLogStatus'], 'SubnetId': flow_log['ResourceId']} for flow_log in flow_logs]})
            if not flow_logs:
                append_summary(data, subnet['SubnetId'] + ' 에 연결된 흐름로그가 존재하지 않습니다.')

            if len(data['summary']) > 0:
                check = 'N'
            execute_insert_sql((low_data.diagnosis_id, 'VPC', '023', subnet['SubnetId'], check, str(data)))
        print()

