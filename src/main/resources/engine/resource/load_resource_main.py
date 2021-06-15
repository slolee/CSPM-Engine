import sys, os
if sys.platform.startswith('win'):
    sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
elif sys.platform.startswith('linux'):
    sys.path.append(sys.path[1] + '/src/main/resources/engine')

from common.client import client
from resource.load_resource import load_resource
from common.db import commit

if __name__ == '__main__':
    arguments = sys.argv

    client.init_client(arguments[1], arguments[2], arguments[3])
    load_resource.set_access_key(arguments[1])

    print('[*] Resource Load Start')

    load_resource.load_iam_resource()
    load_resource.load_vpc_resource()
    load_resource.load_ec2_resource()
    load_resource.load_rds_resource()
    load_resource.load_ebs_resource()
    load_resource.load_s3_resource()
    load_resource.load_cloudtrail_resource()
    load_resource.load_cloudwtach_resource()
    load_resource.load_cloudfront_resource()
    load_resource.load_kms_resource()
    load_resource.load_lambda_resource()

    commit()
    print('[*] Resource Load Complete')

