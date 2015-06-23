from xml.etree import ElementTree
from datetime import datetime

import pytz
from .acl import Acl

__author__ = 'minio'


def parse_list_buckets(data):
    root = ElementTree.fromstring(data)
    bucket_list = []
    for buckets in root.findall('{http://doc.s3.amazonaws.com/2006-03-01}Buckets'):
        for bucket in buckets:
            name = None
            creation_date = None
            for attribute in bucket:
                if attribute.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Name':
                    name = attribute.text
                if attribute.tag == '{http://doc.s3.amazonaws.com/2006-03-01}CreationDate':
                    creation_date = datetime.strptime(attribute.text, '%Y-%m-%dT%H:%M:%S.%fZ')
                    creation_date = pytz.utc.localize(creation_date)
            bucket_list.append(Bucket(name, creation_date))
    return bucket_list

def parse_acl(data):
    root = ElementTree.fromstring(data)

    for acl in root:
        print acl

    return Acl.public_read_write()

class Bucket(object):
    def __init__(self, name, created):
        self.name = name
        self.creation_date = created
