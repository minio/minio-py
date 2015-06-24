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

    public_read = False
    public_write = False

    for acls in root:
        print '|', acls
        if acls.tag == '{http://s3.amazonaws.com/doc/2006-03-01}AccessControlList':
            for grant in acls:
                print '|-- Grant'
                user_uri = None
                permission = None
                for grant_property in grant:
                    print '  |--', grant_property
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01}Grantee':
                        for grantee in grant_property:
                            print '    |--', grantee.tag, grantee.text
                            if grantee.tag == '{http://s3.amazonaws.com/doc/2006-03-01}URI':
                                user_uri = grantee.text
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01}Permission':
                        print '    |--', grant_property.tag, grant_property.text
                        permission = grant_property.text
                print user_uri, permission
                if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'WRITE':
                    public_write = True
                if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'READ':
                    public_read = True
    print 'public read', public_read
    print 'public write', public_write

    if public_read is True and public_write is True:
        return Acl.public_read_write()
    if public_read is True and public_write is False:
        return Acl.public_read()
    return Acl.custom()


class Bucket(object):
    def __init__(self, name, created):
        self.name = name
        self.creation_date = created
