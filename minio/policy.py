# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016 Minio, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
minio.policy

This module implements policy management.

:copyright: (c) 2016 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import collections
import fnmatch
import itertools

from .compat import basestring

_AWS_RESOURCE_PREFIX = "arn:aws:s3:::"

_COMMON_BUCKET_ACTIONS = set(['s3:GetBucketLocation'])
_READ_ONLY_BUCKET_ACTIONS = set(['s3:ListBucket'])
_WRITE_ONLY_BUCKET_ACTIONS = set(['s3:ListBucketMultipartUploads'])

_READ_ONLY_OBJECT_ACTIONS = set(['s3:GetObject'])
_WRITE_ONLY_OBJECT_ACTIONS = set(['s3:AbortMultipartUpload',
                                  's3:DeleteObject',
                                  's3:ListMultipartUploadParts',
                                  's3:PutObject'])
_READ_WRITE_OBJECT_ACTIONS = (_READ_ONLY_OBJECT_ACTIONS |
                              _WRITE_ONLY_OBJECT_ACTIONS)


# Policy Enums.
class Policy(object):
    NONE = "none"
    READ_ONLY = "readonly"
    READ_WRITE = "readwrite"
    WRITE_ONLY = "writeonly"


def _get_resource(statement):
    """
    Always return resource as a list
    """
    resource = statement.get('Resource')
    if isinstance(resource, basestring):
        resource = [resource]
    return resource


def _get_action(statement):
    """
    Always return action as a list
    """
    action = statement.get('Action', [])
    if isinstance(action, basestring):
        action = [action]
    return action


def _get_bucket_resource(bucket_name):
    """
    :param bucket_name: Name of the bucket
    :type bucket_name: str

    :return: Representation of the bucket with the resource prefix
    :rtype: str
    """
    return [_AWS_RESOURCE_PREFIX + bucket_name]


def _get_resource_prefix(bucket_name):
    """
    :param bucket_name: Name of the bucket
    :type bucket_name: str

    :return: Representation of the bucket with the resource prefix,
             but with a trailing slash.
    :rtype: str
    """
    return _get_bucket_resource(bucket_name)[0] + '/'


def _get_object_resource(bucket_name, prefix):
    """
    :param bucket_name: Name of the bucket
    :type bucket_name: str
    :param prefix: Name of the prefix
    :type prefix: str

    :return: Representation of an object in a bucket with the resource prefix.
    :rtype: str
    """
    return [_get_resource_prefix(bucket_name) + prefix + '*']


# Returns new statements with bucket actions.
def _new_bucket_statement(policy, bucket_name, prefix=''):
    if policy == Policy.NONE:
        return []

    bucket_resource = _get_bucket_resource(bucket_name)

    rv = [{'Action': list(_COMMON_BUCKET_ACTIONS),
           'Effect': 'Allow',
           'Principal': {'AWS': '*'},
           'Resource': bucket_resource,
           'Sid': ''}]

    if policy == Policy.READ_ONLY or policy == Policy.READ_WRITE:
        s = {'Action': list(_READ_ONLY_BUCKET_ACTIONS),
             'Effect': 'Allow',
             'Principal': {'AWS': '*'},
             'Resource': bucket_resource,
             'Sid': ''}
        if prefix:
            s.update({'Condition': {'StringEquals': {
                's3:prefix': prefix}}})
        rv.append(s)

    if policy == Policy.WRITE_ONLY or policy == Policy.READ_WRITE:
        rv.append({'Action': list(_WRITE_ONLY_BUCKET_ACTIONS),
                   'Effect': 'Allow',
                   'Principal': {'AWS': '*'},
                   'Resource': bucket_resource,
                   'Sid': ''})

    return rv


# Returns new statements contains object actions.
def _new_object_statement(policy, bucket_name, prefix=''):
    rv = [{'Action': [],
           'Effect': 'Allow',
           'Principal': {'AWS': '*'},
           'Resource': _get_object_resource(bucket_name, prefix),
           'Sid': ''}]
    if policy == Policy.READ_ONLY:
        rv[0]['Action'] = list(_READ_ONLY_OBJECT_ACTIONS)
    elif policy == Policy.WRITE_ONLY:
        rv[0]['Action'] = list(_WRITE_ONLY_OBJECT_ACTIONS)
    elif policy == Policy.READ_WRITE:
        rv[0]['Action'] = list(_READ_WRITE_OBJECT_ACTIONS)
    else:
        rv = []
    return rv


# Returns new statements for given bucket and prefix.
def _new_statements(policy, bucket_name, prefix=''):
    return (_new_bucket_statement(policy, bucket_name, prefix) +
            _new_object_statement(policy, bucket_name, prefix))


def _filter_resources(prefix, resources):
    """
    Returns a list of resources, which starts with given prefix
    """
    return list(filter(lambda r: r.startswith(prefix), resources))


# Returns whether given bucket statements are used by other than given
# prefix statements.
def _get_in_use_policy(statements, bucket_name, prefix=''):
    resource_prefix = _get_resource_prefix(bucket_name)
    object_resource = _get_object_resource(bucket_name, prefix)

    in_use = {Policy.READ_ONLY: False,
              Policy.WRITE_ONLY: False}

    for s in statements:
        resource = _get_resource(s)
        actions = set(_get_action(s))
        if (resource != object_resource and
                _filter_resources(resource_prefix, resource)):
            if (not in_use[Policy.READ_ONLY] and
                    actions & _READ_ONLY_OBJECT_ACTIONS):
                in_use[Policy.READ_ONLY] = True

            if (not in_use[Policy.WRITE_ONLY] and
                    actions & _WRITE_ONLY_OBJECT_ACTIONS):
                in_use[Policy.WRITE_ONLY] = True

    return in_use


# Removes bucket actions for given policy in given statement.
def _remove_bucket_actions(statement, policy, prefix=''):
    def _remove_read_only(s, actions, cond_value):
        if not (set(actions) & _READ_ONLY_BUCKET_ACTIONS ==
                _READ_ONLY_BUCKET_ACTIONS):
            return s, actions, cond_value

        if not prefix and not cond_value:
            actions = list(set(actions) - _READ_ONLY_BUCKET_ACTIONS)
            return s, actions, cond_value

        if prefix and cond_value:
            string_equals_value = cond_value.get('StringEquals', {})
            values = string_equals_value.get('s3:prefix', [])
            if isinstance(values, basestring):
                values = [values]

            if prefix in values:
                values.remove(prefix)

            if not values and 's3:prefix' in string_equals_value:
                del string_equals_value['s3:prefix']

            if (not string_equals_value and
                    'StringEquals' in cond_value):
                del cond_value['StringEquals']

            if not cond_value and 'Condition' in s:
                del s['Condition']

            if not cond_value:
                actions = list(set(actions) - _READ_ONLY_BUCKET_ACTIONS)
        return s, actions, cond_value

    def _remove_write_only(actions, cond_value):
        if not cond_value:
            actions = list(set(actions) - _WRITE_ONLY_BUCKET_ACTIONS)
        return actions

    actions = _get_action(statement)
    cond_value = statement.get('Condition', {})
    aws = statement.get('Principal', {}).get('AWS', [])
    if (statement.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) ):
        if policy == Policy.READ_ONLY:
            statement, actions, cond_value = _remove_read_only(statement,
                                                               actions,
                                                               cond_value)
        elif policy == Policy.WRITE_ONLY:
            actions = _remove_write_only(actions, cond_value)
        elif policy == Policy.READ_WRITE or policy == Policy.NONE:
            statement, actions, cond_value = _remove_read_only(statement,
                                                               actions,
                                                               cond_value)
            actions = _remove_write_only(actions, cond_value)

    if actions:
        statement['Action'] = actions
    else:
        statement = {}

    return statement


# Removes object actions in given statement for given policy.
def _remove_object_actions(statement, policy):
    actions = _get_action(statement)
    aws = statement.get('Principal', {}).get('AWS', [])
    if (statement.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) and
        not statement.get('Condition') ):
        if policy == Policy.READ_ONLY:
            actions = list(set(actions) - _READ_ONLY_OBJECT_ACTIONS)
        elif policy == Policy.WRITE_ONLY:
            actions = list(set(actions) - _WRITE_ONLY_OBJECT_ACTIONS)
        elif policy == Policy.READ_WRITE or policy == Policy.NONE:
            actions = list(set(actions) - _READ_WRITE_OBJECT_ACTIONS)

    if actions:
        statement['Action'] = actions
    else:
        statement = {}

    return statement


# Returns statements containing removed actions/statements for given
# policy, bucket name and prefix.
def _remove_statements(statements, policy, bucket_name, prefix=''):
    bucket_resource = _get_bucket_resource(bucket_name)
    object_resource = _get_object_resource(bucket_name, prefix)
    in_use = _get_in_use_policy(statements, bucket_name, prefix)
    out = []
    read_only_bucket_statements = []
    s3_prefix_value = []
    for s in statements:
        resource = _get_resource(s)
        if resource == bucket_resource:
            if s.get('Condition'):
                s = _remove_bucket_actions(s, policy, prefix)
            else:
                if (policy == Policy.READ_ONLY or
                        policy == Policy.READ_WRITE and
                        not in_use[Policy.READ_ONLY]):
                    s = _remove_bucket_actions(s, Policy.READ_ONLY, prefix)

                if (policy == Policy.WRITE_ONLY or
                        policy == Policy.READ_WRITE and
                        not in_use[Policy.WRITE_ONLY]):
                    s = _remove_bucket_actions(s, Policy.WRITE_ONLY, prefix)
        elif resource == object_resource:
            s = _remove_object_actions(s, policy)

        if s:
            aws = s.get('Principal', {}).get('AWS', [])
            if (resource == bucket_resource and set(_get_action(s)) & _READ_ONLY_BUCKET_ACTIONS and
                s.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) ):
                cond_value = s.get('Condition', {})
                string_equals_value = cond_value.get('StringEquals', {})
                values = string_equals_value.get('s3:prefix', [])
                if isinstance(values, basestring):
                    values = [values]

                s3_prefix_value += [(bucket_resource[0] + '/' + v + '*')
                                    for v in values]

                if s3_prefix_value or not cond_value:
                    read_only_bucket_statements.append(s)
                    continue

            out.append(s)

    skip_bucket_statement = True
    resource_prefix = _get_resource_prefix(bucket_name)
    for s in out:
        resource = _get_resource(s)
        if (_filter_resources(resource_prefix, resource) and
                resource not in s3_prefix_value):
            skip_bucket_statement = False
            break

    for s in read_only_bucket_statements:
        aws = s.get('Principal', {}).get('AWS', [])
        if (skip_bucket_statement and s['Resource'] == bucket_resource and
            s.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) and not s.get('Condition')):
            continue

        _append_statement(out, s)

    if len(out) == 1:
        s = out[0]
        aws = s.get('Principal', {}).get('AWS', [])
        if (s['Resource'] == bucket_resource and s.get('Action') == list(_COMMON_BUCKET_ACTIONS) and
            s.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) and not s.get('Condition') ):
            out = []

    return out


# Returns a dictionary containing values as list for same keys in
# given two dictionaries.
#
# Example:
# d1 = {'s3:prefix': 'hello',
#       's3:x-amz-acl': 'public-read',
#       'aws:SourceIp': '192.168.143.0/24'}
#
# d2 = {'s3:prefix': 'world',
#       's3:x-amz-acl': 'public-read'}
#
# _merge_dict(d1, d2) == {'s3:prefix': ['hello', 'world'],
#                         's3:x-amz-acl': ['public-read'],
#                         'aws:SourceIp': ['192.168.143.0/24']}
#
def _merge_dict(d1, d2):
    out = collections.defaultdict(list)
    for k, v in itertools.chain(d1.items(), d2.items()):
        out[k] = list(set(out[k] + [v] if isinstance(v, basestring) else v))
    return dict(out)


# Returns a dictionary containing merged conditions for given two dictionaries.
#
# Example:
# c1 = {'Condition': {'StringEquals': {'s3:prefix': 'hello'}}}
#
# c2 = {'Condition': {'StringEquals': {'s3:prefix': 'world'},
#                     'StringNotEquals': {'s3:prefix': 'foo'}}}
#
# _merge_condition(c1, c2) == {'Condition': {
#                                 'StringEquals': {
#                                     's3:prefix': ['hello', 'world']},
#                                   {'StringNotEquals': {
#                                      's3:prefix': ['foo']}}}
#
def _merge_condition(c1, c2):
    out = collections.defaultdict(dict)
    for k, v in itertools.chain(c1.items(), c2.items()):
        out.update({k:  _merge_dict(out[k], v)})
    return dict(out)


# Appends given statement into statement list to have unique statements.
# - If statement already exists in statement list, it ignores.
# - If statement exists with different conditions, they are merged.
# - Else the statement is appended to statement list.
def _append_statement(statements, statement):
    for s in statements:
        if (s.get('Resource') == statement.get('Resource') and
                _get_action(s) == _get_action(statement) and
                s.get('Effect') == statement.get('Effect') and
                s.get('Principal') == statement.get('Principal')):
            if s.get('Condition') == statement.get('Condition'):
                return
            if s.get('Condition') and statement.get('Condition'):
                s['Condition'] = _merge_condition(s['Condition'],
                                                  statement['Condition'])
                return

    statements.append(statement)


# Appends two statement lists.
def _append_statements(statements, append_statements):
    for s in append_statements:
        _append_statement(statements, s)


# Checks whether given prefix starts with given s3 prefix list.
def _match_prefix(prefix, s3_prefix):
    if isinstance(s3_prefix, basestring):
        return prefix.startswith(s3_prefix)

    matched = False
    for p in s3_prefix:
        matched = prefix.startswith(p)
        if matched:
            break

    return matched


# Returns policy of given bucket statement.
def _get_bucket_policy(statement, prefix=''):
    common_found = False
    read_only = False
    write_only = False

    actions = set(_get_action(statement))
    cond_value = statement.get('Condition', {})
    aws = statement.get('Principal', {}).get('AWS', [])
    if (statement.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) ):
        if actions & _COMMON_BUCKET_ACTIONS and not cond_value:
            common_found = True

        if actions & _WRITE_ONLY_BUCKET_ACTIONS and not cond_value:
            write_only = True

        if actions & _READ_ONLY_BUCKET_ACTIONS:
            if prefix and cond_value:
                string_equals_value = cond_value.get('StringEquals', {})
                if string_equals_value:
                    s3_prefix_value = string_equals_value.get('s3:prefix', [])
                    if isinstance(s3_prefix_value, basestring):
                        s3_prefix_value = [s3_prefix_value]
                    if _match_prefix(prefix, s3_prefix_value):
                        read_only = True
                else:
                    string_not_equals_value = cond_value.get('StringNotEquals',
                                                             {})
                    if string_not_equals_value:
                        s3_prefix_value = string_not_equals_value.get(
                            's3:prefix', [])
                        if not _match_prefix(prefix, s3_prefix_value):
                            read_only = True
            elif not prefix and not cond_value:
                read_only = True
            elif prefix and not cond_value:
                read_only = True

    return common_found, read_only, write_only


# Returns policy of given object statement.
def _get_object_policy(statement):
    read_only = False
    write_only = False
    aws = statement.get('Principal', {}).get('AWS', [])
    actions = set(_get_action(statement))
    if (statement.get('Effect') == 'Allow' and (aws == '*' or '*' in aws) and
        not statement.get('Condition') ):
        if actions & _READ_ONLY_OBJECT_ACTIONS:
            read_only = True
        if actions & _WRITE_ONLY_OBJECT_ACTIONS:
            write_only = True

    return read_only, write_only


def _get_permissions(s, resource, object_resource, matched_resource,
                     bucket_resource, prefix, bucket_common_found,
                     bucket_read_only, bucket_write_only):

    obj_read_only, obj_write_only = False, False
    if (resource == object_resource or
            fnmatch.fnmatch(object_resource, resource)):
        read_only, write_only = _get_object_policy(s)
        if len(matched_resource) < len(resource):
            obj_read_only = read_only
            obj_write_only = write_only
            matched_resource = resource
        elif len(matched_resource) == len(resource):
            obj_read_only = obj_read_only or read_only
            obj_write_only = obj_write_only or write_only
            matched_resource = resource
    elif resource == bucket_resource:
        common_found, read_only, write_only = _get_bucket_policy(s, prefix)
        bucket_common_found = bucket_common_found or common_found
        bucket_read_only = bucket_read_only or read_only
        bucket_write_only = bucket_write_only or write_only
    return bucket_common_found, bucket_read_only, bucket_write_only, \
        obj_read_only, obj_write_only


# Returns policy of given bucket name, prefix in given statements.
def get_policy(statements, bucket_name, prefix=''):
    bucket_resource = _get_bucket_resource(bucket_name)[0]
    object_resource = _get_object_resource(bucket_name, prefix)[0]

    bucket_common_found = False
    bucket_read_only = False
    bucket_write_only = False
    matched_resource = ''
    obj_read_only = False
    obj_write_only = False
    for s in statements:
        resources = _get_resource(s)
        for resource in resources:
            bucket_common_found, bucket_read_only, bucket_write_only, \
                obj_read_only, obj_write_only = _get_permissions(
                    s, resource, object_resource, matched_resource,
                    bucket_resource, prefix, bucket_common_found,
                    bucket_read_only, bucket_write_only)

    policy = Policy.NONE
    if bucket_common_found:
        if (bucket_read_only and bucket_write_only and
                obj_read_only and obj_write_only):
            policy = Policy.READ_WRITE
        elif bucket_read_only and obj_read_only:
            policy = Policy.READ_ONLY
        elif bucket_write_only and obj_write_only:
            policy = Policy.WRITE_ONLY

    return policy


# Returns new statements containing policy of given bucket name and
# prefix are appended.
def set_policy(statements, policy, bucket_name, prefix=''):
    out = _remove_statements(statements, Policy.READ_WRITE,
                             bucket_name, prefix)
    ns = _new_statements(policy, bucket_name, prefix)
    _append_statements(out, ns)

    return out
