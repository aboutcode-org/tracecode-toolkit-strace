#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/tracecode-build/
# The TraceCode software is licensed under the Apache License version 2.0.
# Data generated with TraceCode require an acknowledgment.
# TraceCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with TraceCode or any TraceCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with TraceCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  TraceCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  TraceCode is a free software build tracing tool from nexB Inc. and others.
#  Visit https://github.com/nexB/tracecode-build/ for support and download.

import genericpath


"""
Common prefix and suffix functions.
"""


def common_prefix(s1, s2):
    """
    Return the common leading subsequence of two sequences.
    """
    if not s1 or not s2:
        return None
    common = genericpath.commonprefix((s1, s2,))
    if common:
        return common
    else:
        return None


def common_suffix(s1, s2):
    """
    Return the common trailing subsequence between two sequences.
    """
    if not s1 or not s2:
        return None
    # revert the seqs and get a common prefix
    common = common_prefix(s1[::-1], s2[::-1])
    # revert back
    if common:
        return common[::-1]
    else:
        return common


def common_path_prefix(p1, p2):
    """
    Return the common leading path between two posix paths and the number of
    common path segments.
    """
    return common_segments(p1, p2, common_func=common_prefix)


def common_path_suffix(p1, p2):
    """
    Return the common trailing path between two posix paths and the number of
    common path segments.
    """
    return common_segments(p1, p2, common_func=common_suffix)


def split(p):
    """
    Split a posix path in a sequence of segments, ignoring leading and
    trailing slash. Return an empty sequence for an empty path and the root /.
    """
    if not p:
        return []
    p = p.strip('/').split('/')
    return [] if p == [''] else p


def common_segments(p1, p2, common_func):
    """
    Common function to compute common leading or trailing paths segments.
    """
    common = common_func(split(p1), split(p2))
    lgth = len(common) if common else 0
    common = '/'.join(common) if common else None
    return common, lgth
