#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/tracecode-toolkit-strace for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

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
    common = genericpath.commonprefix(
        (
            s1,
            s2,
        )
    )
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
    p = p.strip("/").split("/")
    return [] if p == [""] else p


def common_segments(p1, p2, common_func):
    """
    Common function to compute common leading or trailing paths segments.
    """
    common = common_func(split(p1), split(p2))
    lgth = len(common) if common else 0
    common = "/".join(common) if common else None
    return common, lgth
