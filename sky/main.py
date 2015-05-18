#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""main.py: Provision AWS environments quickly."""

import os
import sys
import types
import logging
import importlib
from copy import deepcopy
from .utils import parse_arguments
from .infrastructure import Infrastructure
from .state import ready, config

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC. All rights reserved.'
__license__ = 'GPLv3'

logger = logging.getLogger(__name__)

def load_skyfile(path='./skyfile.py', module_name='skyfile'):
    # Import Skyfile (Only works in Python 3.3+).
    loader = importlib.machinery.SourceFileLoader(module_name, path)
    module = loader.load_module()
    logger.info('Loaded (%s) module from (%s).' % (module_name, path))

    return module

def load_infrastructure(module):

    infrastructure_objects = []

    imported_symbols = vars(module)

    if '__all__' in imported_symbols:
        # Obey the use of <module>.__all__, if it is present.
        imported_symbols = [(name, imported_symbols[name]) for name in \
                            imported_symbols if name in imported_symbols['__all__']]
    else:
        imported_symbols = imported_symbols.items()

    for symbol in imported_symbols:
        name, obj = symbol
        if isinstance(obj, Infrastructure):
            logger.debug('(%s) is a %s object imported from the (%s) module.' % (name, type(obj), module.__name__))
            infrastructure_objects.append(obj)
        elif isinstance(obj, types.ModuleType):
            logger.debug('(%s) module imported from the (%s) module.' % (name, module.__name__))
            infrastructure_objects += load_infrastructure(obj)

    return infrastructure_objects

def build_dependency_graph(nodes, level=1):
    # Create an empty graph.
    graph = []

    # Create a copy of the nodes list to work with.
    _nodes = deepcopy(nodes)

    # Store the length of the nodes list, so that circular dependencies can be detected.
    original_count = len(_nodes)

    # Determine independent nodes.
    independent_nodes = [node for node in _nodes if not node.dependencies]

    if independent_nodes:
        # Remove independent nodes from the search space.
        for independent_node in independent_nodes:
            _nodes.remove(independent_node)
            logger.debug('(%s) is ready.' % independent_node.__name__)

        # Prune independent node from all node dependencies.
        for name, dependencies in [(node.__name__, node.dependencies) for node in _nodes if node.dependencies]:
            logger.debug('(%s) required: (%s).' % (name, ', '.join(list(dependencies))))
            resolved_dependencies = {independent_node.__name__ for independent_node in independent_nodes}
            dependencies.difference_update(resolved_dependencies)
            logger.debug('(%s) now requires: (%s).' % (name, ', '.join(list(dependencies))))

        # Repeat search for newly-independent nodes, if any are left.
        if _nodes:
            graph = build_dependency_graph(_nodes, level=level+1)

        # Build graph from the independent nodes to the most-dependent nodes.
        graph.insert(0, independent_nodes)

    # Check for circular dependencies.
    count = 0
    for depth in graph:
        for breadth in depth:
            count += 1
    if original_count != count:
        raise RuntimeError('Circular dependencies detected.')

    # Restore node dependencies following graph creation, since the recursive algorithm is destructive.
    if _nodes and level == 1:
        for dependencies in graph:
            for dependency in dependencies:
                dependency.dependencies = next(node.dependencies for node in nodes if node.__name__ == dependency.__name__)

    return graph

def build_target(dependency_graph, target='all'):

    # Rebuild the dependency graph, if a specific target was specified.
    if target != 'all':
        target_found = False
        target_dependencies = set()
        temporary_graph = []

        # Search the complete dependency graph for the target node.
        for dependencies in dependency_graph:
            # Add the current dependency group to the temporary graph.
            temporary_graph.append(dependencies)

            # Search each dependency in the dependency group.
            for dependency in dependencies:
                # Locate the target node.
                if dependency.__name__ == target:
                    # Truncate the most-recently added dependency group to the target node.
                    temporary_graph[-1] = [dependency]

                    # Store the target's dependencies so that they are not pruned.
                    target_dependencies = dependency.dependencies

                    # Stop traversing the dependency graph (inner loop) when the target node has been located.
                    target_found = True
                    break

            # Stop traversing the dependency graph (outer loop) when the target node has been located.
            if target_found:
                # Traverse through the temporary graph backwards.
                for dependencies in reversed(temporary_graph):
                    for dependency in dependencies:

                        # Prune nodes that are not part of the target's dependency chain.
                        if dependency.__name__ not in target_dependencies and dependency.__name__ != target:
                            logger.debug('Pruning unneeded node (%s).' % dependency.__name__)
                            dependencies.remove(dependency)
                            logger.debug('Pruned unneeded node (%s).' % dependency.__name__)

                        # Add indirect dependencies to the target's dependency chain.
                        elif dependency.__name__ in target_dependencies and dependency.dependencies:
                            logger.debug('Unioning additional dependency/ies (%s).' % dependency.dependencies)
                            target_dependencies = target_dependencies | dependency.dependencies
                            logger.debug('Unioned additional dependency/ies (%s).' % dependency.dependencies)

                # Reset the dependency graph.
                dependency_graph = temporary_graph
                break

    # Build the target node.
    for dependencies in dependency_graph:
        for dependency in dependencies:
            dependency()
            ready[dependency.__name__] = dependency

def main():
    parse_arguments()
    module = load_skyfile()
    infrastructure = load_infrastructure(module)
    dependency_graph = build_dependency_graph(infrastructure)

    targets = config['TARGETS']

    for target in targets:
        build_target(dependency_graph, target=target)

    # archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    # logger.info('Creating deployment archive (%s).' % archive_name)
    # s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)
    # logger.info('Created deployment archive (%s).' % archive_name)

    # bootstrap_archive_name = '.'.join(['configure', s3.PROJECT_NAME, 'tar', 'gz'])
    # s3.make_tarfile(bootstrap_archive_name, 'deploy')

    # bucket = s3.create_bucket()
    # s3.add_object(bucket, archive_name)
    # s3.add_object(bucket, bootstrap_archive_name)
    # policy = s3.get_bucket_policy(bucket)

    # script = get_script('us-east-1', bucket.name, archive_name, bootstrap_archive_name)
    # script = ec2.install_package(script, 'python3-pip')
    # script = ec2.run(script, 'pip3 install virtualenv')
    # script = ec2.run(script, 'pip3 install virtualenvwrapper')

    # instance_profile_name = iam.create_role(policy)

if __name__ == '__main__':
    main()
