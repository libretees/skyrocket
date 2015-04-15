import os
import timeit
import logging
from boto import regioninfo
from .import_settings import import_settings
from .parse_arguments import parse_arguments

args = parse_arguments()
settings = import_settings(args)

PROJECT_NAME = os.path.abspath(os.path.expanduser(args.directory)).split(os.sep)[-1]
PROJECT_DIRECTORY = os.path.abspath(os.path.expanduser(args.directory))

MODE = None
EPHEMERAL = 'ephemeral'
PERMANENT = 'permanent'

logger = logging.getLogger(__name__)

def get_closest_region(service='ec2', repetitions=1):
    regions = [region.name for region in regioninfo.get_regions(service) if 'gov' not in region.name and 'cn' not in region.name]

    latency = {}
    for region in regions:
        connection = timeit.Timer("h.request('GET', '/')",
                                  "from http.client import HTTPSConnection; h=HTTPSConnection('ec2.%s.amazonaws.com')" % region)
        times = connection.repeat(repetitions, 1)
        avg_latency = sum(times)/float(len(times))
        latency[region] = avg_latency
        logger.info('Average latency to Amazon %s %s is %s' % (service.upper(), region, latency[region]))

    region = min(latency, key=latency.get)
    return region

__all__ = ['import_settings', 'parse_arguments']