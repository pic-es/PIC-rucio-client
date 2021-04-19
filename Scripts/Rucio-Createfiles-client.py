#!/usr/bin/env python
# coding: utf-8

# In[1]:


from __future__ import absolute_import, division, print_function

__author__ = "Agustin Bruzzese"
__copyright__ = "Copyright (C) 2020 Agustin Bruzzese"

__revision__ = "$Id$"
__version__ = "0.2"

import sys
sys.path.append("/usr/lib64/python3.6/site-packages/")

import numpy as np 
import gfal2,io,json,linecache,logging,os,os.path,random,re,time,uuid,zipfile,string,pathlib,time,pytz
from urllib.parse import urlunsplit
import graphyte, socket
from dateutil import parser
from datetime import (
    datetime,
    tzinfo,
    timedelta,
    timezone,
)

from gfal2 import (
    Gfal2Context,
    GError,
)
from io import StringIO

# Import Specific MAGIC and CTA parameters 
import lfn2pfn_MAGIC as magic
import lfn2pfn_CTA as cta

# Import parser 
import argparse


# In[2]:


# Set Rucio virtual environment configuration 
os.environ['RUCIO_HOME']=os.path.expanduser('~/rucio')
from rucio.rse import rsemanager as rsemgr
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
import rucio.rse.rsemanager as rsemgr
# from rucio.client import RuleClient
from rucio.client.ruleclient import RuleClient
from rucio.common.exception import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    AccessDenied, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)

from rucio.common.utils import adler32, detect_client_location, execute, generate_uuid, md5, send_trace, GLOBALLY_SUPPORTED_CHECKSUMS

# Gfal configuration
gfal2.set_verbose(gfal2.verbose_level.debug)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# In[4]:


# Set GFAL transfer parameters

def event_callback(event):
    #print event
    print("[%s] %s %s %s" % (event.timestamp, event.domain, event.stage, event.description))


def monitor_callback(src, dst, average, instant, transferred, elapsed):
    print("[%4d] %.2fMB (%.2fKB/s)\r" % (elapsed, transferred / 1048576, average / 1024)),
    sys.stdout.flush()

# General functions for the creation of files
def PrintException():
    import linecache
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))

# Get RSEs protocol
def get_rse_url(rse):
    """
    Return the base path of the rucio url
    """
    rse_settings = rsemgr.get_rse_info(rse)
    protocol = rse_settings['protocols'][0]

    schema = protocol['scheme']
    prefix = protocol['prefix']
    port = protocol['port']
    rucioserver = protocol['hostname']

    if schema == 'srm':
        prefix = protocol['extended_attributes']['web_service_path'] + prefix
    url = schema + '://' + rucioserver
    if port != 0:
        url = url + ':' + str(port)
    rse_url = url + prefix
    
    return(rse_url)

def rucio_rses() :
    rses_lists = list()
    for single_rse in list(client.list_rses()) :
        rses_lists.append(single_rse['rse'])
    return(rses_lists)
    
def rucio_select_lfn2pfn(lfn, experiment) :

    if experiment.upper() == 'MAGIC':
        return(magic.collection_stats(lfn))
    elif experiment.upper() == 'CTA':
        return(cta.collection_stats(lfn))
    else : 
        sys.exit(0)


# In[5]:


############################

# Check existence of file at RSE

############################

def check_replica(myscope, lfn, dest_rse=None):
    """
    Check if a replica of the given file at the site already exists.
    """
    if lfn : 
        replicas = list(
            client.list_replicas([{
                'scope': myscope,
                'name': lfn
            }], rse_expression=dest_rse))
        
        if replicas:
            for replica in replicas:
                if isinstance(replica,dict) :
                    if dest_rse in replica['rses']:
                        path = replica['rses'][dest_rse][0]
                        return(path)
        return(False)

############################

# Get UTC time
class simple_utc(tzinfo):
    def tzname(self,**kwargs):
        return "UTC"
    def utcoffset(self, dt):
        return timedelta(0)
    
def get_UTC_time() :
    dt_string = datetime.utcnow().replace(tzinfo=simple_utc()).isoformat()
    dt_string = str(parser.isoparse(dt_string))
    return(dt_string)

# Merge dictionary 
def Merge(dict1, dict2): 
    res = dict1.copy()   # start with x's keys and values
    res.update(dict2)    # modifies z with y's keys and values & returns None
    return(res)

# Generate random run
def generate_random() :
    return(random.randint(10000000,99999999))
   
##############################

def make_dir(lfn) : 
    pfn = str(orgRSE_endpoint) + str(lfn)
    file_name, file_extension = os.path.splitext(pfn)
    
    if '.root' in file_extension or '.gz' in file_extension :
        pfn, file_name = os.path.split(pfn) 
        gfal.mkdir_rec(pfn, 775)

        
    else :
        # Check if our test folder still exists 
        gfal.mkdir_rec(pfn, 775)

####################################

def make_file(file_name, dest, size = 1000000):
    file_create = open(file_name, "wb")
    file_create.seek(size)
    file_create.write(b"\0")
    file_create.close ()

def make_folder_file(lfn, DestRSE) :
    
    # Try to build path + file 
    if lfn is not None : 
        lfn = str(orgRSE_endpoint) + str(lfn)
        file_path, file_name = os.path.split(lfn)
        make_file(file_name, file_path)
        
        dir_name = make_dir(lfn)

        try :
            cur_dir = os.getcwd()
            source = os.path.join(cur_dir, file_name)
            r = gfal.filecopy(params, 'file:///'+source, os.path.join(file_path,file_name))
            os.remove(file_name)
            
            return(lfn)
        
        except Exception as e:
            print("Copy failed: %s" % str(e))
            os.remove(file_name)
    else : 
        lfn = get_random_line(experiment_dump, DestRSE)
        
        if isinstance(lfn , list):
            lfn = lfn[0]
            
        lfn = make_folder_file(lfn)
        return(lfn)

# function to add to JSON 
def write_json(data, filename=json_file): 
    with io.open(filename, 'w') as f: 
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_random_line(experiment_dump, DestRSE, number=1, list_files=None):
    
    lines = open(experiment_dump).read().splitlines()
    
    if list_files == None :
        my_list = []
        
    else :
        print('this is list of file ', list_files)
        my_list = list_files
            
    for n in range(number) :  
        
        lfn = random.choice(lines)
        name_file = os.path.basename(lfn) 
        
        if isinstance(lfn, list):
            my_list.extend(lfn)  
            
        else :
            my_list.append(lfn)   
    
    while len(my_list) < number:
        lfn = get_random_line(experiment_dump, DestRSE, number, my_list)
        
        if isinstance(lfn, list):
            my_list.extend(lfn)
        else :
            my_list.append(lfn) 
            
    my_list = np.unique(my_list)       
    return(my_list) 


# In[6]:


if __name__ == '__main__':
    
    ###############################

    # File Creation

    ###############################

    # Initialize Rucio class and functions
    # Create the parser
    parser = argparse.ArgumentParser(add_help=True,
                                   description='Create files through a Rucio account', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--destRSEs', '-d', required=True, action='append', help='List of RSE of the filelist, e.g:--destRSEs PIC-DET --destRSEs PIC-DET-2 ')
    parser.add_argument('--working_folder', '-w', type=str, default='Server-test', help='Specific folder where the data is placed at the origin RSE, e.g:MAGIC-folder')
    parser.add_argument('--orgRSE', '-o', type=str, required=True, help='hostname for RSE; e.g:PIC-INJECT')
    parser.add_argument('--scope', '-s', type=str, required=True, help='Scope to regisister the files; e.g:test-root')
    parser.add_argument('--account', '-a', type=str, required=True, help='scheme for pfn; e.g:root')
    parser.add_argument('--experiment_dump', '-e', type=str, default='MAGIC', choices=['MAGIC', 'CTA'], help='Choose the experiment dump, e.g: MAGIC_dataset.txt or CTA_dataset.txt')
    parser.add_argument('--json_file', '-j', type=str, default='test.json', help='output json file; e.g:test.json') 
    # Execute the parse_args() method
    args = parser.parse_args()

    
    # Predifine origin RSE 
    orgRSE = args.orgRSE
    # Folder where the files will be created
    working_folder = args.working_folder
    # Predifine scope
    scope = args.scope
    # Destiny RSEs
    destRSEs = args.destRSEs
    # Experiment file dump
    experiment_dump = args.experiment_dump
    # experiment_dump = 'CTA_dataset.txt'
    # Json with the created files
    json_file = args.json_file

    # Gfal Configuration
    gfal = Gfal2Context()
    params = gfal.transfer_parameters()
    params.event_callback = event_callback
    params.monitor_callback = monitor_callback
    params.set_checksum = True
    params.overwrite = True
    params.set_create_parent= True
    params.get_create_parent= True 
    params.timeout = 300


    # Rucio Configuration
    account= args.account
    didc = DIDClient(account=account)
    repc = ReplicaClient(account=account)
    client = Client(account=account)
    rulesClient = RuleClient(account=account)

    print(json.dumps(client.whoami(), indent=4, sort_keys=True))
    print(json.dumps(client.ping(), indent=4, sort_keys=True))

    ######################################################

    for destRSE in destRSEs: 

        # Use a predefine folder to create random data 
        orgRSE_endpoint = os.path.join(get_rse_url(orgRSE), working_folder)   
        # Check if our test folder still exists 
        gfal.mkdir_rec(orgRSE_endpoint, 775)           
        # Generate dummy random files at PIC-INJECT  
        lfns = get_random_line(experiment_dump, destRSE, number=15)

        print(destRSE, 'this is list', len(lfns))
        for x in range(len(lfns)) :
            lfn = lfns[x]
            print(lfn)

            if 'MAGIC' in experiment_dump :
                lfn = magic.change_namespace(lfn)            
            if 'CTA' in experiment_dump : 
                lfn = cta.change_namespace(lfn)

            try :
                lfn = make_folder_file(lfn, destRSE)

                #print(lfn)
            except :
                PrintException()
