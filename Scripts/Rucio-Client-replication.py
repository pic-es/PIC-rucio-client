#!/usr/bin/env python
# coding: utf-8

# In[18]:


#!/usr/bin/env python

import sys,os,os.path, io,json,datetime, time, subprocess, traceback,linecache,logging,os,os.path,random,re,time,uuid,zipfile,string,pathlib,time,pytz,graphyte,socket,logging, datetime

os.environ['RUCIO_HOME']=os.path.expanduser('~/rucio')


# In[19]:



from rucio.client import Client
from rucio.common.exception import Duplicate

account='root'
auth_type='x509_proxy'

# account=account, auth_type=auth_type
client = Client(account=account)
print(client.whoami())
print(client.ping())


# In[20]:


# Set Rucio virtual environment configuration 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import numpy as np 
from urllib.parse import urlunsplit
from io import StringIO

# Import Specific MAGIC and CTA parameters 
import lfn2pfn_MAGIC as magic
import lfn2pfn_CTA as cta

# IMport Rucio dependencies
from rucio.rse import rsemanager as rsemgr
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
import rucio.rse.rsemanager as rsemgr
from rucio.client.ruleclient import RuleClient
from rucio.client.uploadclient import UploadClient
from rucio.client.downloadclient import DownloadClient
from rucio.common.utils import (adler32, detect_client_location, 
                                execute, generate_uuid, md5, 
                                send_trace, GLOBALLY_SUPPORTED_CHECKSUMS)
from rucio.common.exception import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    AccessDenied, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)

# Import Gfal
import sys
sys.path.append("/usr/lib64/python3.6/site-packages/")
import gfal2
from gfal2 import (
    Gfal2Context,
    GError,
)

# Import parser 
import argparse


# In[21]:


class Rucio :
    def __init__(self, myscope, orgRSE, destRSEs, account='bruzzese', working_folder='None', experiment=None, realistic_path=False):
        
        # Global Rucio variables 
        self.myscope = myscope
        self.orgRSE = orgRSE 
        self.destRSEs = destRSEs
        self.working_folder = working_folder
        self.experiment = experiment
        self.realistic_path = realistic_path
        # Gfal context
        self.gfal = Gfal2Context()
        
        # Rucio Configuration
        self.account = account
        self.didc = DIDClient()
        self.repc = ReplicaClient()
        self.rulesClient = RuleClient()
        self.client = Client(account=self.account)

    def rucio_metadata(self, did, key, value) :
        set_meta = self.didc.set_metadata(scope=self.myscope, name=did, key=key, value=value, recursive=False)
        return(True)
    
    def rucio_rses(self) :
        rses_lists = list()
        for single_rse in list(self.client.list_rses()) :
            rses_lists.append(single_rse['rse'])
        return(rses_lists)
    
    def rucio_rse_usage(self,s_rse) :
        return(list(self.client.get_local_account_usage(account=self.account,rse=s_rse))[0])
        
    def rucio_list_rules(self) :
        return(list(self.client.list_account_rules(account=self.account)))
    
    def rucio_replication_parameters(self):
        rses_lfn2pfn = list()
        for single_rse in self.destRSEs :
            rses_lfn2pfn.append(rsemgr.get_rse_info(single_rse)["lfn2pfn_algorithm"])

        print()
        print("Hello your setting are account=%s, scope=%s, origin RSE =%s and destination RSE =%s" %(self.account, self.myscope, self.orgRSE, self.destRSEs))
        print("You will be replicating files to the following RSEs =%s using the following lfn2pfn_algorithm =%s, respectively" %(self.destRSEs, list(rses_lfn2pfn)))

        if self.experiment is not None : 
            
            if self.experiment.upper() == 'MAGIC':
                print('In combination with the organization and metadata configure according to the MAGIC lfn2pfn')
            elif self.experiment.upper() == 'CTA':
                print('In combination with the organization and metadata configure according to the CTA lfn2pfn')
            else: 
                print("The experiment variable did not match PIC's lfn2pfn algortihms, using RSEs default algorithm")      
        print()
                
    def rucio_rse_url(self):
        """
        Return the base path of the rucio url
        """
        rse_settings = rsemgr.get_rse_info(self.orgRSE)
        protocol = rse_settings['protocols'][0]
        
        schema = protocol['scheme']
        prefix = protocol['prefix']
        port = protocol['port']
        rucioserver = protocol['hostname']
        
        rse_url = list()
        if None not in (schema,str(rucioserver+':'+str(port)),prefix): 
            rse_url.extend([schema,rucioserver+':'+str(port),prefix,'',''])
            if self.working_folder != None :
                # Check if our test folder exists
                path = os.path.join(urlunsplit(rse_url), self.working_folder)
                self.gfal.mkdir_rec(path, 775)
                return(path)
            else :
                return(urlunsplit(rse_url))
        else :
            return('Wrong url parameters')    

    def rucio_check_replica(self, lfn, destRSE=None):
        """
        Check if a replica of the given file at the site already exists.
        """
        # print('here', self.myscope, lfn, destRSE)
        if lfn :
            try:  
                replicas = list(
                    self.client.list_replicas([{'scope': self.myscope,'name': lfn}], rse_expression=destRSE))

                if replicas:
                    for replica in replicas:
                        if isinstance(replica,dict) :
                            if destRSE in replica['rses']:
                                path = replica['rses'][destRSE][0]
                                return(path)
                return(False)
            except:
                return(False)

    def gfal_check_file(self, lfn) :
        try :
            self.gfal.stat(lfn).st_size
            return(True)
        except : 
            return(False)
        
    ############################

    ## Prepare DIDs for Rucio

    ############################    
    def rucio_file_stat(self, lfn):
        """
        Get the size and checksum for every file in the run from defined path
        """ 
        '''
        generate the registration of the file in a RSE :
        :param rse: the RSE name.
        :param scope: The scope of the file.
        :param name: The name of the file.
        :param bytes: The size in bytes.
        :param adler32: adler32 checksum.
        :param pfn: PFN of the file for non deterministic RSE  
        :param dsn: is the dataset name.
        '''
        Data = dict(); 
        Data['scope'] = self.myscope
          
        
        name_file = os.path.basename(lfn)
        name_file = name_file.replace('/','')
        name_file = name_file.replace('%','_')

        # Look for create and attach groups 
        # look at script lfn2pfn

        if self.realistic_path is False:
            did_name = r1.rucio_select_lfn2pfn(lfn)['replica'].replace('%','_').replace('+','_')
            Data['collections'] = r1.rucio_select_lfn2pfn(lfn)
            Data['rule'] = r1.rucio_select_lfn2pfn(lfn)['replication_collection'] 
        else: 
            did_name = r1.rucio_select_lfn2pfn(lfn)['pfn'].replace('%','_').replace('+','_')
            Data['collections'] = r1.rucio_select_lfn2pfn(lfn)
            Data['rule'] = r1.rucio_select_lfn2pfn(lfn)['replication_collection']     
            
        replica = {
        'scope': self.myscope,
        'name': did_name.replace('%','_').replace('+','_'),
        'adler32': self.gfal.checksum(lfn, 'adler32'),
        'bytes': self.gfal.stat(lfn).st_size,
        'pfn': lfn,
        "meta": {"guid": str(generate_uuid())}
        }
        Data['replica'] = replica

        return(Data) 

    ############################

    ## Create Groups of DIDs

    ############################
    def rucio_create_dataset(self, name_dataset) :         
        logger.debug("|  -  - Checking if a provided dataset exists: %s for a scope %s" % (name_dataset, self.myscope))
        try:
            self.client.add_dataset(scope=self.myscope, name=name_dataset)
            return(True)
        except DataIdentifierAlreadyExists:
            return(False)
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            exc_type, exc_obj, tb = sys.exc_info()
            logger.debug(exc_obj)

    def rucio_create_container(self, name_container):
        '''
        registration of the dataset into a container :
        :param name_container: the container's name
        :param info_dataset : contains, 
            the scope: The scope of the file.
            the name: The dataset name.
        '''
        logger.debug("|  -  -  - registering container %s" % name_container)

        try:
            self.client.add_container(scope=self.myscope, name=name_container)
        except DataIdentifierAlreadyExists:
            logger.debug("|  -  -  - Container %s already exists" % name_container)       
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            exc_type, exc_obj, tb = sys.exc_info()
            logger.debug(exc_obj)
    
    ############################

    ## General funciotn for registering a did into a GROUP of DID (CONTAINER/DATASET)

    ############################
    def rucio_attach_did(self,file_name, dataset_name):
        """
        Attaching a DID to a Collection
        """
        type_1 = self.client.get_did(scope=self.myscope, name=dataset_name)
        type_2 = self.client.get_did(scope=self.myscope, name=file_name)
        
        print('attaching ',file_name, dataset_name)
        try:
            self.client.attach_dids(scope=self.myscope, name=dataset_name, dids=[{'scope':self.myscope, 'name':file_name}])
        except RucioException:
            logger.debug("| - - - %s already attached to %s" %(type_2['type'],type_1['type']))    

    ############################

    ## MAGIC functions 

    ############################
    def rucio_collections(self, collection) :

        if collection['collections']['dataset_1'] :
            # 2.1.1) Create the dataset and containers for the file
            self.rucio_create_dataset(collection['collections']['dataset_1'].replace('%','_'))
            # 2.1.2) Attach the dataset and containers for the file
            self.rucio_attach_did(collection['replica']['name'], collection['collections']['dataset_1'].replace('%','_'))
            
            if collection['collections']['container_1'] :
                # 2.2.1) Create the dataset and containers for the file
                self.rucio_create_container(collection['collections']['container_1'].replace('%','_'))
                # 2.2.2) Attach the dataset and containers for the file
                self.rucio_attach_did(collection['collections']['dataset_1'].replace('%','_'), collection['collections']['container_1'].replace('%','_'))
                                    
                if collection['collections']['container_2'] :  
                    # 2.3.1) Create the dataset and containers for the file
                    self.rucio_create_container(collection['collections']['container_2'].replace('%','_'))
                    # 2.3.2) Attach the dataset and containers for the file
                    self.rucio_attach_did(collection['collections']['container_1'].replace('%','_'), collection['collections']['container_2'].replace('%','_'))                  
                                      
                    if collection['collections']['container_3'] :  
                        # 2.4) Create the dataset and containers for the file
                        self.rucio_create_container(collection['collections']['container_3'].replace('%','_'))
                        # 2.4.1) Attach the dataset and containers for the file
                        self.rucio_attach_did(collection['collections']['container_2'].replace('%','_'), collection['collections']['container_3'].replace('%','_'))                


    ############################

    ## Select collections and metadata from MAGIC, CTA, or neither functions 

    ############################
    def rucio_select_lfn2pfn(self,lfn) :
        
        if self.experiment.upper() == 'MAGIC':
            return(magic.collection_stats(lfn))
        elif self.experiment.upper() == 'CTA':
            return(cta.collection_stats(lfn))
        else : 
            file_data = dict();
            file_data = {'dataset_1':'main_dataset', 'replication_collection':'main_dataset', 'replica':lfn, 'pfn':os.path.join('main_dataset',lfn)}
            return(file_data)            
    
    ############################

    ## Create Rule for DIDs

    ############################            
    def rucio_add_rule(self, destRSE, collection, asynchronous=False):
        """
        Create a replication rule for one dataset at a destination RSE
        """

        type_1 = self.client.get_did(scope=self.myscope, name=collection)
        logger.debug("| - - - Creating replica rule for %s %s at rse: %s" % (type_1['type'], collection, destRSE))
        if destRSE:
            try:
                rule = self.rulesClient.add_replication_rule([{"scope":self.myscope,"name":collection}],copies=1, rse_expression=destRSE, grouping='ALL', 
                                                             account=self.account, purge_replicas=True, asynchronous=asynchronous)
                logger.debug("| - - - - Rule succesfully replicated at %s" % destRSE)
                logger.debug("| - - - - - The %s has the following id %s" % (rule, destRSE))
                return(rule[0])
            except DuplicateRule:
                exc_type, exc_obj, tb = sys.exc_info()
                rules = list(self.client.list_account_rules(account=self.account))
                if rules : 
                    for rule in rules :
                        if rule['rse_expression'] == destRSE and rule['scope'] == self.myscope and rule['name'] == collection:
                            logger.debug('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],self.myscope, collection, str(exc_obj)))
            except ReplicationRuleCreationTemporaryFailed:    
                exc_type, exc_obj, tb = sys.exc_info()
                rules = list(self.client.list_account_rules(account=self.account))
                if rules : 
                    for rule in rules :
                        if rule['rse_expression'] == destRSE and rule['scope'] == self.myscope and rule['name'] == collection:
                            print('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],self.myscope, collection, str(exc_obj)))                  
                            
                                            
    ############################

    ## Create Rules for not registered DIDs

    ############################  
    def outdated_register_replica(self, filemds, destRSE, orgRSE):
        """
        Register file replica.
        """
        carrier_dataset = 'outdated_replication_dataset' + '-' + str(uuid.uuid4())

        creation = self.rucio_create_dataset(carrier_dataset)

        # Make sure your dataset is ephemeral

        # self.client.set_metadata(scope=self.myscope, name=carrier_dataset, key='lifetime', value=86400) # 86400 in seconds = 1 day       

        # Create a completly new create the RULE: 
        for filemd in filemds :
            outdated = filemd['replica']['name']
            self.rucio_attach_did(outdated, carrier_dataset)
            
        # Add dummy dataset for replicating at Destination RSE
        for i in range(0,10):
            try:
                rule = self.rucio_add_rule(destRSE, collection=carrier_dataset, asynchronous=False)
                if rule != None :
                    rule_child = rule 
                print(rule_child)
                break
            except :
                print('fail')
                continue

        for i in range(0,10):
            try:
                rule = self.rucio_add_rule(orgRSE, collection=carrier_dataset, asynchronous=True)
                if rule != None :
                    rule_parent = rule
                print(rule_parent)
                break
            except :
                print('fail')
                continue

        # Add dummy dataset for replicating Origin RSE 
        # Create a relation rule between origin and destiny RSE, so that the source data can be deleted 
        rule = self.client.update_replication_rule(rule_id=rule_parent, options={'lifetime': 10, 'child_rule_id':rule_child, 'purge_replicas':True})
        logger.debug('| - - - - Creating relationship between parent %s and child %s : %s' % (rule_parent, rule_child, rule))

        # Create a relation rule between the destinity rule RSE with itself, to delete the dummy rule, whiles keeping the destiny files    
        rule = self.client.update_replication_rule(rule_id=rule_child, options={'lifetime': 10, 'child_rule_id':rule_child})
        logger.debug('| - - - - Creating relationship between parent %s and child %s : %s' % (rule_parent, rule_child, rule))                          
                        


# In[22]:


class Find_files :
    def __init__(self) :

        self.gfal = Gfal2Context()
        
    def check_directory(self, path):
        try :
            full_path = self.gfal.listdir(str(path))
            is_dir_or_not = True        
        except:
            is_dir_or_not = False

        return(is_dir_or_not)

    def scrap_through_files(self, path) : 

        all_files = []

        # Itinerate over all the entries  
        listFiles = self.gfal.listdir(str(self.path))
        for file in [x for x in listFiles if x != '.' if x != '..']:
        # Create full Path 
            fullPath = os.path.join(self.path, file)
            is_dir = self.check_directory(fullPath) 
            # If entry is a directory then get the list of files in
            if is_dir == True :
                pass
            else :
                all_files.append(fullPath) 
        return(all_files)

    def scrap_through_dir(self, path) : 
        
        logger.debug("*-Listin files from url : %s" % path)
        all_files = []

        # Itinerate over all the entries  
        listFiles = self.gfal.listdir(str(path))
        for file in [x for x in listFiles if x != '.' if x != '..']:
            # Create full Path 
            fullPath = os.path.join(path, file)
            is_dir = self.check_directory(fullPath)
            # If entry is a directory then get the list of files in
            if is_dir == True :
                logger.debug('|--- ' + fullPath + ' its a directory ')
                all_files = all_files + self.scrap_through_dir(fullPath)

            else :
                logger.debug('|--- '+ fullPath + ' its a file')
                all_files.append(fullPath)
                
        return(all_files)
    


# In[23]:


# Get UTC time
class simple_utc(datetime.tzinfo):
    def tzname(self,**kwargs):
        return "UTC"
    def utcoffset(self, dt):
        return timedelta(0)
    
def get_UTC_time() :
    dt_string = datetime.utcnow().replace(tzinfo=simple_utc()).isoformat()
    dt_string = str(parser.isoparse(dt_string))
    return(dt_string)

def check_transfers_rucio(input_file, output_file):
    if os.path.isfile(input_file):
        file = open(input_file, "r+")
        lines = file.readlines()
        file.close()
        
        count = 0
        new_file = open(input_file, "w+")
        n_replicated = []  
        for line in lines:
            print("Line{}: {}".format(count, line.replace("\n", "").strip()))
            parts = line.split() # split line into parts
            if len(parts) > 1:   # if at least 2 parts/columns
                lfn = parts[0]
                destRSE = parts[1]   # print column 2
                del lines[count]
                # lines.pop(count)
                count += 1
                print(line.replace("\n", ""), destRSE)
                check = r1.rucio_check_replica(lfn, destRSE=destRSE)
                print(check)
                if check != False : ## needs to be changed to False

                    bashCommand = str("gfal-stat " + check)
                    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)

                    while True:
                        output = process.stdout.readline()
                        if output:
                            stat = str(output.strip())
                            #print(stat)
                            if "Modify" in stat:
                                stat = stat.replace("b", "").strip().replace("'", "").strip().replace("Modify:", "").strip() 
                                n_replicated.append(line.replace("\n", "") + '\t' +  str(destRSE) + '\t' + stat) 
                        result = process.poll()
                        if result is not None:
                            break
        if len(n_replicated) > 0 :
            dt_string = datetime.datetime.today().strftime('%Y%m%d-%H_%M_%S')
            make_file_transfer(n_replicated, output_file+'-'+str(destRSE)+'-'+str(dt_string))

        lines = [s.rstrip() for s in lines] # remove \r
        lines = list(filter(None, lines)) # remove empty 
        make_file_transfer(lines, output_file=input_file)
        
def make_file_transfer(list_lfn, output_file=r'sample.txt'):
    
    print('writing output file at ' + output_file)
    # Open a file with access and read mode 'a+'
    file_object = open(output_file, 'a')
    # Append 'hello' at the end of file
    
    for lfn in list_lfn:
        print(lfn)        
        file_object.write(lfn+'\n')
        # Close the file
    
    file_object.close()


# In[24]:



############################

# Replication files through Rucio

############################

def replication_files_rucio() : 
        
    # Look for files in the orgRse
    l1 = Find_files()
    listOfFiles = l1.scrap_through_dir(r1.rucio_rse_url())

    if listOfFiles :
        # Create a list with the properties for writing a text file 
        all_list_unreplicated = []       
        for destRSE in r1.destRSEs :
            # Create an array for those files that has not been replicated 
            n_unreplicated = []  
            list_unreplicated = []  
            for n in range(0,len(listOfFiles)):
                
                lfn = str(listOfFiles[n])
                logger.debug('|  -  ' + str(n) + ' - ' + str(len(listOfFiles)) + ' name : ' + lfn)
                
                # Break down the file path
                file_name = base=os.path.basename(lfn)
                # Sometimes storages change some caracters
                file_name_2 = file_name.replace('%','_').replace('+','_')

                # Check if file is already is registered at a particular destination RSE
                print(str(n) + ' - ' + str(len(listOfFiles)) + ' ' + file_name_2 + ' ' + destRSE) 

                # 1) Get the file stat
                fileStat = r1.rucio_file_stat(lfn)                
                check = r1.rucio_check_replica(lfn=fileStat['replica']['name'], destRSE=destRSE)
                
                # If it is registered, skip add replica 
                if check != False : ## needs to be changed to False
                    logger.debug('| - - The FILE %s already have a replica at RSE %s : %s' % (file_name, destRSE, check))
                    print('{} {} already added'.format(fileStat['replica']['name'], destRSE))
                # Else, if the files has no replica at destination RSE
                else :
                    print(json.dumps(fileStat, indent=4, sort_keys=True))
                    r1.client.add_replicas(rse=r1.orgRSE, files=[fileStat['replica']])
                    
                    # 2) Add metadata from experiments
                    if fileStat['collections']['metadata'] :
                        for key in fileStat['collections']['metadata'] :
                            print('adding key =%s metadata with value =%s' %(key, fileStat['collections']['metadata'][str(key)]))
                            r1.rucio_metadata(fileStat['replica']['name'], key, fileStat['collections']['metadata'][str(key)])

                    # 3) Create rucio's collections [datasets, & or containers]:
                    r1.rucio_collections(fileStat)
                    
                    # 5) Create the Main Replication Rule at Destination RSE
                    # main_rule = r1.rucio_add_rule(destRSE, fileStat['rule'], asynchronous=False)
                    logger.debug("| - - - - Getting parameters for rse %s" % destRSE)

                    # 6) Create the json array 

                    # Finally, add them to a general list 
                    n_unreplicated.append(fileStat)
                    list_unreplicated.append(fileStat['replica']['name'] + '\t' +  str(destRSE)) 
                    all_list_unreplicated.append(fileStat['replica']['name'] + '\t' +  str(destRSE)) 
            logger.debug('Your are going to replicate %s files' % str(len(n_unreplicated)))   
            print('Your are going to replicate %s files' % str(len(n_unreplicated)))
            ## Now, create Dummy rules between the ORIGIN and DESTINATION RSEs  
            if len(n_unreplicated) > 0 :
                r1.outdated_register_replica(n_unreplicated, destRSE, r1.orgRSE)

                dt_string = datetime.datetime.today().strftime('%Y%m%d-%H_%M_%S')
                make_file_transfer(list_unreplicated, output_file='MAGIC_replicated'+'-'+str(destRSE)+'-'+str(dt_string))
                print(len(n_unreplicated), destRSE, r1.orgRSE)
        # Finally return the information of the replicas as a dictionary
        return(all_list_unreplicated)


# In[25]:


if __name__ == '__main__':
    
    # Initialize Rucio class and functions
    # Create the parser
     # You could also configure the code to specific parameters

    # Initialize Rucio class and functions
    # Create the parser
    parser = argparse.ArgumentParser(add_help=True,
                                   description='Replicate files from an two sites through a Rucio account', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--destRSEs', '-d', required=True, action='append', help='List of RSE of the filelist, e.g:--destRSEs PIC-DET --destRSEs PIC-DET-2 ')
    parser.add_argument('--working_folder', '-w', type=str, default=None, help='Specific folder where the data is placed at the origin RSE, e.g:MAGIC-folder')
    parser.add_argument('--orgRSE', '-o', type=str, required=True, help='hostname for RSE; e.g:PIC-INJECT')
    parser.add_argument('--scope', '-s', type=str, required=True, help='Scope to regisister the files; e.g:test-root')
    parser.add_argument('--account', '-a', type=str, required=True, help='scheme for pfn; e.g:root')
    parser.add_argument('--experiment', '-e', type=str, default=None, choices=['None', 'MAGIC', 'CTA'], help='optional parameter to set lfn2pfn algortithm pfn; e.g:MAGIC, CTA')
    parser.add_argument('--realistic_path', '-p', type=bool, default=False, help='construct realistic path base on the experiment option')
    parser.add_argument('--input_file', '-x', type=str, required=True, help='file s name with the replicated files')
    parser.add_argument('--output_file', '-y', type=str, required=True, help='prefix file name wih for containing the replication and finish names')
    
    # Execute the parse_args() method
    args = parser.parse_args()

    # Initialize Rucio class and functions

    r1 = Rucio(myscope=args.scope, orgRSE=args.orgRSE,
               destRSEs=args.destRSEs, account=args.account,
               working_folder=args.working_folder, experiment=args.experiment,
               realistic_path=args.realistic_path)
    
    input_file = args.input_file
    output_file = args.output_file
    # You could also configure the code to specific parameters
    '''
    r1 = Rucio(myscope='test-root', orgRSE='ORM-NON-DET', 
               destRSEs=['PIC-DET-2'], 
               account='root', working_folder='Server-test', experiment='MAGIC', realistic_path=True)
    '''
    r1.rucio_replication_parameters()    
    replication_list = replication_files_rucio()
    if replication_list: 
        if len(replication_list) > 0 :
            make_file_transfer(replication_list, output_file=input_file)
        
    # creates a resulting dictionary with the files found with their respective 
    # RSEs where they have been replicated
    check_transfers_rucio(input_file, output_file=output_file)
    


# In[ ]:




