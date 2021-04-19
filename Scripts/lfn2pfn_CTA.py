"""
lfn2pfn.py

Default LFN-to-path algorithms for CTA
"""
import re, os, pathlib, datetime, time, random


############################
    
def look_for_run(fileName) :  

    try :
        run = re.search('\d{5}\.', fileName)
        if not run :
            run = re.search('_\d{5}', fileName)
            run = run[0].replace('_','')
        elif (type(run).__module__, type(run).__name__) == ('_sre', 'SRE_Match') : 
            run = run.group(0)
            run = run.replace('.','')
        else :
            run = run[0].replace('.','')         
        return(str(run))
    except : 
        pass
    
    try :
        if not run :
            run = re.findall('\d{5}\_', fileName)
            run = run[0].replace('_','')
        return(str(run))
    except : 
        pass

def look_for_date(fileName) :  
    try :
        date = re.findall('\d{8}', fileName)   
        return(datetime.datetime.strptime(date[0], '%Y%m%d').strftime('%Y_%m_%d'))
    except : 
        pass
    
def look_for_type_files(fileName) :
    patterns_1 = ['dl1', 'dl2', 'muons_']
    
    matching_1 = [s for s in patterns_1 if s in fileName]
    if matching_1 :
        if matching_1[0] == 'muons_':
            matching_1 = ['dl1']
            
        matching = 'LST_' + str(matching_1[0]).upper()
    else : 
        matching = 'LST_RAW'
    
    return(str(matching))

def get_datatype(fileName) :
    patterns_1 = ['dl1', 'dl2', 'muons_']
    
    matching_1 = [s for s in patterns_1 if s in fileName]
    if matching_1 :
        if matching_1[0] == 'muons_':
            matching_1 = ['dl1']
            
        matching = str(matching_1[0]).upper()
    else : 
        matching = 'RAW'

    return(str(matching))


############################

def collection_stats(lfn) :
    file_data = dict();
    metadata = dict();
    
    file_name = os.path.basename(lfn)
    file_data['replica'] = file_name.replace('+','_')
    file_data['pfn'] = "/".join(filter(bool, [look_for_type_files(lfn),look_for_date(lfn),look_for_run(file_name),file_name.replace('+','_')]))

    metadata['night'] = look_for_date(lfn) 
    metadata['run_number'] = look_for_run(lfn) 
    metadata['telescope'] = 'LST' 
    metadata['datatype'] = get_datatype(lfn) 
    
    file_data['dataset_1'] = look_for_run(file_name)
    file_data['container_1'] = look_for_date(lfn)    
    file_data['container_2'] = look_for_type_files(lfn) 
    file_data['replication_collection'] =  look_for_type_files(lfn)   
    file_data['metadata'] = metadata
    
    return(file_data)
     

def change_namespace(lfn) :          

    date = re.findall('\d{8}', lfn)
    runs = re.findall('\d{4}\.', lfn)
    for run in runs : 
        new_run = str(random.randint(1000,9999))+'.' 
        lfn = lfn.replace(run, new_run)

    today = str(time.strftime('%Y%m%d'))

    lfn = os.path.join('/',lfn.replace(date[0], today))
    return(lfn)

############################


if __name__ == '__main__':

    def test_magic_mapping(lfn):
        print(lfn)
        """Demonstrate the LFN->PFN mapping"""
        mapped_pfn = collection_stats(name)
        print(mapped_pfn)
