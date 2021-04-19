"""
lfn2pfn.py
Default LFN-to-path algorithms for MAGIC
"""
import re, os, pathlib, datetime, time

############################

def look_for_date(fileName) :
    fileName = fileName.replace('/','-')
    fileName = fileName.replace('_','-')
    
    try :
        date = re.search('\d{4}-\d{2}-\d{2}', fileName)
        date = datetime.datetime.strptime(date.group(), '%Y-%m-%d').strftime('%Y_%m_%d')
        return(str(date))
    except : 
        pass

    if not date :
        base, name = os.path.split(name_file)  

        file_name = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]', name)

        date = datetime.strptime(file_name[0], "%Y%m%d").date()
        return(str(date))
    
def look_for_run(fileName) :  

    try :
        run = re.search('\d{8}\.', fileName)
        if not run :
            run = re.search('_\d{8}', fileName)
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
            run = re.findall('\d{8}\_', fileName)
            run = run[0].replace('_','')
        return(str(run))
    except : 
        pass
    
def look_for_type_files(fileName) :
    patterns_1 = ['RAW', 'Calibrated', 'Calibrated', 'Star', 'SuperStar', 'Melibea']
    patterns_2 = ['M1', 'M2', 'ST']
    
    matching_1 = [s for s in patterns_1 if s in fileName]
    matching_2 = [s for s in patterns_2 if s in fileName]
    if matching_1 and matching_2 :
        matching = str(matching_1[0]) + '_' + str(matching_2[0])
        return(str(matching))

def look_for_sources(path) :
    
    base, file_name = os.path.split(path)
    run = str(look_for_run(file_name))

    file_name = re.findall(r'[A-Z]_([^"]*)-W', file_name)
    if not file_name: 
        file_name = os.path.basename(path)
        file_name = file_name.replace(pathlib.Path(file_name).suffix, '')

        file_name = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]', file_name)

        file_name = [i for i in file_name if not i.isdigit()]
        file_name = max(file_name, key=len)    
    else :
        file_name = file_name[0].replace('+','-')
        
    if run in file_name : 
        file_name = file_name.replace(run,'')
        
    return(str(file_name))

def get_datatype(fileName):

    patterns_1 = ['RAW', 'Calibrated', 'Calibrated', 'Star', 'SuperStar', 'Melibea']
    matching_1 = [s for s in patterns_1 if s in fileName]
    if matching_1 :
        return(str(matching_1))
    
def get_telescope(fileName):
    patterns_1 = ['M1', 'M2', 'ST']
    matching_1 = [s for s in patterns_1 if s in fileName]
    if matching_1 :
        return(str(matching_1[0]))
    
def get_source(path):
    base, file_name = os.path.split(path)
    run = str(look_for_run(file_name))

    file_name = re.findall(r'[A-Z]_([^"]*)-W', file_name)
    if not file_name: 
        file_name = os.path.basename(path)
        file_name = file_name.replace(pathlib.Path(file_name).suffix, '')

        file_name = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]', file_name)

        file_name = [i for i in file_name if not i.isdigit()]
        file_name = max(file_name, key=len)    
    else :
        file_name = file_name[0].replace('+','-')
        
    if run in file_name : 
        file_name = file_name.replace(run,'')
        
    return(str(file_name))

############################

def collection_stats(lfn) :
    file_data = dict();
    metadata = dict();
    
    file_name = os.path.basename(lfn)
    file_data['replica'] = file_name.replace('+','_')
    file_data['pfn'] = "/".join(filter(bool, [look_for_type_files(lfn),look_for_sources(lfn),look_for_date(lfn),look_for_run(lfn),file_name.replace('+','_')]))

    metadata['night'] = look_for_date(lfn) 
    metadata['run_number'] = look_for_run(lfn) 
    metadata['telescope'] = get_telescope(lfn) 
    metadata['datatype'] = get_source(lfn) 

    file_data['dataset_1'] = look_for_run(lfn)
    file_data['container_1'] = look_for_date(lfn)
    file_data['container_2'] = look_for_sources(lfn)
    file_data['container_3'] = look_for_type_files(lfn) 
    file_data['replication_collection'] = look_for_type_files(lfn)
    file_data['metadata'] = metadata
    
    return(file_data)

def change_namespace(lfn) :          
    try:
        date = re.search('\d{4}_\d{2}_\d{2}', lfn)
        date = datetime.datetime.strptime(date.group(), '%Y_%m_%d').date()
        date = date.strftime('%Y_%m_%d')
        today = str(time.strftime('%Y_%m_%d'))
        lfn = os.path.join('/',lfn.replace(date, today))
    except: 
        pass
    try:    
        file_path, file_name = os.path.split(lfn)  
        file_name = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]', file_name)
        date = datetime.datetime.strptime(file_name[0], "%Y%m%d").date()
        date = date.strftime('%Y%m%d') 
        today = str(time.strftime('%Y%m%d'))
        lfn = os.path.join('/',lfn.replace(date, today))
    except: 
        pass
    return(lfn)
############################


if __name__ == '__main__':

    def test_magic_mapping(lfn):
        """Demonstrate the LFN->PFN mapping"""
        mapped_pfn = collection_stats(name)
        print(mapped_pfn)

    test_magic_mapping("testing", "root://xrootd.pic.es:1094/pnfs/pic.es/data/escape/rucio/pic_inject/Magic-test/data/M1/OSA/Calibrated/2020/02/03/20200203_M1_10284097.005_D_CrabNebula-W0.40+035.root")
    test_magic_mapping("testing", "root://xrootd.pic.es:1094/pnfs/pic.es/data/escape/rucio/pic_inject/Magic-test/data/M1/OSA/Calibrated/2020/02/03/20200203_M1_10382583.007_D_Perseus-MA-W0.26+288.root")
    test_magic_mapping("testing", "root://xrootd.pic.es:1094/pnfs/pic.es/data/escape/rucio/pic_inject/Magic-test/data/ST/OSA/SuperStar/2020/02/03/superstar75939036.root")
    test_magic_mapping("testing", "root://xrootd.pic.es:1094/pnfs/pic.es/data/escape/rucio/pic_inject/Magic-test/data/ST/OSA/Melibea/2020/02/03/melibea39615589.root")
