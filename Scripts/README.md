Here, there are two script that automates transfers using Rucio software.

1- Create files at a specific endpoint:
    [root@rucio03 ~]# python Rucio-Createfiles-client.py --help
    usage: Rucio-Createfiles-client.py [-h] --destRSEs DESTRSES
                                       [--working_folder WORKING_FOLDER] --orgRSE
                                       ORGRSE --scope SCOPE --account ACCOUNT
                                       [--experiment_dump {MAGIC,CTA}]
                                       [--json_file JSON_FILE]

    Create files through a Rucio account

    optional arguments:
      -h, --help            show this help message and exit
      --destRSEs DESTRSES, -d DESTRSES
                            List of RSE of the filelist, e.g:--destRSEs PIC-DET
                            --destRSEs PIC-DET-2
      --working_folder WORKING_FOLDER, -w WORKING_FOLDER
                            Specific folder where the data is placed at the origin
                            RSE, e.g:MAGIC-folder
      --orgRSE ORGRSE, -o ORGRSE
                            hostname for RSE; e.g:PIC-INJECT
      --scope SCOPE, -s SCOPE
                            Scope to regisister the files; e.g:test-root
      --account ACCOUNT, -a ACCOUNT
                            scheme for pfn; e.g:root
      --experiment_dump {MAGIC,CTA}, -e {MAGIC,CTA}
                            Choose the experiment dump, e.g: MAGIC_dataset.txt or
                            CTA_dataset.txt
      --json_file JSON_FILE, -j JSON_FILE
                            output json file; e.g:test.json


    [root@rucio03 ~]# python Rucio-Client-replication.py -h
    usage: Rucio-Client-replication.py [-h] --destRSEs DESTRSES
                                       [--working_folder WORKING_FOLDER] --orgRSE
                                       ORGRSE --scope SCOPE --account ACCOUNT
                                       [--experiment {None,MAGIC,CTA}]
                                       [--realistic_path REALISTIC_PATH]
                                       
2- Repicate the created files accross the datalake: 
    Replicate files from an two sites through a Rucio account

    optional arguments:
      -h, --help            show this help message and exit
      --destRSEs DESTRSES, -d DESTRSES
                            List of RSE of the filelist, e.g:--destRSEs PIC-DET
                            --destRSEs PIC-DET-2
      --working_folder WORKING_FOLDER, -w WORKING_FOLDER
                            Specific folder where the data is placed at the origin
                            RSE, e.g:MAGIC-folder
      --orgRSE ORGRSE, -o ORGRSE
                            hostname for RSE; e.g:PIC-INJECT
      --scope SCOPE, -s SCOPE
                            Scope to regisister the files; e.g:test-root
      --account ACCOUNT, -a ACCOUNT
                            scheme for pfn; e.g:root
      --experiment {None,MAGIC,CTA}, -e {None,MAGIC,CTA}
                            optional parameter to set lfn2pfn algortithm pfn;
                            e.g:MAGIC, CTA
      --realistic_path REALISTIC_PATH, -p REALISTIC_PATH
  
  
  Exemple of use:
  
    [root@rucio03 ~]# python Rucio-Client-replication.py --destRSEs PIC-DET-2 --orgRSE ORM-NON-DET --scope test-root --working_folder Server-test --account root --realistic_path True --experiment MAGIC
