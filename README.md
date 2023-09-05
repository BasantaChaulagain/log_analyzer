# Log Analyzer

This repo contains the tools for analyzing linux audit logs.

## Module auditBridge 

This module converts raw audit logs to csv format. [34 fields](auditBridge/README_CSV.txt) are extracted from the raw audit logs and stored in csv file.

1. Build the files using a 'make' command.

2. Usage: ./UBSI_auditBridge -c -u -F <audit log file>  >  <output csv file>

## Module tracking

This module performs backtracking and forward tracking on the csv file converted using auditBridge module.

1. Build the files using a 'make' command.

2. For forward tracking: ./AUDIT_ft -i <csv file> -f <inode_number>

3. For backward tracking: ./AUDIT_bt -i <csv file> -p <pid>

4. To convert the .gv file to .png: dot -Tpng AUDIT_ft.gv > AUDIT_ft.png


** For details on the usage of these modules, use -h option. e.g: ./AUDIT_ft -h **