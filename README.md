# FlowLog-Analyzer
A log aggregation exercise based on on AWS Flow Log Records

### The following are the assumptions made while writing the program

* Plain Text Input Files: It's assumed that both input files are plan text files and encoded  n ASCII

* Log Delimeter: Constant delimeter( space by default) seperates fields within each line.

* Flow log structure (when no field names): If log_field_names are not provided, the program assumes a basic flow log structure where destination port is the 6th field, and protocol is the 8th field

* Data Integrity: It is assumed, the data in files are reasomnably well formed (like in the description provided). And input data will not contain any malicious code


* Mapping rules: It is assumed that, the combination of destination port and protocol in mapping rules are unique, and if there are duplicates, the last one read will override the previou one.

* Untagged Logic: The logic relies on the assumptioin that, if a log entry doesnot match any mapping rule, it would be counted as untagged.


