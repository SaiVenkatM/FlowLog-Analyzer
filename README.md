# FlowLog-Analyzer
A log aggregation exercise based on on AWS Flow Log Records

### The following are the assumptions made while writing the program

* Created for the specific version 2, and could not find much support for other kind of version to create an universal script to work dynamically

* Plain Text Input Files: It's assumed that both input files are plan text files and encoded  n ASCII

* Log Delimeter: Constant delimeter( space by default) seperates fields within each line.

* Flow log structure (when no field names): If log_field_names are not provided, the program assumes a basic flow log structure where destination port is the 6th field, and protocol is the 8th field

* Data Integrity: It is assumed, the data in files are reasomnably well formed (like in the description provided). And input data will not contain any malicious code

* Mapping rules: It is assumed that, the combination of destination port and protocol in mapping rules are unique, and if there are duplicates, the last one read will override the previou one.

* Untagged Logic: The logic relies on the assumptioin that, if a log entry doesnot match any mapping rule, it would be counted as untagged.
  


### Instructions on running the code 

####  Requirements
- Python 3.x
- No additional libraries

#### Files

- `flowLogProcessor.py`
- `flow_logs.txt`
- `mappings.csv`
- `output.txt`


#### Usage

* If you prefer to run the script on your local system:

1. Download the `flowLogProcessor.py` script
2. Ensure you have the required input files (`flow_logs.txt` and `mapping.csv`)
3. Execute the following command:

```bash
python3 flowLogProcessor.py flow_logs.txt mapping.csv output.txt
```

* If you prefer to have it run in github directly (The flow_logs.txt. mapping.csv are generated according to `generateSampleFiles.py`)
1. Clone the repo
2. Navigate to the actions tab, in your github cloned repo
3. Select the `Flow Log Processor` workflow
4. In the right panel, click the run workflow dropdown and select ` Run workflow`
5. Or you can also trigger the workflow either by commiting, push, or pull
6. And the resulting output file would be automatically uploaded to parent folder of the repo.
   

