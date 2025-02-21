# FlowLog-Analyzer
A log aggregation exercise based on on AWS Flow Log Records

## The following are the assumptions made while writing the program

* Created for the all the versions, including the custom formats (check for instructions on running the code below)

* Plain Text Input Files: It's assumed that both input files are plan text files and encoded  in ASCII

* Portmapping keyword to number derived from IANA
  
* Log Delimeter: Constant delimeter( space by default) seperates fields within each line.

* Flow log structure (when no field names): If log_field_names are not provided, the program assumes a basic flow log structure where destination port is the 6th field, and protocol is the 8th field (V2, unless specified in log)

* Data Integrity: It is assumed, the data in files are reasomnably well formed (like in the description provided). And input data will not contain any malicious code

* Mapping rules: It is assumed that, the combination of destination port and protocol in mapping rules are unique, and if there are duplicates, the last one read will override the previou one.

* Untagged Logic: The logic relies on the assumptioin that, if a log entry doesnot match any mapping rule, it would be counted as untagged.
  


## Instructions on running the code 

###  Requirements
- Python 3.x
- No additional libraries

### Files

- `flowLogProcessor.py`
- `flow_logs.txt`
- `mappings.csv`
- `protocolnumber1.csv`
- `output.txt`


### Usage

generateSampleFiles.py: Generates test flow logs in various formats
flowLogProcessor.py: Processes and analyzes flow logs

#### Manual Log Generation (If not needed skip to Log Processor)
The generator creates test flow logs in various AWS VPC Flow Log formats for testing and development.

##### Basic Usage

```bash
python generatorSampleFiles.py
```

This creates log files for all versions (2, 3, 4, 5, 7) in a directory called "flow_logs".

##### Common Options

| Option | Description |
|--------|-------------|
| `--versions 2 3 5` | Generate only versions 2, 3, and 5 |
| `--custom_sets minimal network_security` | Generate specific custom formats |
| `--logs_per_file 5000` | Set number of log entries per file |
| `--output_dir my_logs` | Specify output directory |
| `--include_headers` | Add field headers to log files |
| `--mapping_file my_mapping.csv` | Set custom mapping file location |
| `--no_mixed` | Don't generate mixed-version log file |

##### Custom Format Examples

The generator supports several predefined custom formats:

- **minimal**: Basic fields only (srcaddr, dstaddr, dstport, protocol, action)
- **network_security**: Fields relevant for security analysis
- **traffic_analysis**: Fields for bandwidth and traffic pattern analysis
- **container_tracking**: ECS container-specific fields

### Example Commands

Generate only custom formats:
```bash
python generatorSampleFiles.py --versions none --custom_sets minimal traffic_analysis
```

Generate 2,000 logs for versions 3 and 5 with headers:
```bash
python generatorSampleFiles.py --versions 3 5 --logs_per_file 2000 --include_headers
```

#### Log Processor 

* If you prefer to run the script on your local system:

1. Download the `flowLogProcessor.py` script
2. Ensure you have the required input files (`flow_logs.txt`, `mapping.csv`, `protocolnumber1.csv`)
3. Execute the following commands:

##### Basic Usage

```bash
python flowLogProcessor.py flow_logs_v2.txt mapping.csv output.txt
```

This processes a version 2 flow log file using standard format.

##### Common Options

| Option | Description |
|--------|-------------|
| `--delimiter "\t"` | Specify field delimiter (default: space) |
| `--log_field_names field1 field2...` | Specify custom field names and order |
| `--protocol_mapping_file protocols.csv` | Use CSV for protocol number to name mapping |

##### Processing Different Log Formats

##### Standard Version Logs

Process any standard version log:
```bash
python flowLogProcessor.py flow_logs_v3.txt mapping.csv output.txt
```

##### Custom Format Logs

Process custom format logs by specifying field names:
```bash
python flowLogProcessor.py flow_logs_custom_minimal.txt mapping.csv output.txt --log_field_names srcaddr dstaddr dstport protocol action
```

##### Mixed Version Logs

Process logs containing multiple versions:
```bash
python flowLogProcessor.py flow_logs_mixed.txt mapping.csv output.txt
```

##### Custom Field Formats

When processing custom format logs, you must specify the field names in the exact order they appear:

**Minimal Format:**
```bash
--log_field_names srcaddr dstaddr dstport protocol action
```

##### Protocol Number Mapping

To map protocol numbers (e.g., 6) to protocol names (e.g., "tcp"), by default the scipt would have some protocols harcoded:
In order to have full list, add the argument ` --protocol_mapping_file protocolnumbers1.csv`
```bash
python flowLogProcessor.py flow_logs.txt mapping.csv output.txt --protocol_mapping_file protocolnumbers1.csv
```
The CSV file should contain columns "Decimal" (protocol number) and "Keyword" (protocol name).

## Complete Workflow Example

1. Generate test data in multiple formats:
```bash
python generatorSampleFiles.py --versions 2 5 --custom_sets minimal --include_headers
```

2. Process standard version logs:
```bash
python flowLogProcessor.py flow_logs_v2.txt mapping.csv output_v2.txt --protocol_mapping_file protocolnumbers1.csv
```

3. Process custom format logs:
```bash
python flowLogProcessor.py flow_logs_custom_minimal.txt mapping.csv output_minimal.txt --log_field_names srcaddr dstaddr dstport protocol action --protocol_mapping_file protocolnumbers1.csv
```

This workflow generates both standard and custom logs, then processes them with appropriate parameters.


### If you prefer to have it run in github directly 
* (The flow_logs.txt. mapping.csv are generated according to `generateSampleFiles.py`)

1. Clone the repo
2. Navigate to the actions tab, in your github cloned repo
3. Select the `Flow Log Processor` workflow
4. In the right panel, click the run workflow dropdown and select ` Run workflow`
5. Or you can also trigger the workflow either by commiting, push, or pull
6. And the resulting output file would be automatically uploaded to parent folder of the repo.
   

