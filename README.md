[comment]: # "Auto-generated SOAR connector documentation"
# iSight Partners

Publisher: Splunk Community  
Connector Version: 2\.0\.9  
Product Vendor: iSight Partners  
Product Name: ThreatScape  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with iSight Partners' ThreatScape product to pull campaign reports and provide hunting capabilities

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2014-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This App is an Ingestion source. In the Phantom documentation, in the [Administration
Manual](../admin/) under the [Data Sources](../admin/sources) section, you will find an explanation
of how Ingest Apps works and how information is extracted from the ingested data. There is a general
explanation in Overview, and some individuals Apps have their own sections.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ThreatScape asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_url** |  required  | string | API URL
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**api\_key** |  required  | password | API Key
**secret** |  required  | password | Secret
**download\_report** |  optional  | boolean | Add report pdf to vault during ingestion

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[hunt file](#action-hunt-file) - Look for information about a file hash in the ThreatScape product database  
[hunt domain](#action-hunt-domain) - Look for information about a domain in the ThreatScape product database  
[hunt ip](#action-hunt-ip) - Look for information about an IP in the ThreatScape product database  
[hunt url](#action-hunt-url) - Look for information about a URL in the ThreatScape product database  
[get report](#action-get-report) - Get report details  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'hunt file'
Look for information about a file hash in the ThreatScape product database

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of the binary to hunt | string |  `hash`  `md5`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.data\.\*\.ThreatScape | string | 
action\_result\.data\.\*\.matchedOn\.\*\.key | string | 
action\_result\.data\.\*\.matchedOn\.\*\.value | string | 
action\_result\.data\.\*\.publishDate | numeric | 
action\_result\.data\.\*\.published\_date | string | 
action\_result\.data\.\*\.reportId | string |  `isightpartners report id` 
action\_result\.data\.\*\.reportLink | string | 
action\_result\.data\.\*\.threatscape\_info | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.webLink | string | 
action\_result\.summary\.reports\_matched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt domain'
Look for information about a domain in the ThreatScape product database

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to hunt | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.ThreatScape | string | 
action\_result\.data\.\*\.matchedOn\.\*\.key | string | 
action\_result\.data\.\*\.matchedOn\.\*\.value | string | 
action\_result\.data\.\*\.publishDate | numeric | 
action\_result\.data\.\*\.published\_date | string | 
action\_result\.data\.\*\.reportId | string |  `isightpartners report id` 
action\_result\.data\.\*\.reportLink | string | 
action\_result\.data\.\*\.threatscape\_info | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.webLink | string | 
action\_result\.summary\.reports\_matched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt ip'
Look for information about an IP in the ThreatScape product database

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to hunt | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.ThreatScape | string | 
action\_result\.data\.\*\.matchedOn\.\*\.key | string | 
action\_result\.data\.\*\.matchedOn\.\*\.value | string | 
action\_result\.data\.\*\.publishDate | numeric | 
action\_result\.data\.\*\.published\_date | string | 
action\_result\.data\.\*\.reportId | string |  `isightpartners report id` 
action\_result\.data\.\*\.reportLink | string | 
action\_result\.data\.\*\.threatscape\_info | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.webLink | string | 
action\_result\.summary\.reports\_matched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt url'
Look for information about a URL in the ThreatScape product database

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to hunt | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.ThreatScape | string | 
action\_result\.data\.\*\.matchedOn\.\*\.key | string | 
action\_result\.data\.\*\.matchedOn\.\*\.value | string | 
action\_result\.data\.\*\.publishDate | numeric | 
action\_result\.data\.\*\.published\_date | string | 
action\_result\.data\.\*\.reportId | string |  `isightpartners report id` 
action\_result\.data\.\*\.reportLink | string | 
action\_result\.data\.\*\.threatscape\_info | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.webLink | string | 
action\_result\.summary\.reports\_matched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Get report details

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Report ID to get the details of | string |  `isightpartners report id` 
**download\_report** |  optional  | Download the report pdf to vault | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.download\_report | boolean | 
action\_result\.parameter\.id | string |  `isightpartners report id` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.app\_run\_id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.report\.ThreatScape\.product | string | 
action\_result\.data\.\*\.report\.copyright | string | 
action\_result\.data\.\*\.report\.execSummary | string | 
action\_result\.data\.\*\.report\.keyPoints | string | 
action\_result\.data\.\*\.report\.overview | string | 
action\_result\.data\.\*\.report\.previousVersionSection\.previousVersion\.\*\.publishDate | string | 
action\_result\.data\.\*\.report\.previousVersionSection\.previousVersion\.\*\.title | string | 
action\_result\.data\.\*\.report\.previousVersionSection\.previousVersion\.\*\.versionNumber | string | 
action\_result\.data\.\*\.report\.publishDate | string | 
action\_result\.data\.\*\.report\.reportId | string | 
action\_result\.data\.\*\.report\.reportType | string | 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.fileName | string |  `file name` 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.fileSize | string | 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.identifier | string | 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.sha1 | string |  `sha1`  `hash` 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.report\.tagSection\.files\.file\.\*\.type | string | 
action\_result\.data\.\*\.report\.tagSection\.main\.affectedIndustries\.affectedIndustry | string | 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.identifier | string | 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.networkType | string | 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.port | string | 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.protocol | string | 
action\_result\.data\.\*\.report\.tagSection\.networks\.network\.\*\.url | string |  `url` 
action\_result\.data\.\*\.report\.threatDetail | string | 
action\_result\.data\.\*\.report\.title | string | 
action\_result\.data\.\*\.report\.version | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.vault\_id | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

<table><tr><th>Parameter</th><th>Default Value</th></tr><tr><td>Start Time</td><td>Past 10 days</td></tr><tr><td>End Time</td><td>Now</td></tr></table>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Container IDs to limit the ingestion to | string | 
**start\_time** |  optional  | Start of time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 

#### Action Output
No Output