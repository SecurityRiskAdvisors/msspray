# msspray.py
MSSpray is used to conduct password spray attacks against Azure AD as well as validate the implementation of MFA on Azure and Office 365 endpoints
```
  ------------------------------------------------------------
 |    ;---<<<<,___________//_________________________________ |
 |   _|_     /        /  ____/  ____/  __ /  __ / __  /  /  / |
 |  /   \   /  /  /  /____  /____  /  ___/   __/     / \   /  |
 |  |   |  /__/__/__/______/______/__/  /__/\_\__/__/  /__/   |
 |  |___|             //                                      |
  ------------------------------------------------------------
```

--- 
## Usage
Perform a password spray against the selected endpoint with the supplied userfile (one email address per line) and password and the option to stop on success (stop):

`python3 msspray.py spray <userfile> <password> <endpoint_selection> <stop/blank> ` 

Check each endpoint for authentication with a valid username and password:

`python3 msspray.py validate <username> <password> `

--- 
## Endpoints (Default is 1)
| Number | Endpoint | Endpoint URL |
|---|---|---|
|[1] | aad_graph_api|https://graph.windows.net 
|[2]|ms_graph_api| https://graph.microsoft.com 
|[3]|azure_mgmt_api |https://management.azure.com
|[4]|windows_net_mgmt_api | https://management.core.windows.net 
|[5]|cloudwebappproxy| https://proxy.cloudwebappproxy.net/registerapp
|[6]|officeapps| https://officeapps.live.com 
|[7]|outlook|https://outlook.office365.com 
|[8]|webshellsuite|https://webshell.suite.office.com 
|[9]|sara |https://api.diagnostics.office.com
|[10] |office_mgmt|https://manage.office.com 
|[11] |msmamservice |https://msmamservice.api.application
|[12] |spacesapi|https://api.spaces.skype.com
|[13] |datacatalog|https://datacatalog.azure.com 
|[14] |database |https://database.windows.net
|[15] |AzureKeyVault|https://vault.azure.net 
|[16] |onenote|https://onenote.com 
|[17] |o365_yammer|https://api.yammer.com
|[18] |skype4business |https://api.skypeforbusiness.com
|[19] |o365_exchange|https://outlook-sdf.office.com 
 
---
## Examples
spray against https://graph.windows.net, stopping on first successful login

`python3 msspray.py spray users.txt Spring2020 1 stop`

spray against https://management.core.windows.net

`python3 msspray.py spray users.txt Spring2020 4`

check all endpoints using valid account

`python3 msspray.py validate bill.smith@sra.io ReallyBadPass`

---

Blog Post: https://sra.io/blog/msspray-wait-how-many-endpoints-dont-have-mfa/

For any questions, feel free to reach out to me on Twitter [@__TexasRanger](https://twitter.com/__TexasRanger)
