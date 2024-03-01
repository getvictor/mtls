Get-ChildItem -Path Cert:\LocalMachine\Root |
        Where-Object{$_.Subject -match 'testServerCA'} |
        Test-Certificate -Policy SSL

Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object{$_.Subject -match 'testClientTLS'}
