
# Test-Signed. 
# V1.0 D Scholefield (david.dv@port80security.com). Nov 2019

# This software is distributed under the MIT open source permissive
# license (see https://opensource.org/licenses/MIT)

# License summary
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Description
# use: Test-Signed
#
# Find all unique executables and dll's associated with services
# and warn on those that are not signed by a valid cert.

# Define registry keys.
# Services gorup registry key to point to which services the svchost.exe wants to run
# note that when svchost.exe is called with the '-k <string>' the 'string' is
# the key into this registry entry. The value for the key will have space
# separated service names
$svcGroupKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\'

# The service DLL is stored under the service name in the following key under the
# \<service name>\parameters\ServiceDLL key. Note that the text 'INSERT_SVC_NAME'
# is a placeholder for the actual service name and needs to be replaced
$svcDLLKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\INSERT_SVC_NAME\Parameters'

# Main function declaration - call this function to begin test
function Test-Signed {

    # no POSH script is complete without ASCII art banner!
    StartUP

    # setup a number of report variables
    $uniqueExes = @{ }
    $uniqueSVCName = @{ }
    $unresolvableServices = @{ }
    $hasValidSig = @{ }
    $noValidSig = @{ }
    $uniqueIsValid = @{ }
    $uniqueIsNotValid = @{ }
    $dllNoValidSig = @{ }

    # we need to tell the user that something is happening
    # so we'll output a dot every 10 services checked
    $progressCount = 0;

    # find full paths for services first
    $fullPaths = Get-WmiObject win32_service | Select-Object -Property PathName
    
    # remember existing Error Action value for restoration later
    # and set current to 'Stop' so that exceptions can be caught
    $keepErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"

    # remove all options from .exe's on path
    # start with a hash to store names ('name' => $true elements) 
    foreach ($path in $fullpaths) {
        [regex]$rx = '(.+\.exe)\.*'

        $rm = $rx.Match($path.PathName)
        [regex]$rx_svchost = '.*svchost\.exe.*\-k\s+(\S+).*'
    
        if ($rm.Success) {
            $progressCount++ 
            [int]$i = (100 / $fullpaths.count) * $progressCount
            Write-Progress -Activity "checking services" -Status "$i% Complete:" -PercentComplete $i
            $exePath = $rm.Groups[1].Value
            $exePath = $exePath.TrimStart('"')
            Write-Verbose -Message "From $path.PathName extracted $exePath"
            $uniqueExes[$exePath] = 1
            
            # if script is run as non-admin account then reading sig will
            # be denied so we need to catch this
            try {
                $sigDetails = Test-IsValidSig($exePath)
                $uniqueExes[$exePath] = $sigDetails
                if ($sigDetails[0]) {
                    $uniqueIsValid[$exePath] = 1
                }
                else {
                    $uniqueIsNotValid[$exePath] = $sigDetails[1]
                }
            }
            catch {
                $uniqueIsNotValid[$exePath] = "UNAUTHORISED ACCESS"
                $noValidSig[$exePath] = "none"
            }

            Write-Verbose -Message "Sig details for $exePath : $sigDetails"
            $rm_svc = $rx_svchost.Match($path.PathName)
            if ($rm_svc.Success) {
                Write-Verbose -Message "Found service in $path matched service name is  $rm_svc.Groups[1].value"
                $connectedServices = Get-SVCsFromTag($rm_svc.Groups[1].value)
                Write-Verbose -Message "`tconnected services: $connectedServices"

                foreach ($connectedService in $connectedServices) {
                    # ensure we don't keep checking the same service DLL
                    # in the weird case that it might appear in two service
                    # startups tags
                    if (-NOT ($uniqueSVCName.ContainsKey($connectedService))) {
                        try {
                            $pathToSvc = Get-SVCDll($connectedService)
                            if ($pathToSvc -ne 'no key') {
                                $svcDLLIsValid = Test-IsValidSig($pathToSvc)
                                Write-Verbose -Message "`t connected service $connectedService has path $pathToSvc sig value $svcDLLIsValid"
                                $uniqueSVCName[$connectedService] = $svcDLLIsValid 
                                if ($svcDLLIsValid[0]) {
                                    $hasValidSig[$pathToSvc] = 1
                                }
                                else {
                                    $noValidSig[$pathToSvc] = $svcDLLIsValid[1]
                                    # record the details of the DLLs with no valid sig
                                    # create a unique key from tag and DLL
                                    $uniqueKeyForDLL = $rm_svc.Groups[1].value + ':' + $connectedService
                                    $dllNoValidSig[$uniqueKeyForDLL] = $pathToSvc
                                }
                            }
                            else {
                                $uniqueKeyForDLL =  $rm_svc.Groups[1].value + ':' + $connectedService
                                $dllNoValidSig[$uniqueKeyForDLL] = $pathToSvc + ':' + '[HKLM key not found defining this service DLL]'
                                Write-Verbose -message "`n`n******`n`t connect service $connectedService has no path"
                            }
                        }
                        catch [System.Management.Automation.ItemNotFoundException],  [System.Security.SecurityException] {
                            Write-Verbose -Message "EXCEPTION! $PSItem ($($pathToSvc))"
                            $unresolvableServices[$connectedService] = $PSItem.Exception.Message
                            $uniqueKeyForDLL =  $rm_svc.Groups[1].value + ':' + $connectedService
                            $dllNoValidSig[$uniqueKeyForDLL] = $pathToSvc + ':' + '[No valid sig]'
                        }
                    }
                }

            }
        }
        else {
            Write-Verbose -Message "Not found exe $path.PathName"
        }
    
    }

    # restore the original Error Action value
    $ErrorActionPreference = $keepErrorActionPreference

    # time to report on what has been found
    # most important is the number of unsigned services
    Write-Output "Number of signed services:  $($hasValidSig.Count) (of which unique $($uniqueIsValid.Count))"
    Write-Output "Number of unsigned services: $($noValidSig.Count) (of which unique $($uniqueIsNotValid.Count))" 

    Write-Output "Service .exe's that have no valid signature or unauthorised:"
    # list exes without signatures
    if ($uniqueIsNotValid.Count -gt 0) {
        Write-Output "Total of $($uniqueIsNotValid.Count)"
        foreach ($svcExeName in $uniqueIsNotValid.keys) {
            Write-Output "`t$svcExeName (details: $($uniqueIsNotValid[$svcExeName]))"
        }
    }   
    else {
        # there were none
        Write-Output "`tnone"
    }

    Write-Output "Service .DLL's that have no valid signature or DLL path cannot be found:"
    # list SVSs without signatures
    if ($dllNoValidSig.Count -gt 0) {
        Write-Output "Total of $($dllNoValidSig.Count)"
        foreach ($svcDLLName in $dllNoValidSig.keys) {
            Write-Output "`t$svcDLLName (details: $($dllNoValidSig[$svcDLLName]))"
        }
    }
    else {
        # there were none
        Write-Output "`tnone"
    }
}

# given a path to an executable, Test-IsValidSig($filename) will return
# a two element list: the first element is boolean and indicates whether
# a valid sig was found, the second is the string containing the signer
# information

function Test-IsValidSig {
    param ([String] $filePath)

    $result = @()

    $thisCert = Get-AuthenticodeSignature -FilePath $exePath
    if ($thisCert.Status -eq "Valid") {
        $result += $true 
        $result += $thisCert.SignerCertificate.Subject 
    }
    else {
        $result += $false
        $result += "none"
    }
    return $result
}

# given a service name, Get-SVCDll will return the .DLL that svchost.exe
# will load with the -k <key> command
function Get-SVCDll {
    param ([string] $svcName)
    $actualSvcName = $svcDLLKey.Replace("INSERT_SVC_NAME", $svcName)

    try {
        $svcDll = (Get-ItemProperty -path $actualSvcName).ServiceDll
    }
    catch {
        $svcDll = "no key"
    }
    return $svcDll
}


# given a service tag on a command svchost.exe -k <tag> the function
# Get-SVCsFromTag will return the services associated with that tag
# so that Get-SVCDll can find the DLLs
function Get-SVCsFromTag {
    param ([string] $svcTag)

    $svcs = (Get-ItemProperty -path $svcGroupKey).$svcTag

    return $svcs
}

function StartUP {
    Write-Output "`nTest-Signed V1.0"
    Write-Output "D Scholefield Nov 2019"
    Write-Output "---------------------------------------------"

}