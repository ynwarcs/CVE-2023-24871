$devices = Get-PnpDevice -Class Bluetooth |? InstanceId -notlike "BTH*"

"Bluetooth devices on the system: "

$radios = New-Object System.Collections.ArrayList
foreach ($device in $devices) {   
    $radio = New-Object PSObject
    Add-Member -InputObject $radio -MemberType NoteProperty -Name "InstanceId" -Value $device.InstanceId
    $property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAddress'
    Add-Member -InputObject $radio -MemberType NoteProperty -Name "MAC" -Value $(-join ($property.Data |  foreach { "{0:X2}" -f $_ } ))
    $radios.Add($radio) | Out-Null

    # Driver Info
    $property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverDesc'
    Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverDescription" -Value $property.Data
    $property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion'
    Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverVersion" -Value $property.Data
	
	# Extended Advertising
	$extAdvProp = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioIsExtendedAdvertisingSupported'
	Add-Member -InputObject $radio -MemberType NoteProperty -Name "Extended Advertising Supported" -Value $extAdvProp.Data
	
	# Maximum Advertisement Data Length
	$maxDataLenProp = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioMaximumAdvertisementDataLength'
	Add-Member -InputObject $radio -MemberType NoteProperty -Name "Maximum Advertisement Data Length" -Value $maxDataLenProp.Data
	
	# Check the values
	$isCapable = ($extAdvProp.Data -eq 1) -and ($maxDataLenProp.Data -gt 513)
	Add-Member -InputObject $radio -MemberType NoteProperty -Name "Is Capable" -Value $isCapable
}

# Print device properties
$radios

