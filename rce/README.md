# CVE-2023-24871 RCE
This folder contains poc & scripts that showcase RCE via bluetooth on Windows by using CVE-2023-24871. The material here goes in hand with the blog post [here](https://ynwarcs.github.io/x-cve-2023-24871-rce). If you haven't read the post, you most likely won't be able to follow further.

## contents
- The `scripts` folder contains two scripts:
    + `check_cap.bat` checks whether the system is capable of "attacking" another system, i.e. whether the poc provided in this repo can be executed.
    + `check_vuln.bat` checks whether the system is vulnerable to RCE, i.e. whether the prerequisites mentioned in the blog post are satisfied on the system.
- The `poc` folder contains code necessary to build the proof of concept that can be used to trigger the vulnerability remotely.

## credit
The proof of concept is implemented via the awesome [btstack](https://github.com/bluekitchen/btstack/) project. A huge thanks to them for maintaining an extensive, easy to use, cross-platform, open-source BLE host stack.

## details
**If you want to compile a poc and try it out, do it in an isolated environment like a VM, don't be stupid. You should never trust pocs/exploits published by people you don't know, this one is no exception.**

The PoC is a C application that sends crafted Bluetooth Low Energy advertisement data to a target system in order to demonstrate the vulnerability. The reproduction steps cover all four scenarios and require two systems with Bluetooth 5.0 capable controllers. We will refer to these two systems as the **Attacker system** and the **Target system**.

Reproduction steps marked with **[A]** denote that this action should be taken on the attacker system.
Reproduction steps marked with **[T]** denote that this action should be taken on the target system.

In local testing, I used two laptops with Intel Wireless Bluetooth controllers and Intel Bluetooth Driver Version 22.120.0.2. More recent driver versions limit the maximum length of advertisement data to **160**, making the vulnerability condition impossible. I recommend using this setup to test the vulnerability, even though it requires old driver versions. Setups with controllers from different vendors and latest driver versions should work as long as all requirements are satisfied.

## requirements
The target system must be running a vulnerable version of Windows. This means that the March 2023 security update must not be applied, as that's when the vulnerability was fixed.

### attacker system
- The Bluetooth controller used by the system must support extended advertising and have maximum advertisement data length set to at least **514**. To verify this, run **scripts\check_cap\check_cap.bat** and verify that "Is Capable" is True for the main Bluetooth device.
- For the PoC application to function properly, [WinUSB](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb) must be installed as the driver of the main Bluetooth device, following the installation steps in [this link](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation). Alternatively, you can use a tool such as [zadig](https://zadig.akeo.ie/) to make this process straightforward.
- To be able to compile the PoC application, [cmake](https://cmake.org/download/) must be installed. Alternatively, you can use cmake included with Visual Studio 2022.

### target system
- The Bluetooth controller used by the system must support extended advertising and have maximum advertisement data length set to at least **514**. To verify this, run **scripts\check_vuln\check_vuln.bat** and verify that "Is Vulnerable" is True for the main Bluetooth device.

## preparation
- [T] Ensure Bluetooth is turned on and working properly.
- [T] (Optional) To capture crashes that happen as a result of the vulnerability being triggered:
     * For scenarios triggering the vulnerability in **bthserv**, attach a user mode debugger to the process.
     * For scenarios triggering the vulnerability in **bthport**, setup [Kernel mode debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-kernel-mode-debugging-in-windbg--cdb--or-ntsd). 
- [A] Compile the proof of concept application: (Windows only - using cmake, can be done from Visual Studio if you prefer)
   * Open a command line prompt and navigate to **poc**. Execute the following:
   * Execute `mkdir build && cd build`
   * Execute `cmake ..` to generate the application build files.
   * Execute `cmake --build . --config=Debug`. Alternatively, you can use `Release` or `RelWithDebInfo` configurations.
   * Verify that the executable **poc.exe** is now located in `build\{config}\`.
- Ensure that the target system can be reached via Bluetooth from the attacker system. Having the two devices in the same room together should be sufficient.

## triggering the rce

The PoC application provides two different payloads that can be used to trigger the vulnerability in the target system:
- The first payload is the minimum reproducible payload and serves to ensure that the target system will crash.  It can be activated using the command line switch `-d`.
- The second payload is the one that writes arbitrary data into the heap of the target process. It can be activated by using the command line switch `-w` and specifying a hex encoded string of bytes that will be written into the heap of the target process (for example, `414141414141`). Deploying this payload may not always crash the target process, depending on the heap layout and how many bytes are being overwritten.

By default, payloads will be broadcast to all nearby devices scanning for Bluetooth advertisements. If you want to target a specific system:
- Find the public MAC address of the target system. This can be seen in the **Advanced** page of the main Bluetooth device in Device Manager, under **Address**.
- When running the PoC application, specify the command line arguments: `-a XX:XX:XX:XX:XX:XX`, where the second argument is the previously obtained MAC address.

You can find videos depicting each scenario [here](https://ynwarcs.github.io/x-cve-2023-24871-rce#40-poc).

----

### scenario 1
This scenario covers the case where the target system is actively scanning for Bluetooth advertisements but there are no paired BLE devices on the system and Swift Pair is disabled. In this scenario, only **bthport** is vulnerable. The steps provided below can be run in any order, ie. it doesn't matter whether the PoC application is run before or after the target system starts scanning.

- [A] Run the PoC application:
    * `poc.exe -t 2 -d` to deploy the DoS payload.
    * `poc.exe -t 2 -w [bytes]` to deploy the User Data payload.
- [T] Open **Settings -> Bluetooth & other devices**.
- [T] Click on **[+] Add Bluetooth or other device**.
- [T] Click on **Bluetooth**.
- [T] Observe that the Windows kernel crashed in `bthport.sys` as a result of heap corruption caused by the vulnerability.

----

### scenario 2
This scenario is an extension of Scenario 1 with the added requirement that there must be a BLE device that's paired with the system. The device doesn't need to be connected. In this case, the behaviour of **bthport** is unchanged from Scenario 1, so there is no need to re-test it. The reproduction steps below will trigger the vulnerability in **bthserv**.

- [A] Run the PoC application:
    * `poc.exe -t 1 -d` to deploy the DoS payload.
    * `poc.exe -t 1 -w [bytes]` to deploy the User Data payload.
- [T] Pair the system with a Bluetooth Low Energy device:
    * Open **Settings -> Bluetooth & other devices**.
    * Click on **[+] Add Bluetooth or other device**.
    * Click on **Bluetooth**.
    * Find an appropriate device and click on it.
    * Confirm that the device is paired.
- [T] Start scanning for Bluetooth devices:
    - Open **Settings -> Bluetooth & other devices**.
    - Click on **[+] Add Bluetooth or other device**.
    - Click on **Bluetooth**.
- [T] Observe that **bthserv** crashed as a result of heap corruption caused by the vulnerability.
- [T] Additionally, observe that **bthserv** will repeatedly restart and crash.

----

### scenario 3
This scenario is similar to Scenario 2. but it doesn't require the target system to be actively scanning. This scenario requires the attacker to spoof an address of a BLE device that is paired with the target system in order to trigger the vulnerability. Both modules are vulnerable in this scenario, as shown in the scenario table. 

To showcase the behaviour, we'll pair with a BLE device on the target system and read its address in Device properties. No real spoofing will be done, as setting that up would be rather complicated. Actual spoofing would have to be done via brute force or by sniffing radio data with custom controller-level code.

Note: When spoofing devices that are identified by their public address, the public device of the remote controller has to be changed. The PoC supports this functionality only for Intel controllers. Random address spoofing is supported for all controllers.

- [T] Pair the system with a Bluetooth Low Energy device:
    * Open **Settings -> Bluetooth & other devices**.
    * Click on **[+] Add Bluetooth or other device**.
    * Click on **Bluetooth**.
    * Find an appropriate device and click on it.
    * Confirm that the device is paired.
    * Close all Bluetooth-related windows.
- [T] Find the Bluetooth address of the paired device:
    * Open **Device Manager**
    * Expand the **Bluetooth** section and find the paired device.
    * Right click on the device and select **Properties**.
    * In the **Details** tab:
         * Select "Bluetooth LE Address Type". Denote this value as an integer value `[addr_type]`.
         * Select "Association Endpoint address". Denote this value as a string value `[addr]`.
- [T] (Optional) Disconnect the paired device to confirm that it doesn't need to be connected for the system to be vulnerable (e.g. move the device out of range or turn it off. You can also restart the target system to confirm that the behaviour persists among reboots.).
- [A] Run the PoC application:
    * `poc.exe -t 1 -i [addr_type] [addr] -d` to deploy the DoS payload.
    * `poc.exe -t 1 -i [addr_type] [addr] -w [bytes]` to deploy the User Data payload.
- [T] There's two possibilities for the observed behaviour: 
    * The Windows kernel will immediately crash in `bthport.sys` as a result of heap corruption caused by the vulnerability. In the provided video, this is the behaviour that was observed.
    * If the initial memory corruption in **bthport** doesn't crash the kernel, **bthserv** will almost certainly crash first. **bthserv** will continue restarting and crashing until one of the memory corruptions in the kernel actually crashes it. If you're debugging the kernel, simply ignore/continue the crashes in **bthserv** to observe the crash in the driver.

----

### scenario 4
This scenario covers the case where Swift Pair is enabled on the target system. In this case, only **bthserv** is vulnerable. This scenario requires the attacker to ensure that the controller they're using emits a signal that's strong enough to be within the monitored range setup by Swift Pair. Triggering this scenario might take some trial and error in figuring out at which range the remote controller will be eligible for Swift Pair. In my tests, I had to bring two laptops with Intel Wireless Bluetooth controllers very close together.

- [T] Verify that the system is vulnerable to this scenario by confirming that **scripts\check_vuln\check_vuln.bat** prints `Swift Pair: Enabled`.
- [A] Run the PoC application:
    * `poc.exe -t 1 -m -d` to deploy the DoS payload.
    * `poc.exe -t 1 -m -w [bytes]` to deploy the User Data payload.
- [A] Reach the RSSI range setup by Swift Pair (**-55dbM** to **-65dbM**).
- [T] Observe that **bthserv** crashed as a result of heap corruption caused by the vulnerability.
- [T] Additionally, observe that **bthserv** does not repeatedly crash after restarting, as Bluetooth User Support service didn't re-register an advertisement monitor.

----