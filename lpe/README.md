This folder contains the poc & exploit that demonstrate LPE on Windows 10/11 from an unprivileged user to SYSTEM via CVE-2023-24871. The description of the vulnerability can be found [on the blog](https://ynwarcs.github.io/z-btadv-cves), with the LPE vector being specifically covered in [this post](https://ynwarcs.github.io/w-cve-2023-24871-lpe). You should definitely read those before you go any further.

## contents
- `poc` folder contains simple poc code that can be made to trigger the vulnerability, but not an actual exploit. It simply sends some data via RPC to **bthserv**, which triggers the vulnerable code path.
- `exploit` folder contains the exploit which can be run as an unprivileged user to escalate privileges to SYSTEM. it's probabilistic but works well in reality, as there's virtually an infinite amount of attempts.

## credit
The exploit makes use of [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) to escalate privileges from LOCAL SERVICE to SYSTEM.

## requirements
The vulnerability was fixed in the March 2023 security update, so the system that's being targeted should not have that update. I did my testing on Windows 11 Insider Pro Build 25236 (yes it's super old). Both the poc and the exploit work out-of-the-box even on most recent builds of Windows 11 if you patch the fix out.

## poc
The poc is very simple. As explained in the blog post, we use `biwinrt.dll` to issue an RPC call from an application to the RPC server running in **bthserv**. The only catch is that we have to do this from an AppContainer process with a Bluetooth capability, so we inject a remote thread into `StartMenuExperienceHost.exe` to load a DLL that contains the actual poc code. I picked this process because it should be present on all desktop windows versions, and should be running under all circumstances. In case you can't get the vulnerability to trigger for some reason, check if the DLL is being successfully injected and/or try to restart the process.

You can compile the poc by opening the solution and building it normally from VS. I used VS 2022, but it will probably work on earlier versions as well. Running the poc is easy - just run the compiled program. This will send advertisement data containing 257 empty sections to **bthserv**, triggering integer overflow & the vulnerability. The program will then almost certainly crash, as memory overwrites end up happening way past the allocated memory.

## exploit
The exploit is more complex, on the other hand. The essence is the same - we'll load a DLL into `StartMenuExperienceHost.exe` and send RPC data to trigger the vulnerability. However, to actually achieve code execution some grooming is needed, as well as post-exploitation steps to ensure that we further escalate to SYSTEM, as **bthserv** is running "only" as LOCAL SERVICE.

The exploit code is split into four modules:
- **bthlpe_master.exe** is the main process which "coordinates" the exploit. Most of the exploit code is in here. Other modules are used mainly to execute code from other processes, while the master process runs standalone and pulls the strings.
- **bthlpe_payload.dll** is the DLL we're going to inject into `StartMenuExperienceHost.exe`. The sole purpose of this DLL is to trigger the vulnerability by sending RPC requests.
- **bthlpe_harness.dll** is the DLL that we intend to load inside **bthserv**. To achieve execution within **bthserv**, the exploit doesn't execute shellcode, but rather overwrites a function pointer with a pointer to `LoadLibraryW`, which the program then ends up calling. This DLL is the one that's going to be used as an argument to that `LoadLibraryW` call.
- **bthlpe_juicypotato.exe** is a wrapper executable around JuictyPotatoNG which is going to be executed by the harness DLL once it's loaded within **bthserv**. Its purpose is to escalate privileges from LOCAL SERVICE to SYSTEM. How that's done, you can read on [this blog post](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/). The main reason we do this from a separate executable, rather than from the harness DLL, is that the method of escalation that JuicyPotatoNG uses relies on the process having not called `CoInitializeSecurity` earlier, which **bthserv** does call at startup.

Note that the exploit only works out of the box on 64-bit targets, but could be adjusted to work on 32-bit ones as well, with some tinkering.

### description
Most of the exploit code is trivial boilerplate stuff like communication between different modules via pipes. As such, I'll just describe the overview of the steps that are taken. The only interesting part really is how we go from the heap corruption to ACE, which I'll share further below.

The code in **bthlpe_master.exe** is split into two steps. The first step is performed only once and has five smaller steps:
```
bool DoStep1()
{
    ...
        // No bluetooth radio = no vulnerability, so ensure one exists and is enabled
        if (!CheckIfBluetoothRadioExists())
        {
            return false;
        }
        
        // Change other modules' DACL so that the LOCAL SERVICE user can access them
        if (!GrantFileAccesses())
        {
            return false;
        }

        // Tries to find two gadgets that are necessary for the exploit
        // The first gadget is a string that can be interpreted as a file path, here we use \Bluetooth\Policy,
        // the exploit will call `LoadLibrary` on this string, which will be interpreted as C:\Bluetooth\Policy.dll
        // The second gadget is a "chained" pointer to a byte that's equal to one, we'll later see why it's needed.
        if (!GetHarnessAndPointerReferenceInExtModule(HARNESS_REF_EXT_MODULE, HARNESS_DEPLOY_NAME))
        {
            return false;
        }
        
        // Deploys the harness DLL into the previously found special filepath, i.e. C:\Bluetooth\Policy.dll
        if (!DeployHarness(HARNESS_DEPLOY_NAME))
        {
            return false;
        }
        
        // Loads the payload dll into bthserv via CreateRemoteThread in StartMenuExperienceHost.exe
        if (!LoadPayloadDllIntoProcess(TARGET_PROCESS_NAME, PAYLOAD_DLL_NAME))
        {
            return false;
        }
    }

    return true;
}
```

The second step is the more essential one:
```
bool DoStep2()
{
    // Crashes bthserv to reset the heap layout, the service will automatically restart
    CrashBthserv();
    
    // The heart of the exploit - see snippet below
    TriggerRCEWithSprayingAndWaitForHarness();
    
    // If the exploit succeeded, waits until the post-exploitation steps finish (like escalating from LOCAL SERVICE to SYSTEM)
    WaitForJuicyPotatoAndShell();
}
```

The heart of the exploit is in `TriggerRCEWithSprayingAndWaitForHarness`:
```
bool TriggerRCEWithSprayingAndWaitForHarness()
{
    // A lambda function to create a BluetoothLEAdvertisementPublisher object (both on the client & the server)
    auto GenerateBthLEPublisher =...;

    // A lambda function which sprays the heap of bthserv with BluetoothLEAdvertisementPublisher objects by creating many of them
    auto SprayObjects = ...;

    // A lambda function which deletes previously created objects.
    auto FreeObjects = ...;

    ...
    for (uint32_t i = 0; i < k_RetryCount; ++i)
    {
            // First we spray some objects
            if (!SprayObjects(0, k_InitialSprayCount))
            {
                return false;
            }
            
            // Then we delete some objects
            ...
            for (uint32_t i = 0; i < k_FreeCount; i += freeCount)
            {
                FreeObjects(freeOffset, freeCount);
            }
            ...

            // And then we spray more objects again, all of these steps are supposed to groom the heap
            if (!SprayObjects(k_InitialSprayCount, k_PostSprayCount))
            {
                return false;
            }

            // Trigger the vulnerabilty and wait until the harness DLL reports back (if the exploit succeeded!)
            // If this step fails, we simply repeat the loop
            if (!DeployRCEPayloadAndWaitForHarness())
            {
                Sleep(2000u);
                continue;
            }

            // Spray more objects, this is necessary so that we don't trigger heap protection further below when wrapping up
            if (!SprayObjects(k_InitialSprayCount + k_PostSprayCount, k_FreeCount))
            {
                return false;
            }

            // Check if harness succeeded
            ...
        }
    }

    ...

    return true;
}
```


The code above sprays some objects on the heap of **bthserv** and then triggers the vulnerability, hoping to overwrite memory in such a way that we can end up calling `LoadLibraryW` on our super special filepath string, i.e. `\Bluetooth\Policy`. So what are we overwriting and how?

When a client creates a [`BluetoothLEAdvertisementPublisher`](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementpublisher?view=winrt-22621) object, the RPC server in **bthserv** creates a `GapAdvertisementPublisher` object, which is in a way the counterpart to the client object. This server-side publisher internally contains a `SmFx::StateMachineEngine` object (part of `Microsoft.Bluetooth.Service.dll` which is another DLL loaded by **bthserv**). Its purpose is to represent a state machine that changes as the publisher enters different states. The client has a lot of control over the state machine object on the server, as pretty much all methods executed on the client's object will end up changing the state of the server object in some way.

What's interesting about `SmFx::StateMachineEngine`  however, is that their size is `0x420` bytes, and they internally contain an array of function pointers at offset `0x388`, which is initialized in `SmFx::StateMachineEngine::StateMachineEngineImpl::Initialize` and then later used throughout multiple different functions. This makes them a prime target for being overwritten:
- Their existence and internal data can be controlled by the client.
- Their size fits into the same bucket as the size of sections array with 3 sections (3 * 0x153 = 0x3F9).
- If the attacker successfully overwrites function pointers, they can then end up calling an arbitrary function in **bthserv**.

Calling an arbitrary function is nice, but it doesn't immediately lead arbitrary code execution. Luckily, the callback at offset `0x388` has another nice property:

```
void SmFx::StateMachineEngine::StateMachineEngineImpl::ReportExceptionWithLockHeld(...)
{
    ...
    if ( *(stateMachineObject + 0x388) )
      {
        ...
        (*(stateMachineObject + 0x388))(*(stateMachineObject + 0x380), ...);
        ...
      }
    ...
}
```

Unlike some other callbacks, this one takes a value from nearby memory as the first argument. If we were to corrupt this part of memory, we could also control an argument to the function and not only the function that's going to be called. The idea then is to overwrite the function pointer at `0x388` with a pointer to `LoadLibraryW` and the value at `0x380` to point towards a special filepath string, i.e. `\Bluetooth\Policy`, which would make `LoadLibraryW` attempt to load a DLL from "C:\Bluetooth\Policy.dll". We could've also called something like `WinExec` with a command string argument but the problem is that we'd need to get that string into the memory of **bthserv** and then find out its address, which is IMO more complicated than this approach.

The only thing left to do is to figure out how to trigger this code path. The method is called only from `SmFx::StateMachineEngine::StateMachineEngineImpl::AddEventToEventQueue`, and only if the byte values at offsets `0x3C2` and `0x3C3` in the state machine object mismatch. This is easy to stage by writing values 5 and 6 to these locations via the memory corruption. Next, we need to trigger the code path that would call `AddEventToEventQueue`. This is rather easy as well. If we delete a `BluetoothLEAdvertisementPublisher` object on the client, the corresponding `GapAdvertisementPublisher` object is destroyed on the server as well, which can end up calling the exception method. The callstack then ends up being:

```
SmFx::StateMachineEngine::StateMachineEngineImpl::ReportExceptionWithLockHeld(enum SmFx::MachineException, unsigned short, unsigned short)+C9
SmFx::StateMachineEngine::StateMachineEngineImpl::AddEventToEventQueue(unsigned short)+30
SmFx::StateMachineEngine::EnqueueEventWithDisposition(unsigned short)+DD
SmFx::StateMachineEngine::EnqueueEvent(unsigned short)+DD
Microsoft::Bluetooth::Protocols::Att::AttConnectionModeCoordinatorImpl::Stop(void)+12
...
Microsoft::Bluetooth::Core::Interface::GapAdvertisementPublisherImpl::`vector deleting dtor'(unsigned int)+14
...
```

However, there are some branches in `EnqueueEventWithDisposition` that need to be nudged too. Namely, the function checks the transition states of the machine, which are stored at offset `0x378`, with individual states stored at chained pointers at offset `0x10`. To avoid some unexpected branching here, I used the gadget mentioned earlier. We overwrite the memory at offset `0x378` to point towards a chained pointer to a value that's equal to `1`. This makes it so that we always end up in the desired branch.

That's all there is to the method. The exploit sprays a bunch of these state machine objects by creating a bunch of `BluetoothLEAdvertisementPublisher` objects. Luckily, this doesn't create any other objects in the same heap bucket on the server, so once we trigger the vulnerability we have a high chance of overwriting one of the desired objects (or unallocated heap memory otherwise). It doesn't matter much anyway as **bthserv** restarts after crashing. It's most likely possible to improve the grooming but I had some 80% success rate per try on the builds I tested, which was enough.

Once the `LoadLibrary` call succeeds and the DLL is successfully loaded into **bthserv**, it spawns **bthlpe_juicypotato.exe** to further escalate from LOCAL SERVICE to SYSTEM. The reason this is not done on the fly is because the token hooking method that JuicyPotatoNG uses relies on grabbing some info during `CoInitializeSecurity`, which can only be called once per process and which **bthserv** calls during its startup. As such, we need a new process to be able to do the thing.

### running the exploit
**If you don't have one, make an isolated environment where you're going to work. Never trust pocs/exploits published by people you don't know.**

Compile the solution in VS 2022 and run **bthlpe_master.exe** with no arguments. That's it. You can see the video of the exploit in action [here](https://ynwarcs.github.io/w-cve-2023-24871-lpe#30-poc--exploit). 

If you get an error saying that payload execution failed, try to kill `StartMenuExperienceHost.exe`, I would've added this as part of the exploit too but it's a little too invasive.
